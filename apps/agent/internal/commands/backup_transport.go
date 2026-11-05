package commands

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// backup.* transports (agent spec §4.14, B10) — the seam ADR-0001-style:
// v1.0 ships local, SFTP and S3-compatible destinations; each transport
// shells out to a node binary (or stdlib for local) and every binary is an
// injectable Deps field (empty = exec.LookPath) so tests run against fakes.
//
// Secret discipline: destination secrets (S3 secret key, SFTP private key)
// ride the signed command channel exactly once per call — the same trust
// model as the MariaDB password (MYSQL_PWD precedent). They are never
// written to a WAL entry, a log line, a manifest, or an argv (env vars or
// temp key files with 0600 instead).

// BackupTransport moves one artifact (and its manifest) to/from a
// destination. Names are destination-relative artifact names.
type BackupTransport interface {
	Put(localPath, name string) error
	Get(name, localPath string) error
	Delete(name string) error
}

// backupDestination is the decrypted, typed destination config the control
// plane passes per call. It is never persisted agent-side.
type backupDestination struct {
	Type string `json:"type"` // local | s3 | sftp

	// local
	Root string `json:"root,omitempty"`

	// s3 (via rclone with env-based config)
	Bucket          string `json:"bucket,omitempty"`
	Prefix          string `json:"prefix,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	Provider        string `json:"provider,omitempty"`

	// sftp (via the OpenSSH sftp client in batch mode)
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	Username   string `json:"username,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	BaseDir    string `json:"base_dir,omitempty"`
	HostKey    string `json:"host_key,omitempty"` // base64 ssh host key; empty = accept-new (flagged honestly)

	// C15: age recipient public keys. Empty = the artifact is NOT encrypted
	// and the run is flagged honestly as plaintext.
	AgeRecipients []string `json:"age_recipients,omitempty"`
}

// resolveTransport validates the destination and returns its transport.
// Missing node binaries are loud preconditions — never silent fallbacks.
func (r *Registry) resolveTransport(dest backupDestination) (BackupTransport, error) {
	switch dest.Type {
	case "local":
		if strings.TrimSpace(dest.Root) == "" {
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "local destination requires 'root'"}
		}
		root, err := confineUnderBackupRoot(r.deps.BackupRoot, dest.Root)
		if err != nil {
			return nil, err
		}
		return &localTransport{root: root}, nil
	case "s3":
		if dest.Bucket == "" {
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "s3 destination requires 'bucket'"}
		}
		if dest.AccessKeyID == "" || dest.SecretAccessKey == "" {
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "s3 destination requires 'access_key_id' and 'secret_access_key'"}
		}
		rclone := r.deps.RcloneBinary
		if rclone == "" {
			found, err := exec.LookPath("rclone")
			if err != nil {
				return nil, &rpc.RPCError{
					Code:    rpc.CodePrecondition,
					Message: "rclone binary not found on this node — s3 destinations require it (install rclone, or use a local/sftp destination)",
				}
			}
			rclone = found
		}
		return &s3Transport{rclone: rclone, dest: dest}, nil
	case "sftp":
		if dest.Host == "" || dest.Username == "" {
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "sftp destination requires 'host' and 'username'"}
		}
		if dest.PrivateKey == "" {
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "sftp destination requires 'private_key' (PEM)"}
		}
		sftpBin := r.deps.SftpBinary
		if sftpBin == "" {
			found, err := exec.LookPath("sftp")
			if err != nil {
				return nil, &rpc.RPCError{
					Code:    rpc.CodePrecondition,
					Message: "sftp client not found on this node — sftp destinations require the OpenSSH sftp binary",
				}
			}
			sftpBin = found
		}
		return &sftpTransport{sftp: sftpBin, dest: dest}, nil
	case "":
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "destination.type is required (local | s3 | sftp)"}
	default:
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: fmt.Sprintf("destination.type must be local, s3 or sftp — '%s' is not a v1.0 destination", dest.Type)}
	}
}

// confineUnderBackupRoot pins local destination roots under the agent's
// backup root (C13-style confinement for backup writes).
func confineUnderBackupRoot(backupRoot, requested string) (string, error) {
	if backupRoot == "" {
		backupRoot = "/var/backups/nexuspanel"
	}
	if strings.ContainsRune(requested, 0) {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "root contains NUL"}
	}
	root := filepath.Clean(backupRoot)
	p := filepath.Clean(requested)
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	if p != root && !strings.HasPrefix(p, root+string(filepath.Separator)) {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: "local destination root must stay under the agent backup root"}
	}
	return p, nil
}

// ---- local -----------------------------------------------------------------

type localTransport struct{ root string }

func (t *localTransport) Put(localPath, name string) error {
	if err := os.MkdirAll(t.root, 0o750); err != nil {
		return mailInternalError("backup dir create failed", err)
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		return mailInternalError("backup stage read failed", err)
	}
	if err := atomicWriteFile(filepath.Join(t.root, name), data, 0o600); err != nil {
		return mailInternalError("backup write failed", err)
	}
	return nil
}

func (t *localTransport) Get(name, localPath string) error {
	data, err := os.ReadFile(filepath.Join(t.root, name))
	if err != nil {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "artifact not found at the destination"}
	}
	return os.WriteFile(localPath, data, 0o600)
}

func (t *localTransport) Delete(name string) error {
	err := os.Remove(filepath.Join(t.root, name))
	if err != nil && !os.IsNotExist(err) {
		return mailInternalError("backup delete failed", err)
	}
	return nil
}

// ---- s3 (rclone, env-based config) ------------------------------------------

type s3Transport struct {
	rclone string
	dest   backupDestination
}

func (t *s3Transport) remote(name string) string {
	prefix := strings.Trim(t.dest.Prefix, "/")
	if prefix == "" {
		return fmt.Sprintf("nexuspanelbk:%s/%s", t.dest.Bucket, name)
	}
	return fmt.Sprintf("nexuspanelbk:%s/%s/%s", t.dest.Bucket, prefix, name)
}

func (t *s3Transport) env() []string {
	env := os.Environ()
	set := func(k, v string) { env = append(env, k+"="+v) }
	set("RCLONE_CONFIG_NEXUSPANELBK_TYPE", "s3")
	if t.dest.Provider != "" {
		set("RCLONE_CONFIG_NEXUSPANELBK_PROVIDER", t.dest.Provider)
	} else {
		set("RCLONE_CONFIG_NEXUSPANELBK_PROVIDER", "Other")
	}
	set("RCLONE_CONFIG_NEXUSPANELBK_ACCESS_KEY_ID", t.dest.AccessKeyID)
	set("RCLONE_CONFIG_NEXUSPANELBK_SECRET_ACCESS_KEY", t.dest.SecretAccessKey)
	if t.dest.Region != "" {
		set("RCLONE_CONFIG_NEXUSPANELBK_REGION", t.dest.Region)
	}
	if t.dest.Endpoint != "" {
		set("RCLONE_CONFIG_NEXUSPANELBK_ENDPOINT", t.dest.Endpoint)
	}
	set("RCLONE_CONFIG_NEXUSPANELBK_NO_CHECK_BUCKET", "true")
	return env
}

func (t *s3Transport) run(args ...string) error {
	cmd := exec.Command(t.rclone, args...)
	cmd.Env = t.env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: "rclone failed: " + firstDbErr(string(out), err)}
	}
	return nil
}

func (t *s3Transport) Put(localPath, name string) error {
	return t.run("copyto", localPath, t.remote(name))
}

func (t *s3Transport) Get(name, localPath string) error {
	return t.run("copyto", t.remote(name), localPath)
}

func (t *s3Transport) Delete(name string) error {
	return t.run("deletefile", t.remote(name))
}

// ---- sftp (OpenSSH sftp client, batch mode) ----------------------------------

type sftpTransport struct {
	sftp string
	dest backupDestination
}

// session writes the private key + known_hosts into a temp dir for the
// duration of one call, then removes them.
func (t *sftpTransport) session() (keyFile, knownHosts string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "nexuspanel-sftp-")
	if err != nil {
		return "", "", nil, mailInternalError("sftp temp dir failed", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	keyFile = filepath.Join(dir, "id_backup")
	if werr := os.WriteFile(keyFile, []byte(t.dest.PrivateKey), 0o600); werr != nil {
		cleanup()
		return "", "", nil, mailInternalError("sftp key write failed", werr)
	}
	knownHosts = filepath.Join(dir, "known_hosts")
	hk := t.dest.HostKey
	if hk == "" {
		hk = "" // accept-new below; flagged honestly at test time
	} else {
		line := fmt.Sprintf("%s %s\n", t.dest.Host, hk)
		if werr := os.WriteFile(knownHosts, []byte(line), 0o600); werr != nil {
			cleanup()
			return "", "", nil, mailInternalError("sftp known_hosts write failed", werr)
		}
	}
	return keyFile, knownHosts, cleanup, nil
}

func (t *sftpTransport) run(batch string) error {
	keyFile, knownHosts, cleanup, err := t.session()
	if err != nil {
		return err
	}
	defer cleanup()

	port := t.dest.Port
	if port == 0 {
		port = 22
	}
	args := []string{
		"-P", fmt.Sprintf("%d", port),
		"-i", keyFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
	}
	if knownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+knownHosts)
	}
	base := strings.TrimSuffix(t.dest.BaseDir, "/")
	target := t.dest.Host
	if base != "" {
		target = fmt.Sprintf("%s@%s:%s", t.dest.Username, t.dest.Host, base)
	} else {
		target = fmt.Sprintf("%s@%s", t.dest.Username, t.dest.Host)
	}
	args = append(args, target)

	cmd := exec.Command(t.sftp, args...)
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: "sftp failed: " + firstDbErr(string(out), err)}
	}
	return nil
}

func (t *sftpTransport) sftpPath(name string) string {
	base := strings.TrimSuffix(t.dest.BaseDir, "/")
	if base == "" {
		return name
	}
	return base + "/" + name
}

func (t *sftpTransport) Put(localPath, name string) error {
	return t.run(fmt.Sprintf("put %s %s\n", quoteSftp(localPath), quoteSftp(t.sftpPath(name))))
}

func (t *sftpTransport) Get(name, localPath string) error {
	return t.run(fmt.Sprintf("get %s %s\n", quoteSftp(t.sftpPath(name)), quoteSftp(localPath)))
}

func (t *sftpTransport) Delete(name string) error {
	return t.run(fmt.Sprintf("rm %s\n", quoteSftp(t.sftpPath(name))))
}

func quoteSftp(p string) string {
	return "'" + strings.ReplaceAll(p, "'", "'\\''") + "'"
}

// ---- shared artifact helpers -------------------------------------------------

const manifestSuffix = ".manifest.json"

// newArtifactName mints nexuspanel-<scope>-<utc ts>-<rand>.tar[.gz][.age].
func newArtifactName(scope, ext string) string {
	ts := time.Now().UTC().Format("20060102T150405Z")
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	return fmt.Sprintf("nexuspanel-%s-%s-%s%s", scope, ts, hex.EncodeToString(rnd[:]), ext)
}

// sha256File streams a file into a hex digest.
func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// atomicWriteFile writes via a staged temp file + rename (distinct from
// the config-engine atomicWrite in nginx.go, which keeps a rollback copy).
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
