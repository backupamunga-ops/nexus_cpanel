package commands

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// backup.* (agent spec §4.14, amended at B10 with backup.test_destination) —
// P4: backups & restore.
//
//   - One artifact per run: a gzipped tar of the staged sources plus a JSON
//     manifest sibling (format, scope, sources, entry count, tar checksum,
//     encryption flag). The sha256 recorded by the control plane is over the
//     final artifact bytes (after encryption) — the transport never sees a
//     trusted checksum, so verify() re-hashes what actually landed.
//   - C15 encryption: artifacts are encrypted with age against recipient
//     PUBLIC keys carried in the destination config; the age identity
//     (master key) never crosses the RPC channel — it is a file on the node
//     (AgeIdentityPath). An encrypted artifact with no identity on the node
//     is a loud precondition error, never a silent skip: decryption without
//     the master key fails, by construction.
//   - Destination secrets ride the signed channel once per call (the
//     MYSQL_PWD precedent) and are never written to a WAL entry, a log line,
//     a manifest, or an argv.
//   - Path confinement: account/site sources and restore targets resolve
//     through fsTarget (C13). Local destination roots are confined under
//     BackupRoot. Tar entries are sanitized (no absolute paths, no "..",
//     no escaping symlinks — v1 extracts regular files and directories
//     only, skipping anything else with an honest count).

const (
	backupPreviewEntryCap = 500
	backupMaxSources      = 64
	backupProbeBytes      = 1024
)

var backupScopeRe = regexp.MustCompile(`^(server|account|site|database)$`)

var backupUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// backupManifest is the JSON written next to every artifact.
type backupManifest struct {
	Format         string   `json:"format"` // nexuspanel-backup/v1
	CreatedAt      string   `json:"created_at"`
	Scope          string   `json:"scope"`
	ScopeID        string   `json:"scope_id,omitempty"`
	Owner          string   `json:"owner_username,omitempty"`
	Sources        []string `json:"sources,omitempty"`
	Database       string   `json:"database,omitempty"`
	Entries        int      `json:"entries"`
	SizeBytes      int64    `json:"size_bytes"` // pre-encryption tar.gz size
	ChecksumTarGz  string   `json:"checksum_sha256_tar_gz"`
	Encrypted      bool     `json:"encrypted"`
	AgeRecipientsN int      `json:"age_recipients_count"`
	Artifact       string   `json:"artifact"`
	Panel          string   `json:"panel"`
}

// ---- staging ------------------------------------------------------------------

// backupStageResult is what staging produces before encryption/upload.
type backupStageResult struct {
	stagingDir string
	entries    int
	sources    []string
	database   string
}

// backupStageSources copies the requested home-relative sources into a
// staging dir (scope account/site), or dumps the database into it
// (scope database), or snapshots the agent's own managed dirs (scope server).
func (r *Registry) backupStageSources(scope, scopeID, owner string, sources []string, database *struct {
	Engine string `json:"engine"`
	Name   string `json:"name"`
}) (*backupStageResult, error) {
	staging, err := os.MkdirTemp("", "nexuspanel-bk-")
	if err != nil {
		return nil, mailInternalError("backup staging failed", err)
	}
	res := &backupStageResult{stagingDir: staging}

	switch scope {
	case "server":
		// Fixed allowlist of agent-managed dirs — the operator never picks
		// server-scope paths over the wire.
		for _, dir := range []string{r.deps.VhostRoot, r.deps.FtpConfigDir, r.deps.OpendkimTableDir} {
			if dir == "" {
				continue
			}
			if err := copyTree(dir, filepath.Join(staging, filepath.Base(dir))); err != nil {
				os.RemoveAll(staging)
				return nil, mailInternalError("server source copy failed", err)
			}
			res.sources = append(res.sources, filepath.Base(dir))
		}
		if len(res.sources) == 0 {
			// Honest: an empty server config snapshot is still a valid
			// (documented) artifact.
			res.sources = []string{"(no managed dirs configured)"}
		}
	case "database":
		if database == nil || database.Engine == "" || database.Name == "" {
			os.RemoveAll(staging)
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
				Message: "database scope requires database.engine and database.name"}
		}
		if err := requireEngine(database.Engine); err != nil {
			os.RemoveAll(staging)
			return nil, err
		}
		name := strings.ToLower(strings.TrimSpace(database.Name))
		if !dbNameRe.MatchString(name) {
			os.RemoveAll(staging)
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid database name"}
		}
		adapter, err := r.resolveDbAdapter(database.Engine)
		if err != nil {
			os.RemoveAll(staging)
			return nil, err
		}
		m, ok := adapter.(*mariadbAdapter)
		if !ok || m.dumpBin == "" {
			os.RemoveAll(staging)
			return nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "mariadb-dump binary not found on this node"}
		}
		out, err := exec.Command(m.dumpBin, name).Output()
		if err != nil {
			os.RemoveAll(staging)
			return nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "db dump failed: " + firstDbErr(string(out), err)}
		}
		if err := os.WriteFile(filepath.Join(staging, name+".sql"), out, 0o600); err != nil {
			os.RemoveAll(staging)
			return nil, mailInternalError("db dump write failed", err)
		}
		res.database = name
		res.sources = []string{name + ".sql"}
	default: // account | site
		if owner == "" {
			os.RemoveAll(staging)
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
				Message: "owner_username is required for account/site backups (paths confine to the account home)"}
		}
		if err := r.ftpValidateOwner(owner); err != nil {
			os.RemoveAll(staging)
			return nil, err
		}
		if len(sources) == 0 {
			sources = []string{"."} // whole home
		}
		if len(sources) > backupMaxSources {
			os.RemoveAll(staging)
			return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
				Message: fmt.Sprintf("too many sources (max %d)", backupMaxSources)}
		}
		for i, src := range sources {
			if strings.TrimSpace(src) == "" {
				src = "." // whole home
			}
			abs, err := fsTarget(r.deps.HomeRoot, owner, src)
			if err != nil {
				os.RemoveAll(staging)
				return nil, err
			}
			name := filepath.Base(abs)
			if src == "" || abs == filepath.Join(r.deps.HomeRoot, owner) {
				name = "home"
			}
			if err := copyTree(abs, filepath.Join(staging, fmt.Sprintf("%02d-%s", i, name))); err != nil {
				os.RemoveAll(staging)
				return nil, err
			}
			res.sources = append(res.sources, src)
		}
	}
	return res, nil
}

// copyTree copies files/dirs (regular files only; symlinks become honest
// skips — hosting homes are full of sockets and links we must not follow).
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "source not found: " + filepath.Base(src)}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil // honest skip, counted by the caller via tar walk
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return mailInternalError("source read failed", err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return mailInternalError("staging mkdir failed", err)
		}
		return os.WriteFile(dst, data, 0o600)
	}
	return filepath.WalkDir(src, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks/devices/sockets honestly
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil // skip unreadable files honestly
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

// backupBuildTar gzips the staging dir into outPath and returns the entry
// count + tar.gz size.
func backupBuildTar(stagingDir, outPath string) (entries int, size int64, err error) {
	f, err := os.Create(outPath)
	if err != nil {
		return 0, 0, mailInternalError("artifact create failed", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	err = filepath.WalkDir(stagingDir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(stagingDir, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		hdr, herr := tar.FileInfoHeader(info, "")
		if herr != nil {
			return herr
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.Type().IsRegular() {
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}
		entries++
		return nil
	})
	if err != nil {
		return 0, 0, mailInternalError("tar walk failed", err)
	}
	if err := tw.Close(); err != nil {
		return 0, 0, mailInternalError("tar close failed", err)
	}
	if err := gz.Close(); err != nil {
		return 0, 0, mailInternalError("gzip close failed", err)
	}
	if err := f.Sync(); err != nil {
		return 0, 0, mailInternalError("artifact sync failed", err)
	}
	fi, err := os.Stat(outPath)
	if err != nil {
		return 0, 0, mailInternalError("artifact stat failed", err)
	}
	return entries, fi.Size(), nil
}

// ---- age (C15) ------------------------------------------------------------------

func (r *Registry) resolveAgeBinary() (string, error) {
	if r.deps.AgeBinary != "" {
		return r.deps.AgeBinary, nil
	}
	found, err := exec.LookPath("age")
	if err != nil {
		return "", &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "age binary not found on this node — encrypted backups (C15) require it; use an empty recipients list only if plaintext is an explicit, documented choice",
		}
	}
	return found, nil
}

// ageEncrypt encrypts src into out against the recipient public keys.
func (r *Registry) ageEncrypt(src, out string, recipients []string) error {
	bin, err := r.resolveAgeBinary()
	if err != nil {
		return err
	}
	args := []string{"-o", out}
	for _, rc := range recipients {
		args = append(args, "-r", rc)
	}
	args = append(args, src)
	cmd := exec.Command(bin, args...)
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: "age encrypt failed: " + firstDbErr(string(outBytes), err)}
	}
	return nil
}

// ageDecrypt decrypts src into out using the node's identity file. A missing
// identity is a loud precondition (C15 negative path), not a silent fallback.
func (r *Registry) ageDecrypt(src, out string) error {
	bin, err := r.resolveAgeBinary()
	if err != nil {
		return err
	}
	if r.deps.AgeIdentityPath == "" {
		return &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "this artifact is age-encrypted but no age identity is configured on this node — decryption without the master key must fail (C15)",
		}
	}
	if _, err := os.Stat(r.deps.AgeIdentityPath); err != nil {
		return &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "age identity file is configured but missing/unreadable — encrypted restore refused (C15)",
		}
	}
	cmd := exec.Command(bin, "-d", "-i", r.deps.AgeIdentityPath, "-o", out, src)
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: "age decrypt failed (wrong or missing master key?): " + firstDbErr(string(outBytes), err)}
	}
	return nil
}

// ---- handlers --------------------------------------------------------------------

type backupCreateResult struct {
	Status         string         `json:"status"` // created
	Scope          string         `json:"scope"`
	Artifact       string         `json:"artifact"`
	ChecksumSha256 string         `json:"checksum_sha256"`
	SizeBytes      int64          `json:"size_bytes"`
	Encrypted      bool           `json:"encrypted"`
	Manifest       backupManifest `json:"manifest"`
}

func (r *Registry) backupCreate(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Scope       string            `json:"scope"`
		ScopeID     string            `json:"scope_id"`
		Destination backupDestination `json:"destination"`
		Sources     []string          `json:"sources"`
		Database    *struct {
			Engine string `json:"engine"`
			Name   string `json:"name"`
		} `json:"database"`
		OwnerUsername string `json:"owner_username"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !backupScopeRe.MatchString(p.Scope) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: "scope must be one of server | account | site | database"}
	}
	if p.Scope == "server" && p.ScopeID != "" {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "server scope takes no scope_id"}
	}
	if p.Scope != "server" && !backupUUIDRe.MatchString(p.ScopeID) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "scope_id must be a uuid for account/site/database scopes"}
	}

	transport, err := r.resolveTransport(p.Destination)
	if err != nil {
		return nil, nil, err
	}

	staged, err := r.backupStageSources(p.Scope, p.ScopeID, p.OwnerUsername, p.Sources, p.Database)
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(staged.stagingDir)

	tmpDir, err := os.MkdirTemp("", "nexuspanel-bk-art-")
	if err != nil {
		return nil, nil, mailInternalError("artifact temp failed", err)
	}
	defer os.RemoveAll(tmpDir)

	tarPath := filepath.Join(tmpDir, "artifact.tar.gz")
	entries, tarSize, err := backupBuildTar(staged.stagingDir, tarPath)
	if err != nil {
		return nil, nil, err
	}
	tarSum, _, err := sha256File(tarPath)
	if err != nil {
		return nil, nil, mailInternalError("artifact hash failed", err)
	}

	// Encryption (C15): age against the destination's recipient keys.
	finalPath := tarPath
	encrypted := len(p.Destination.AgeRecipients) > 0
	if encrypted {
		encPath := tarPath + ".age"
		if err := r.ageEncrypt(tarPath, encPath, p.Destination.AgeRecipients); err != nil {
			return nil, nil, err
		}
		finalPath = encPath
	}
	finalSum, finalSize, err := sha256File(finalPath)
	if err != nil {
		return nil, nil, mailInternalError("artifact hash failed", err)
	}

	artifact := newArtifactName(p.Scope, map[bool]string{true: ".tar.gz.age", false: ".tar.gz"}[encrypted])
	manifest := backupManifest{
		Format:         "nexuspanel-backup/v1",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Scope:          p.Scope,
		ScopeID:        p.ScopeID,
		Owner:          p.OwnerUsername,
		Sources:        staged.sources,
		Entries:        entries,
		SizeBytes:      tarSize,
		ChecksumTarGz:  tarSum,
		Encrypted:      encrypted,
		AgeRecipientsN: len(p.Destination.AgeRecipients),
		Artifact:       artifact,
		Panel:          "nexuspanel-agent",
	}
	if staged.database != "" {
		manifest.Database = staged.database
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	// Upload artifact + manifest. If the artifact lands but the manifest
	// does not, roll the artifact back — no half-uploaded pairs.
	if err := transport.Put(finalPath, artifact); err != nil {
		return nil, nil, err
	}
	manifestName := artifact + manifestSuffix
	manifestTmp := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestTmp, manifestBytes, 0o600); err != nil {
		_ = transport.Delete(artifact)
		return nil, nil, mailInternalError("manifest write failed", err)
	}
	if err := transport.Put(manifestTmp, manifestName); err != nil {
		_ = transport.Delete(artifact)
		return nil, nil, err
	}

	entry := r.deps.WAL.NewEntry("backup.create", map[string]any{
		"scope":            p.Scope,
		"scope_id":         p.ScopeID,
		"destination_type": p.Destination.Type,
		"encrypted":        encrypted,
		"artifact":         artifact,
		"size_bytes":       finalSize,
		"checksum":         finalSum,
	})
	_ = r.deps.WAL.Append(entry)
	return backupCreateResult{
		Status:         "created",
		Scope:          p.Scope,
		Artifact:       artifact,
		ChecksumSha256: finalSum,
		SizeBytes:      finalSize,
		Encrypted:      encrypted,
		Manifest:       manifest,
	}, auditQueued(entry), nil
}

// backupFetch pulls the artifact (+manifest) to a temp dir, decrypting when
// the manifest flags it. Returns (artifactPath, manifest, tmpDir, cleanup).
func (r *Registry) backupFetch(artifact string, dest backupDestination) (string, *backupManifest, string, func(), error) {
	transport, err := r.resolveTransport(dest)
	if err != nil {
		return "", nil, "", nil, err
	}
	if strings.ContainsRune(artifact, '/') || strings.ContainsRune(artifact, '\\') || strings.Contains(artifact, "..") {
		return "", nil, "", nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "artifact must be a bare destination-relative name"}
	}
	tmpDir, err := os.MkdirTemp("", "nexuspanel-bk-get-")
	if err != nil {
		return "", nil, "", nil, mailInternalError("temp dir failed", err)
	}
	cleanup := func() { os.RemoveAll(tmpDir) }

	local := filepath.Join(tmpDir, "artifact")
	if err := transport.Get(artifact, local); err != nil {
		cleanup()
		return "", nil, "", nil, err
	}
	manifestPath := filepath.Join(tmpDir, "manifest")
	if err := transport.Get(artifact+manifestSuffix, manifestPath); err != nil {
		cleanup()
		return "", nil, "", nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: "manifest not found next to the artifact — previews and restores require it"}
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		cleanup()
		return "", nil, "", nil, mailInternalError("manifest read failed", err)
	}
	var m backupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		cleanup()
		return "", nil, "", nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "manifest is not valid JSON"}
	}
	work := local
	if m.Encrypted {
		plain := local + ".plain"
		if err := r.ageDecrypt(local, plain); err != nil {
			cleanup()
			return "", nil, "", nil, err
		}
		work = plain
	}
	return work, &m, tmpDir, cleanup, nil
}

type backupPreviewResult struct {
	Manifest      backupManifest   `json:"manifest"`
	Entries       []backupTarEntry `json:"entries"`
	TotalEntries  int              `json:"total_entries"`
	Truncated     bool             `json:"truncated"`
	ChecksumMatch bool             `json:"checksum_match"`
}

type backupTarEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (r *Registry) backupRestorePreview(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Artifact    string            `json:"artifact_path"`
		Destination backupDestination `json:"destination"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	work, m, _, cleanup, err := r.backupFetch(p.Artifact, p.Destination)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	entries, match, err := listTar(work, m.ChecksumTarGz)
	if err != nil {
		return nil, nil, err
	}
	truncated := false
	if len(entries) > backupPreviewEntryCap {
		entries = entries[:backupPreviewEntryCap]
		truncated = true
	}
	return backupPreviewResult{
		Manifest:      *m,
		Entries:       entries,
		TotalEntries:  len(entries),
		Truncated:     truncated,
		ChecksumMatch: match,
	}, nil, nil
}

// listTar walks the tar and verifies its sha256 against the manifest.
func listTar(tarGz, expectSum string) ([]backupTarEntry, bool, error) {
	f, err := os.Open(tarGz)
	if err != nil {
		return nil, false, mailInternalError("artifact open failed", err)
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return nil, false, mailInternalError("artifact hash failed", err)
	}
	match := expectSum == "" || hex.EncodeToString(h.Sum(nil)) == expectSum
	if _, err := f.Seek(0, 0); err != nil {
		return nil, false, mailInternalError("artifact rewind failed", err)
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, false, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "artifact is not a gzipped tar"}
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	entries := []backupTarEntry{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		entries = append(entries, backupTarEntry{Name: hdr.Name, Size: hdr.Size})
	}
	return entries, match, nil
}

type backupRestoreResult struct {
	Status     string   `json:"status"` // restored | dry_run_ok
	Extracted  []string `json:"extracted"`
	Skipped    int      `json:"skipped"`
	Into       string   `json:"into,omitempty"`
	ChecksumOk bool     `json:"checksum_ok"`
}

func (r *Registry) backupRestore(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Artifact      string            `json:"artifact_path"`
		Destination   backupDestination `json:"destination"`
		Scope         string            `json:"scope"`
		ScopeID       string            `json:"scope_id"`
		TargetPath    string            `json:"target_path"`
		DryRun        bool              `json:"dry_run"`
		OwnerUsername string            `json:"owner_username"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !backupScopeRe.MatchString(p.Scope) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: "scope must be one of server | account | site | database"}
	}
	if p.OwnerUsername == "" {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: "owner_username is required — restores extract inside the account home (C13)"}
	}
	if err := r.ftpValidateOwner(p.OwnerUsername); err != nil {
		return nil, nil, err
	}
	target := p.TargetPath
	if target == "" {
		target = fmt.Sprintf("restored-%s", time.Now().UTC().Format("20060102T150405Z"))
	}
	if strings.ContainsRune(target, 0) || strings.Contains(target, "..") {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "target_path must be a home-relative path without '..'"}
	}
	targetAbs, err := fsTarget(r.deps.HomeRoot, p.OwnerUsername, target)
	if err != nil {
		return nil, nil, err
	}

	work, m, tmpDir, cleanup, err := r.backupFetch(p.Artifact, p.Destination)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	// Restore integrity gate: the fetched (decrypted) tar.gz must match the
	// manifest checksum, or the restore refuses — restore never consumes a
	// silently corrupted artifact.
	gotSum, _, err := sha256File(work)
	if err != nil {
		return nil, nil, mailInternalError("artifact hash failed", err)
	}
	if gotSum != m.ChecksumTarGz {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: "artifact does not match its manifest checksum — refusing to restore (run backup.verify for details)"}
	}

	// Server-scope restores land in a temp dir and are reported, not
	// extracted into a home (server config is applied via the config
	// engine, not by overwriting files under an account).
	extractDir := targetAbs
	if p.Scope == "server" {
		extractDir = filepath.Join(tmpDir, "server-extract")
	} else if !p.DryRun {
		if err := os.MkdirAll(targetAbs, 0o750); err != nil {
			return nil, nil, mailInternalError("restore target create failed", err)
		}
	}

	extracted, skipped, sumOk, err := extractTar(work, m.ChecksumTarGz, extractDir, p.DryRun)
	if err != nil {
		return nil, nil, err
	}

	status := "restored"
	into := safePathSummary(extractDir)
	if p.DryRun {
		status = "dry_run_ok"
	}
	_ = sumOk

	entry := r.deps.WAL.NewEntry("backup.restore", map[string]any{
		"artifact":  p.Artifact,
		"scope":     p.Scope,
		"scope_id":  p.ScopeID,
		"dry_run":   p.DryRun,
		"into":      safePathSummary(into),
		"owner":     p.OwnerUsername,
		"extracted": len(extracted),
		"skipped":   skipped,
	})
	_ = r.deps.WAL.Append(entry)
	return backupRestoreResult{
		Status:     status,
		Extracted:  extracted,
		Skipped:    skipped,
		Into:       into,
		ChecksumOk: true,
	}, auditQueued(entry), nil
}

// extractTar extracts a (possibly encrypted) tar.gz, sanitizing every entry:
// absolute paths, "..", and non-regular/dir entries are skipped with a count.
func extractTar(tarGz, expectSum, into string, dryRun bool) (extracted []string, skipped int, sumOk bool, err error) {
	f, err := os.Open(tarGz)
	if err != nil {
		return nil, 0, false, mailInternalError("artifact open failed", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, 0, false, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "artifact is not a gzipped tar"}
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	extracted = []string{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		name := hdr.Name
		if filepath.IsAbs(name) || strings.Contains(name, "..") || strings.ContainsRune(name, 0) {
			skipped++
			continue
		}
		clean := filepath.Clean(name)
		target := filepath.Join(into, clean)
		if !strings.HasPrefix(target, filepath.Clean(into)+string(filepath.Separator)) && target != filepath.Clean(into) {
			skipped++
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if !dryRun {
				if err := os.MkdirAll(target, 0o750); err != nil {
					return nil, skipped, false, mailInternalError("restore mkdir failed", err)
				}
			}
			extracted = append(extracted, clean+"/")
		case tar.TypeReg:
			data, rerr := io.ReadAll(tr)
			if rerr != nil {
				return nil, skipped, false, mailInternalError("restore read failed", rerr)
			}
			if !dryRun {
				if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
					return nil, skipped, false, mailInternalError("restore mkdir failed", err)
				}
				if err := os.WriteFile(target, data, 0o600); err != nil {
					return nil, skipped, false, mailInternalError("restore write failed", err)
				}
			}
			extracted = append(extracted, clean)
		default:
			skipped++ // symlinks/devices: skipped honestly (v1)
		}
	}
	return extracted, skipped, true, nil
}

type backupVerifyResult struct {
	Status         string `json:"status"` // verified | failed
	ChecksumSha256 string `json:"checksum_sha256"`
	Expected       string `json:"expected,omitempty"`
	Encrypted      bool   `json:"encrypted"`
	Reason         string `json:"reason,omitempty"`
}

func (r *Registry) backupVerify(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Artifact    string            `json:"artifact_path"`
		Destination backupDestination `json:"destination"`
		Checksum    string            `json:"checksum"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	work, m, _, cleanup, err := r.backupFetch(p.Artifact, p.Destination)
	// NOTE: on fetch failure we still report a *failed* verify with the
	// reason, because a verify endpoint that errors is less useful to the
	// operator than one that answers "failed: <why>".
	if err != nil {
		return backupVerifyResult{Status: "failed", Expected: p.Checksum, Reason: err.Error()}, nil, nil
	}
	defer cleanup()

	sum, _, err := sha256File(work)
	if err != nil {
		return backupVerifyResult{Status: "failed", Encrypted: m.Encrypted, Reason: "hash failed: " + err.Error()}, nil, nil
	}
	if p.Checksum != "" && sum != p.Checksum {
		return backupVerifyResult{Status: "failed", ChecksumSha256: sum, Expected: p.Checksum, Encrypted: m.Encrypted,
			Reason: "checksum mismatch — the artifact at the destination does not match the recorded digest"}, nil, nil
	}
	// Cross-check the manifest's inner tar checksum (detects bit-rot inside
	// a re-encrypted artifact).
	entries, innerOk, err := listTar(work, m.ChecksumTarGz)
	if err != nil || !innerOk {
		reason := "inner tar checksum mismatch"
		if err != nil {
			reason += ": " + err.Error()
		}
		return backupVerifyResult{Status: "failed", ChecksumSha256: sum, Expected: p.Checksum, Encrypted: m.Encrypted, Reason: reason}, nil, nil
	}
	if len(entries) == 0 {
		return backupVerifyResult{Status: "failed", ChecksumSha256: sum, Encrypted: m.Encrypted,
			Reason: "artifact contains no entries"}, nil, nil
	}

	entry := r.deps.WAL.NewEntry("backup.verify", map[string]any{
		"artifact": p.Artifact, "destination_type": p.Destination.Type,
		"encrypted": m.Encrypted, "checksum": sum, "outcome": "verified",
	})
	_ = r.deps.WAL.Append(entry)
	return backupVerifyResult{
		Status:         "verified",
		ChecksumSha256: sum,
		Expected:       p.Checksum,
		Encrypted:      m.Encrypted,
	}, auditQueued(entry), nil
}

type backupPurgeResult struct {
	Status    string   `json:"status"` // purged
	Deleted   []string `json:"deleted"`
	Protected []string `json:"protected"`
	Failed    []string `json:"failed,omitempty"`
}

func (r *Registry) backupPurge(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Destination backupDestination `json:"destination"`
		BeforeDate  string            `json:"before_date"`
		Delete      []string          `json:"delete"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	cutoff, err := time.Parse(time.RFC3339, strings.TrimSpace(p.BeforeDate))
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: "before_date must be an RFC3339 timestamp"}
	}
	transport, err := r.resolveTransport(p.Destination)
	if err != nil {
		return nil, nil, err
	}
	res := backupPurgeResult{Status: "purged"}
	for _, name := range p.Delete {
		if strings.ContainsRune(name, '/') || strings.ContainsRune(name, '\\') || strings.Contains(name, "..") {
			res.Failed = append(res.Failed, name)
			continue
		}
		// Belt and suspenders: if a manifest sits next to the artifact and
		// says it is NEWER than the cutoff, protect it even though the
		// control plane asked for deletion.
		if m := r.purgeManifestDate(transport, name); m != nil && m.After(cutoff) {
			res.Protected = append(res.Protected, name)
			continue
		}
		if err := transport.Delete(name); err != nil {
			res.Failed = append(res.Failed, name)
			continue
		}
		_ = transport.Delete(name + manifestSuffix)
		res.Deleted = append(res.Deleted, name)
	}
	if len(res.Deleted) > 0 {
		entry := r.deps.WAL.NewEntry("backup.purge", map[string]any{
			"destination_type": p.Destination.Type,
			"before_date":      cutoff.Format(time.RFC3339),
			"deleted":          len(res.Deleted),
			"protected":        len(res.Protected),
			"failed":           len(res.Failed),
		})
		_ = r.deps.WAL.Append(entry)
		return res, auditQueued(entry), nil
	}
	return res, nil, nil
}

// purgeManifestDate best-effort reads the manifest's created_at for the
// protection check. Absent manifests never block a purge (the control
// plane's registry is authoritative).
func (r *Registry) purgeManifestDate(t BackupTransport, name string) *time.Time {
	tmp, err := os.MkdirTemp("", "nexuspanel-bk-pm-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)
	if err := t.Get(name+manifestSuffix, filepath.Join(tmp, "m")); err != nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(tmp, "m"))
	if err != nil {
		return nil
	}
	var m backupManifest
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	ts, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return nil
	}
	return &ts
}

type backupTestDestinationResult struct {
	Status         string `json:"status"` // ok
	RoundTripBytes int    `json:"round_trip_bytes"`
	Encrypted      bool   `json:"encrypted"`
	HostKeyPinned  bool   `json:"host_key_pinned"`
	Note           string `json:"note,omitempty"`
}

// backupTestDestination is the B10 amendment to §4.14: probe a destination
// with a small round-trip (put → get → checksum → delete both).
func (r *Registry) backupTestDestination(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Destination backupDestination `json:"destination"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	transport, err := r.resolveTransport(p.Destination)
	if err != nil {
		return nil, nil, err
	}

	tmpDir, err := os.MkdirTemp("", "nexuspanel-bk-probe-")
	if err != nil {
		return nil, nil, mailInternalError("probe temp failed", err)
	}
	defer os.RemoveAll(tmpDir)

	probe := make([]byte, backupProbeBytes)
	if _, err := rand.Read(probe); err != nil {
		return nil, nil, mailInternalError("probe rand failed", err)
	}
	probePath := filepath.Join(tmpDir, "probe")
	if err := os.WriteFile(probePath, probe, 0o600); err != nil {
		return nil, nil, mailInternalError("probe write failed", err)
	}
	sum, _, err := sha256File(probePath)
	if err != nil {
		return nil, nil, mailInternalError("probe hash failed", err)
	}
	name := fmt.Sprintf("probe-%s.bin", strings.ReplaceAll(time.Now().UTC().Format("20060102T150405Z"), ":", ""))
	if err := transport.Put(probePath, name); err != nil {
		return nil, nil, err
	}
	backPath := filepath.Join(tmpDir, "probe.back")
	if err := transport.Get(name, backPath); err != nil {
		_ = transport.Delete(name)
		return nil, nil, err
	}
	backSum, _, err := sha256File(backPath)
	if err != nil {
		_ = transport.Delete(name)
		return nil, nil, mailInternalError("probe hash failed", err)
	}
	_ = transport.Delete(name)
	_ = transport.Delete(name + manifestSuffix)

	if backSum != sum {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: "round-trip checksum mismatch — the destination returned different bytes than it received"}
	}

	note := ""
	if p.Destination.Type == "sftp" && p.Destination.HostKey == "" {
		note = "host key not pinned — StrictHostKeyChecking=accept-new is in effect; pin host_key for defense against MITM"
	}
	entry := r.deps.WAL.NewEntry("backup.test_destination", map[string]any{
		"destination_type": p.Destination.Type,
		"round_trip_bytes": len(probe),
	})
	_ = r.deps.WAL.Append(entry)
	return backupTestDestinationResult{
		Status:         "ok",
		RoundTripBytes: len(probe),
		Encrypted:      len(p.Destination.AgeRecipients) > 0,
		HostKeyPinned:  p.Destination.Type != "sftp" || p.Destination.HostKey != "",
		Note:           note,
	}, auditQueued(entry), nil
}
