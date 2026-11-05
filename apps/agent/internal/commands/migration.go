package commands

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// migration.* (ADR-0020 amendment to agent spec §4) — B15: migration center.
//
// The agent is where the artifact lives and where extraction happens; the
// panel owns the ledger (migration_jobs / migration_entity_mappings) and
// the phase machine. Safety mirrors the backup root rules:
//
//   - artifacts live ONLY under the migration root (basename references,
//     no separators, no "..", symlink-refusing);
//   - analyze NEVER extracts to the live tree — it streams the tarball
//     entry-by-entry and hashes small entities on the fly (M15: integrity
//     over wall-clock);
//   - extraction targets are account-confined (fsTarget); extraction runs
//     with --no-same-owner and the tree is chowned to the ACCOUNT USER
//     (root artifact files are never readable by the account);
//   - every written file is hashed into a manifest the verify phase
//     replays byte-for-byte;
//   - dumps are imported with FRESH credentials created in the same call —
//     artifact credentials are never read, parsed or reused (§6).

const (
	maxArtifactSize  = 100 << 30 // 100 GiB cap (spec §2: size caps)
	maxManifestFiles = 200_000   // honest refusal before silent truncation
	inlineMemberMax  = 2 << 20   // zones/certs/crons are small; dumps are not
)

var migrationNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,128}$`)
var migrationDBRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

type migrationArtifactRef struct {
	Artifact string `json:"artifact"`
}

// migrationRoot resolves (and creates) the artifact staging root.
func (r *Registry) migrationRoot() (string, error) {
	root := r.deps.MigrationRoot
	if root == "" {
		root = "/var/lib/nexuspanel-agent/migrations"
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", &rpc.RPCError{Code: rpc.CodeInternalError, Message: "migration root unavailable: " + err.Error()}
	}
	return filepath.Abs(root)
}

// resolveArtifact confines an artifact reference to the migration root.
func (r *Registry) resolveArtifact(name string) (string, error) {
	if !migrationNameRe.MatchString(name) || strings.Contains(name, "..") {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "artifact must be a file name inside the migration staging root"}
	}
	root, err := r.migrationRoot()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return "", &rpc.RPCError{Code: rpc.CodePrecondition, Message: "artifact not found in the migration staging root: " + name}
	}
	if !fi.Mode().IsRegular() {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "artifact must be a regular file"}
	}
	if fi.Size() > maxArtifactSize {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "artifact exceeds the 100 GiB cap"}
	}
	return path, nil
}

// migrationArtifact is one cpmove artifact on the staging root (list view).
type migrationArtifact struct {
	Name     string `json:"name"`
	Size     int64  `json:"size_bytes"`
	Checksum string `json:"sha256"`
}

// migrationListArtifacts lists candidate cpmove artifacts with sizes and
// sha256 checksums (the artifact hash is recorded BEFORE anything else
// happens, spec §2).
func (r *Registry) migrationListArtifacts(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	root, err := r.migrationRoot()
	if err != nil {
		return nil, nil, err
	}
	entries, _ := os.ReadDir(root)
	out := []migrationArtifact{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		p := filepath.Join(root, e.Name())
		sum, size, err := sha256File(p)
		if err != nil {
			continue
		}
		out = append(out, migrationArtifact{Name: e.Name(), Size: size, Checksum: sum})
	}
	return map[string]any{"root": root, "artifacts": out}, nil, nil
}

// ---- analyze -----------------------------------------------------------------

type migrationEntity struct {
	Type     string `json:"type"` // files | dns_zone | mail_domain | mailbox | database | ssl | cron
	SourceID string `json:"source_id"`
	Size     int64  `json:"size_bytes"`
	Checksum string `json:"sha256,omitempty"`
	Count    int    `json:"count,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

type migrationAnalyzeResult struct {
	Artifact   string            `json:"artifact"`
	Size       int64             `json:"size_bytes"`
	Checksum   string            `json:"sha256"`
	Prefix     string            `json:"prefix"`
	Entities   []migrationEntity `json:"entities"`
	EntryCount int               `json:"entry_count"`
}

// migrationAnalyze inventories the artifact read-only (streaming walk,
// never extracted to the live tree — spec §2).
func (r *Registry) migrationAnalyze(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p migrationArtifactRef
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := r.resolveArtifact(p.Artifact)
	if err != nil {
		return nil, nil, err
	}
	sum, size, err := sha256File(path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "artifact hash failed: " + err.Error()}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "artifact unreadable: " + err.Error()}
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "not a gzip tarball: " + err.Error()}
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	res := migrationAnalyzeResult{Artifact: p.Artifact, Size: size, Checksum: sum}
	fileSets := map[string]*migrationEntity{}
	mailDomains := map[string]bool{}
	mailboxes := map[string]bool{}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition,
				Message: "malformed artifact (tar stream): " + err.Error() + " — a partial inventory is never promoted to a plan"}
		}
		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "./")
		if res.Prefix == "" && !strings.HasPrefix(name, ".") {
			res.Prefix = strings.SplitN(name, "/", 2)[0]
		}
		res.EntryCount++
		rel := strings.TrimPrefix(name, res.Prefix+"/")

		switch {
		case strings.HasPrefix(rel, "homedir/mail/") && strings.HasSuffix(name, "/"):
			// homedir/mail/<domain>/<localpart>/ directory members → mailboxes
			inner := strings.Trim(rel[len("homedir/mail/"):], "/")
			parts := strings.Split(inner, "/")
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				key := parts[0] + "/" + parts[1]
				if !mailboxes[key] {
					mailboxes[key] = true
					mailDomains[parts[0]] = true
				}
			}
		case strings.HasPrefix(rel, "homedir/"):
			top := strings.SplitN(strings.TrimPrefix(rel, "homedir/"), "/", 2)[0]
			if top == "" || top == "mail" || strings.HasPrefix(top, ".") || top == "etc" {
				break
			}
			fs := fileSets[top]
			if fs == nil {
				fs = &migrationEntity{Type: "files", SourceID: "homedir/" + top}
				fileSets[top] = fs
			}
			if !strings.HasSuffix(name, "/") {
				fs.Size += hdr.Size
				fs.Count++
			}
		case strings.HasPrefix(rel, "mysql/") && (strings.HasSuffix(rel, ".sql") || strings.HasSuffix(rel, ".sql.gz")):
			msum, msz, merr := hashTarMember(path, name)
			if merr != nil {
				return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "dump hash failed for " + name + ": " + merr.Error()}
			}
			res.Entities = append(res.Entities, migrationEntity{
				Type: "database", SourceID: strings.TrimSuffix(strings.TrimPrefix(rel, "mysql/"), ".gz"),
				Size: msz, Checksum: msum,
			})
		case strings.HasPrefix(rel, "dnszones/") && strings.HasSuffix(rel, ".db"):
			msum, msz, merr := hashTarMember(path, name)
			if merr != nil {
				return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "zone hash failed for " + name + ": " + merr.Error()}
			}
			res.Entities = append(res.Entities, migrationEntity{
				Type: "dns_zone", SourceID: strings.TrimSuffix(strings.TrimPrefix(rel, "dnszones/"), ".db"),
				Size: msz, Checksum: msum,
			})
		case strings.HasPrefix(rel, "sslcerts/"):
			msum, msz, merr := hashTarMember(path, name)
			if merr != nil {
				return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "cert hash failed for " + name + ": " + merr.Error()}
			}
			res.Entities = append(res.Entities, migrationEntity{
				Type: "ssl", SourceID: strings.TrimPrefix(rel, "sslcerts/"), Size: msz, Checksum: msum,
			})
		case strings.HasPrefix(rel, "cron/"):
			msum, msz, merr := hashTarMember(path, name)
			if merr != nil {
				return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "cron hash failed for " + name + ": " + merr.Error()}
			}
			res.Entities = append(res.Entities, migrationEntity{
				Type: "cron", SourceID: strings.TrimPrefix(rel, "cron/"), Size: msz, Checksum: msum,
				Notes: "imported as data (stored lines); scheduling lands with the job framework",
			})
		}
	}
	for _, fs := range fileSets {
		res.Entities = append(res.Entities, *fs)
	}
	for d := range mailDomains {
		res.Entities = append(res.Entities, migrationEntity{Type: "mail_domain", SourceID: d})
	}
	for k := range mailboxes {
		res.Entities = append(res.Entities, migrationEntity{Type: "mailbox", SourceID: k})
	}
	sort.Slice(res.Entities, func(i, j int) bool {
		if res.Entities[i].Type != res.Entities[j].Type {
			return res.Entities[i].Type < res.Entities[j].Type
		}
		return res.Entities[i].SourceID < res.Entities[j].SourceID
	})
	return res, nil, nil
}

// hashTarMember streams one member's content into sha256 without touching
// the live tree (analyze stays read-only, spec §2).
func hashTarMember(artifact, member string) (string, int64, error) {
	cmd := exec.Command("tar", "-xOzf", artifact, member)
	pr, pw := io.Pipe()
	h := sha256.New()
	var size int64
	done := make(chan error, 1)
	go func() {
		n, err := io.Copy(h, pr)
		size = n
		done <- err
	}()
	cmd.Stdout = pw
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	_ = pw.Close()
	if copyErr := <-done; copyErr != nil {
		return "", 0, copyErr
	}
	if runErr != nil {
		return "", 0, fmt.Errorf("%s", firstLine(errBuf.String()))
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// ---- extraction ----------------------------------------------------------------

type migrationExtractTreeParams struct {
	Artifact       string `json:"artifact"`
	Prefix         string `json:"prefix"`     // e.g. cpmove-user/homedir/public_html
	Username       string `json:"username"`   // account user
	TargetRel      string `json:"target_rel"` // relative to the account home
	AllowOverwrite bool   `json:"allow_overwrite"`
}

type treeManifest struct {
	Path   string `json:"path"`
	Size   int64  `json:"size_bytes"`
	Sha256 string `json:"sha256"`
}

type migrationTreeResult struct {
	Target     string         `json:"target"`
	Files      int            `json:"files"`
	Bytes      int64          `json:"bytes"`
	TreeSha256 string         `json:"tree_sha256"`
	Entries    []treeManifest `json:"entries"`
	Truncated  bool           `json:"truncated"`
}

// hashTreeDir walks a directory and produces the content manifest (shared
// by extract_tree and hash_tree).
func hashTreeDir(dir string) (*migrationTreeResult, error) {
	res := &migrationTreeResult{Target: dir, Entries: []treeManifest{}}
	var lines []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		if len(lines) >= maxManifestFiles {
			res.Truncated = true
			return fmt.Errorf("tree exceeds %d files — refusing to hash silently", maxManifestFiles)
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		sum, _, serr := sha256File(path)
		if serr != nil {
			return serr
		}
		res.Files++
		res.Bytes += info.Size()
		lines = append(lines, fmt.Sprintf("%s %d %s", filepath.ToSlash(rel), info.Size(), sum))
		if len(res.Entries) < 5000 {
			res.Entries = append(res.Entries, treeManifest{Path: filepath.ToSlash(rel), Size: info.Size(), Sha256: sum})
		}
		return nil
	})
	if err != nil && !res.Truncated {
		return nil, err
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		_, _ = h.Write([]byte(l + "\n"))
	}
	res.TreeSha256 = hex.EncodeToString(h.Sum(nil))
	return res, nil
}

// chownTreeToUserBestEffort hands a whole tree to the account user (dev
// rigs report the skip honestly, same contract as chownToUserBestEffort).
func chownTreeToUserBestEffort(root, username string) string {
	uid, gid, ok := lookupUser(username)
	if !ok || os.Geteuid() != 0 {
		return "skipped: not running as root / user lookup unavailable"
	}
	var fail string
	_ = filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return nil // best-effort: report the first failure, keep going
		}
		if err := os.Chown(path, uid, gid); err != nil && fail == "" {
			fail = err.Error()
		}
		return nil
	})
	if fail != "" {
		return "partial chown failure: " + fail
	}
	return "account-owned"
}

// migrationExtractTree extracts an artifact subtree into an account home
// and returns the content manifest the verify phase replays.
func (r *Registry) migrationExtractTree(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p migrationExtractTreeParams
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	path, err := r.resolveArtifact(p.Artifact)
	if err != nil {
		return nil, nil, err
	}
	if !prefixValid(p.Prefix) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid prefix"}
	}
	target, err := fsTarget(r.deps.HomeRoot, p.Username, p.TargetRel)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid target: " + err.Error()}
	}
	if entries, _ := os.ReadDir(target); len(entries) > 0 && !p.AllowOverwrite {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict,
			Message: "target is not empty — resume passes allow_overwrite=true (re-extraction is idempotent)"}
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "target create failed: " + err.Error()}
	}

	// Extract with --no-same-owner (artifact uids are never trusted) and
	// hand the tree to the account user afterwards.
	depth := len(strings.Split(strings.Trim(p.Prefix, "/"), "/"))
	argv := []string{"tar", "-xzf", path, "-C", target,
		"--strip-components", fmt.Sprint(depth), "--no-same-owner", p.Prefix}
	cmd := exec.Command(argv[0], argv[1:]...)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "extraction failed: " + firstLine(errBuf.String())}
	}
	ownership := chownTreeToUserBestEffort(target, p.Username)

	manifest, err := hashTreeDir(target)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "manifest hash failed: " + err.Error()}
	}
	entry := r.deps.WAL.NewEntry("migration.extract_tree", map[string]any{
		"artifact": p.Artifact, "prefix": p.Prefix, "username": p.Username, "target": p.TargetRel, "ownership": ownership,
	})
	_ = r.deps.WAL.Append(entry)
	return manifest, auditQueued(entry), nil
}

func prefixValid(prefix string) bool {
	if prefix == "" || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") {
		return false
	}
	parts := strings.Split(prefix, "/")
	if len(parts) < 3 {
		return false
	}
	for _, s := range parts {
		if !migrationNameRe.MatchString(s) {
			return false
		}
	}
	return true
}

func memberValid(m string) bool {
	if m == "" || strings.HasPrefix(m, "/") || strings.Contains(m, "..") {
		return false
	}
	for _, s := range strings.Split(m, "/") {
		if !migrationNameRe.MatchString(s) {
			return false
		}
	}
	return true
}

// migrationHashTree re-hashes an extracted tree (verify phase).
func (r *Registry) migrationHashTree(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username  string `json:"username"`
		TargetRel string `json:"target_rel"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	target, err := fsTarget(r.deps.HomeRoot, p.Username, p.TargetRel)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid target"}
	}
	res, err := hashTreeDir(target)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "hash failed: " + err.Error()}
	}
	return res, nil, nil
}

// ---- single-member extraction (zones, certs, cron) ------------------------------

type migrationExtractMemberResult struct {
	Member   string `json:"member"`
	Sha256   string `json:"sha256"`
	Size     int64  `json:"size_bytes"`
	Content  string `json:"content_b64,omitempty"`
	TooLarge bool   `json:"too_large,omitempty"`
}

// migrationExtractMember returns one member's content inline (zones,
// certs and crontabs are small; a 2 MiB cap keeps the signed channel lean).
func (r *Registry) migrationExtractMember(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Artifact string `json:"artifact"`
		Member   string `json:"member"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := r.resolveArtifact(p.Artifact)
	if err != nil {
		return nil, nil, err
	}
	if !memberValid(p.Member) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid member path"}
	}
	cmd := exec.Command("tar", "-xOzf", path, p.Member)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "member extraction failed: " + firstLine(err.Error())}
	}
	sum := sha256.Sum256(out)
	res := migrationExtractMemberResult{Member: p.Member, Size: int64(len(out)), Sha256: hex.EncodeToString(sum[:])}
	if len(out) <= inlineMemberMax {
		res.Content = base64.StdEncoding.EncodeToString(out)
	} else {
		res.TooLarge = true
	}
	return res, nil, nil
}

// ---- database import ------------------------------------------------------------

type migrationImportDBParams struct {
	Artifact   string `json:"artifact"`
	Member     string `json:"member"` // mysql/<db>.sql[.gz]
	DBName     string `json:"db_name"`
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	DBHost     string `json:"db_host"`
}

type migrationImportDBResult struct {
	DBName     string           `json:"db_name"`
	DumpSha256 string           `json:"dump_sha256"`
	DumpBytes  int64            `json:"dump_bytes"`
	Tables     map[string]int64 `json:"table_rows"`
	Log        string           `json:"log"`
}

// migrationImportDatabase extracts the dump to a temp file, provisions a
// FRESH database/user/grant (never imported credentials, spec §6), imports,
// and returns the dump checksum plus per-table row counts for the report.
func (r *Registry) migrationImportDatabase(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p migrationImportDBParams
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	path, err := r.resolveArtifact(p.Artifact)
	if err != nil {
		return nil, nil, err
	}
	if !memberValid(p.Member) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid member path"}
	}
	if !migrationDBRe.MatchString(p.DBName) || !migrationDBRe.MatchString(p.DBUser) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid database name or user"}
	}
	if len(p.DBPassword) < 8 || len(p.DBPassword) > 1024 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "db_password must be 8-1024 bytes"}
	}
	if p.DBHost == "" {
		p.DBHost = "localhost"
	}
	adapter, err := r.resolveDbAdapter("mariadb")
	if err != nil {
		return nil, nil, err
	}

	// 1. stream the dump to a temp file (decompressing .gz on the way).
	tmpDir, terr := os.MkdirTemp("", "nexuspanel-mig-")
	if terr != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "staging failed: " + terr.Error()}
	}
	defer os.RemoveAll(tmpDir)
	dumpPath := filepath.Join(tmpDir, "import.sql")
	tarCmd := exec.Command("tar", "-xOzf", path, p.Member)
	var dumpStream io.Reader
	if strings.HasSuffix(p.Member, ".gz") {
		tarReader, terr2 := tarCmd.StdoutPipe()
		if terr2 != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "pipe failed: " + terr2.Error()}
		}
		if err := tarCmd.Start(); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "dump extraction failed to start: " + err.Error()}
		}
		gzr, gerr := gzip.NewReader(tarReader)
		if gerr != nil {
			_ = tarCmd.Wait()
			return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "dump is not gzip: " + gerr.Error()}
		}
		defer gzr.Close()
		dumpStream = gzr
	} else {
		dumpStream, terr = tarCmd.StdoutPipe()
		if terr != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "pipe failed: " + terr.Error()}
		}
		if err := tarCmd.Start(); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "dump extraction failed to start: " + err.Error()}
		}
	}
	dumpHash := sha256.New()
	f, ferr := os.Create(dumpPath)
	if ferr != nil {
		_ = tarCmd.Wait()
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "dump staging failed: " + ferr.Error()}
	}
	dumpSize, cerr := io.Copy(io.MultiWriter(f, dumpHash), dumpStream)
	_ = f.Close()
	waitErr := tarCmd.Wait()
	if cerr != nil || waitErr != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "dump extraction failed"}
	}

	// 2. fresh database + user + grant.
	if err := adapter.CreateDatabase(p.DBName); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "create database failed: " + err.Error()}
	}
	if err := adapter.CreateUser(p.DBUser, p.DBPassword, p.DBHost); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "create user failed: " + err.Error()}
	}
	if err := adapter.Grant(p.DBUser, p.DBName, p.DBHost); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "grant failed: " + err.Error()}
	}

	// 3. import.
	log, ierr := adapter.ImportFile(p.DBName, dumpPath)
	if ierr != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "import failed: " + ierr.Error()}
	}

	// 4. row stats for the verification report.
	stats, serr := adapter.TableStats(p.DBName)
	if serr != nil {
		stats = map[string]int64{}
		log += "\n(row stats unavailable: " + serr.Error() + ")"
	}

	entry := r.deps.WAL.NewEntry("migration.import_database", map[string]any{
		"artifact": p.Artifact, "member": p.Member, "db_name": p.DBName, "db_user": p.DBUser,
	})
	_ = r.deps.WAL.Append(entry)
	return migrationImportDBResult{
		DBName:     p.DBName,
		DumpSha256: hex.EncodeToString(dumpHash.Sum(nil)),
		DumpBytes:  dumpSize,
		Tables:     stats,
		Log:        log,
	}, auditQueued(entry), nil
}
