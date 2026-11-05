package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// backup.* tests (§4.14, B10). Every external binary is a fake shell script
// (age, sftp, rclone, mariadb-dump) so the suite needs nothing installed.
// The C15 property is exercised three ways: a real-age round trip that skips
// when age is absent, a loud precondition when the identity is missing, and
// a failing-decrypt fake standing in for a wrong master key.

const fakeAgeOK = `#!/bin/sh
# passthrough "encryption": copies -o OUT <- SRC
out=""
src=""
prev=""
for a in "$@"; do
  case "$prev" in
    -o) out="$a" ;;
  esac
  case "$a" in
    -o|-r|-d|-i) prev="$a" ;;
    *) if [ "$prev" != "-r" ] && [ "$prev" != "-i" ]; then src="$a"; fi; prev="" ;;
  esac
done
cp "$src" "$out"
exit 0
`

const fakeAgeWrongKey = `#!/bin/sh
echo "age: error: decryption failed — wrong key" >&2
exit 1
`

// fakeSftp implements put/get/rm batch lines against a base dir (the last
// argv word user@host:/abs/base). The argv line is logged for the
// "secrets never in argv" assertion.
func fakeSftp(logFile string) string {
	return `#!/bin/sh
echo "ARGV: $*" >> "` + logFile + `"
target=""
for a in "$@"; do target="$a"; done
remote="${target#*@}"
case "$remote" in
  *:*) base="${remote#*:}" ;;
  *)   base="" ;;
esac
# the real sftp batch parser strips surrounding single quotes; mirror it
unq() { q="${1#\'}"; echo "${q%\'}"; }
while read -r op src dst; do
  [ -z "$op" ] && continue
  src="$(unq "$src")"; dst="$(unq "$dst")"
  case "$op" in
    put) mkdir -p "$(dirname "$dst")" && cp "$src" "$dst" || exit 1 ;;
    get) mkdir -p "$(dirname "$dst")" && cp "$src" "$dst" || exit 1 ;;
    rm)  rm -f "$src" || exit 1 ;;
  esac
done
exit 0
`
}

// fakeRclone implements copyto/deletefile for the nexuspanel-bk: remote and
// logs the RCLONE_CONFIG_* env block plus argv for the secret-discipline
// assertion. Remote objects materialize under storeRoot (baked into the
// script) so the test never writes into the package dir.
func fakeRclone(logFile, storeRoot string) string {
	return `#!/bin/sh
env | grep '^RCLONE_CONFIG' >> "` + logFile + `"
echo "ARGV: $*" >> "` + logFile + `"
case "$1" in
  copyto)
    src="$2"; dst="$3"
    case "$dst" in
      nexuspanelbk:*) p="${dst#nexuspanelbk:}"; mkdir -p "$(dirname "` + storeRoot + `"/"$p")" && cp "$src" "` + storeRoot + `/$p" || exit 1 ;;
      nexuspanelbk-*:) exit 1 ;;
      *) p="${src#nexuspanelbk:}"; cp "` + storeRoot + `/$p" "$dst" || exit 1 ;;
    esac ;;
  deletefile)
    p="${2#nexuspanelbk:}"; rm -f "` + storeRoot + `/$p" || exit 1 ;;
esac
exit 0
`
}

type backupRig struct {
	r          *Registry
	home       string // /…/alice
	backupRoot string
	walDir     string
	binDir     string
}

func newBackupRig(t *testing.T) *backupRig {
	t.Helper()
	binDir := t.TempDir()
	walDir := t.TempDir()
	homeRoot := t.TempDir()
	backupRoot := t.TempDir()
	r := NewRegistry(Deps{
		WAL:          newTestWAL(t),
		HomeRoot:     homeRoot,
		VhostRoot:    t.TempDir(),
		BackupRoot:   backupRoot,
		AgeBinary:    filepath.Join(binDir, "age"),
		SftpBinary:   filepath.Join(binDir, "sftp"),
		RcloneBinary: filepath.Join(binDir, "rclone"),
	})
	home := filepath.Join(homeRoot, "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return &backupRig{r: r, home: home, backupRoot: backupRoot, walDir: walDir, binDir: binDir}
}

func (b *backupRig) installFake(t *testing.T, name, script string) string {
	t.Helper()
	p := filepath.Join(b.binDir, name)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func localDest(root string, recipients ...string) map[string]any {
	d := map[string]any{"type": "local", "root": root}
	if len(recipients) > 0 {
		d["age_recipients"] = recipients
	}
	return d
}

func backupCreateReq(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	return rawParams(t, m)
}

// mustCreate runs backup.create and returns the result.
func (b *backupRig) mustCreate(t *testing.T, params map[string]any) backupCreateResult {
	t.Helper()
	res, hint, err := b.r.backupCreate("id", backupCreateReq(t, params))
	if err != nil {
		t.Fatalf("backup.create: %v", err)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("backup.create must queue a WAL audit entry")
	}
	return res.(backupCreateResult)
}

func TestBackupCreateLocalAndManifest(t *testing.T) {
	rig := newBackupRig(t)
	if err := os.WriteFile(filepath.Join(rig.home, "index.html"), []byte("<h1>hi</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": localDest(rig.backupRoot), "owner_username": "alice", "sources": []string{""},
	})
	if res.Status != "created" || res.Encrypted {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.HasPrefix(res.Artifact, "nexuspanel-account-") || !strings.HasSuffix(res.Artifact, ".tar.gz") {
		t.Fatalf("artifact naming wrong: %s", res.Artifact)
	}
	// Manifest must sit next to the artifact and carry the inner checksum.
	manifestRaw, err := os.ReadFile(filepath.Join(rig.backupRoot, res.Artifact+".manifest.json"))
	if err != nil {
		t.Fatalf("manifest must be uploaded next to the artifact: %v", err)
	}
	var m backupManifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "nexuspanel-backup/v1" || m.Encrypted || m.Scope != "account" || m.Owner != "alice" {
		t.Fatalf("manifest fields wrong: %+v", m)
	}
	// The recorded checksum is over the final artifact bytes.
	artifactSum, _, err := sha256File(filepath.Join(rig.backupRoot, res.Artifact))
	if err != nil {
		t.Fatal(err)
	}
	if artifactSum != res.ChecksumSha256 {
		t.Fatalf("checksum mismatch: manifest %s vs artifact %s", res.ChecksumSha256, artifactSum)
	}
}

func TestBackupCreateDatabaseScope(t *testing.T) {
	rig := newBackupRig(t)
	rig.installFake(t, "mariadb-dump", "#!/bin/sh\necho '-- fake dump for' \"$1\"\n")
	rig.r.deps.MysqlDumpBinary = filepath.Join(rig.binDir, "mariadb-dump")
	rig.installFake(t, "mariadb", "#!/bin/sh\ncat >/dev/null\nexit 0\n")
	rig.r.deps.MysqlClientBinary = filepath.Join(rig.binDir, "mariadb")

	res := rig.mustCreate(t, map[string]any{
		"scope": "database", "scope_id": "01900000-0000-7000-8000-00000000d001",
		"destination": localDest(rig.backupRoot), "owner_username": "alice",
		"database": map[string]any{"engine": "mariadb", "name": "app_production"},
	})
	manifestRaw, err := os.ReadFile(filepath.Join(rig.backupRoot, res.Artifact+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m backupManifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Database != "app_production" {
		t.Fatalf("manifest must name the database: %+v", m)
	}
	// The dump content must be inside the tar.
	f, err := os.Open(filepath.Join(rig.backupRoot, res.Artifact))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name == "app_production.sql" {
			buf := new(bytes.Buffer)
			if _, err := buf.ReadFrom(tr); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), "fake dump for app_production") {
				t.Fatal("dump content wrong inside artifact")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("artifact must contain the sql dump")
	}
}

func TestBackupEncryptedRoundTripAndC15Negatives(t *testing.T) {
	rig := newBackupRig(t)
	rig.installFake(t, "age", fakeAgeOK)
	identity := filepath.Join(t.TempDir(), "age-identity.txt")
	if err := os.WriteFile(identity, []byte("AGE-SECRET-KEY-FAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rig.home, "secret.txt"), []byte("top"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": localDest(rig.backupRoot, "age1keyxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), "owner_username": "alice",
	})
	if !res.Encrypted || !strings.HasSuffix(res.Artifact, ".tar.gz.age") {
		t.Fatalf("encrypted artifact expected: %+v", res)
	}

	// C15 negative 1: no identity configured on the node → loud precondition.
	rig.r.deps.AgeIdentityPath = ""
	params := map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"owner_username": "alice", "dry_run": true,
	}
	_, _, err := rig.r.backupRestore("id", backupCreateReq(t, params))
	if err == nil || !strings.Contains(err.Error(), "age identity") {
		t.Fatalf("restore without identity must fail loudly (C15), got: %v", err)
	}

	// C15 negative 2: identity path configured but file missing → refused.
	rig.r.deps.AgeIdentityPath = filepath.Join(t.TempDir(), "absent.txt")
	_, _, err = rig.r.backupRestore("id", backupCreateReq(t, params))
	if err == nil || !strings.Contains(err.Error(), "C15") {
		t.Fatalf("restore with missing identity file must be refused, got: %v", err)
	}

	// Happy path: identity present → dry-run restore succeeds.
	rig.r.deps.AgeIdentityPath = identity
	res2, hint, err := rig.r.backupRestore("id", backupCreateReq(t, params))
	if err != nil {
		t.Fatalf("dry-run restore with identity: %v", err)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("restore is a mutation-class op and must queue a WAL entry")
	}
	out := res2.(backupRestoreResult)
	if out.Status != "dry_run_ok" || len(out.Extracted) == 0 {
		t.Fatalf("unexpected dry-run result: %+v", out)
	}

	// Real restore lands the file inside the account home.
	params["target_path"] = "restored-here"
	params["dry_run"] = false
	out2, _, err := rig.r.backupRestore("id", backupCreateReq(t, params))
	if err != nil {
		t.Fatal(err)
	}
	o := out2.(backupRestoreResult)
	if o.Status != "restored" {
		t.Fatalf("expected restored, got %+v", o)
	}
	data, err := os.ReadFile(filepath.Join(rig.home, "restored-here", "00-home", "secret.txt"))
	if err != nil || string(data) != "top" {
		t.Fatalf("restored file wrong: %v %q", err, data)
	}

	// Escape attempt: target outside the home is refused.
	params["target_path"] = "../escape"
	if _, _, err := rig.r.backupRestore("id", backupCreateReq(t, params)); err == nil {
		t.Fatal("target escape must be refused")
	}
}

func TestBackupRestoreWrongMasterKeyFails(t *testing.T) {
	rig := newBackupRig(t)
	rig.installFake(t, "age", fakeAgeOK)
	identity := filepath.Join(t.TempDir(), "age-identity.txt")
	if err := os.WriteFile(identity, []byte("AGE-SECRET-KEY-FAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.r.deps.AgeIdentityPath = identity
	res := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": localDest(rig.backupRoot, "age1key"), "owner_username": "alice",
	})

	// Swap in a "wrong key" age: decrypt fails like a real wrong identity.
	rig.installFake(t, "age", fakeAgeWrongKey)
	_, _, err := rig.r.backupRestore("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"owner_username": "alice", "dry_run": true,
	}))
	if err == nil || !strings.Contains(err.Error(), "age decrypt failed") {
		t.Fatalf("restore with a wrong master key must fail loudly, got: %v", err)
	}
	// verify() answers "failed" with the reason instead of erroring.
	vres, _, err := rig.r.backupVerify("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
	}))
	if err != nil {
		t.Fatal(err)
	}
	v := vres.(backupVerifyResult)
	if v.Status != "failed" || !strings.Contains(v.Reason, "age decrypt failed") {
		t.Fatalf("verify must report failure honestly: %+v", v)
	}
}

func TestBackupVerifyChecksumAndTamper(t *testing.T) {
	rig := newBackupRig(t)
	if err := os.WriteFile(filepath.Join(rig.home, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": localDest(rig.backupRoot), "owner_username": "alice",
	})

	// Good checksum → verified.
	vres, hint, err := rig.r.backupVerify("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
		"checksum": res.ChecksumSha256,
	}))
	if err != nil || hint == nil {
		t.Fatalf("verify: %v (hint %v)", err, hint)
	}
	if vres.(backupVerifyResult).Status != "verified" {
		t.Fatalf("expected verified: %+v", vres)
	}

	// Tampered checksum → failed with reason, no error.
	vres2, _, err := rig.r.backupVerify("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
		"checksum": strings.Repeat("0", 64),
	}))
	if err != nil {
		t.Fatal(err)
	}
	v2 := vres2.(backupVerifyResult)
	if v2.Status != "failed" || v2.Reason == "" {
		t.Fatalf("tamper must be a failed verify: %+v", v2)
	}

	// Bit-flip on disk → inner tar checksum mismatch.
	artifactPath := filepath.Join(rig.backupRoot, res.Artifact)
	data, _ := os.ReadFile(artifactPath)
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(artifactPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	vres3, _, err := rig.r.backupVerify("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if vres3.(backupVerifyResult).Status != "failed" {
		t.Fatalf("bit-flipped artifact must fail verify: %+v", vres3)
	}
}

func TestBackupPreviewListsEntries(t *testing.T) {
	rig := newBackupRig(t)
	if err := os.MkdirAll(filepath.Join(rig.home, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rig.home, "web", "a.php"), []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := rig.mustCreate(t, map[string]any{
		"scope": "site", "scope_id": "01900000-0000-7000-8000-000000005001",
		"destination": localDest(rig.backupRoot), "owner_username": "alice",
		"sources": []string{"web"},
	})
	pres, hint, err := rig.r.backupRestorePreview("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if hint != nil {
		t.Fatal("preview must NOT queue a WAL entry (inspection, not mutation)")
	}
	p := pres.(backupPreviewResult)
	if p.Manifest.Artifact != res.Artifact || !p.ChecksumMatch || len(p.Entries) == 0 {
		t.Fatalf("preview wrong: %+v", p)
	}
	found := false
	for _, e := range p.Entries {
		if strings.HasSuffix(e.Name, "a.php") {
			found = true
		}
	}
	if !found {
		t.Fatalf("preview entries must include the file: %+v", p.Entries)
	}
}

func TestBackupPurgeProtectsNewerArtifacts(t *testing.T) {
	rig := newBackupRig(t)
	old := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": localDest(rig.backupRoot), "owner_username": "alice",
	})
	// A future-dated manifest protects its (absent) artifact even though
	// the control plane listed it for deletion.
	future := "nexuspanel-account-29990101T000000Z-deadbeef.tar.gz"
	futureManifest := `{"format":"nexuspanel-backup/v1","created_at":"2999-01-01T00:00:00Z","scope":"account","entries":1,"size_bytes":1,"checksum_sha256_tar_gz":"x","encrypted":false,"artifact":"` + future + `","panel":"nexuspanel-agent"}`
	if err := os.WriteFile(filepath.Join(rig.backupRoot, future+".manifest.json"), []byte(futureManifest), 0o600); err != nil {
		t.Fatal(err)
	}

	pres, hint, err := rig.r.backupPurge("id", backupCreateReq(t, map[string]any{
		"destination": localDest(rig.backupRoot),
		"before_date": "2100-01-01T00:00:00Z",
		"delete":      []string{old.Artifact, future},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if hint == nil {
		t.Fatal("a deleting purge must queue a WAL entry")
	}
	p := pres.(backupPurgeResult)
	if len(p.Deleted) != 1 || p.Deleted[0] != old.Artifact {
		t.Fatalf("old artifact must be deleted: %+v", p)
	}
	if len(p.Protected) != 1 || p.Protected[0] != future {
		t.Fatalf("future-dated artifact must be protected: %+v", p)
	}
	if _, err := os.Stat(filepath.Join(rig.backupRoot, old.Artifact)); !os.IsNotExist(err) {
		t.Fatal("deleted artifact must be gone from the destination")
	}
}

func TestBackupTestDestinationRoundTrip(t *testing.T) {
	rig := newBackupRig(t)
	res, hint, err := rig.r.backupTestDestination("id", backupCreateReq(t, map[string]any{
		"destination": localDest(rig.backupRoot),
	}))
	if err != nil || hint == nil {
		t.Fatalf("test destination: %v (hint %v)", err, hint)
	}
	if res.(backupTestDestinationResult).Status != "ok" {
		t.Fatalf("expected ok: %+v", res)
	}
}

func TestBackupSftpTransportAndSecretDiscipline(t *testing.T) {
	rig := newBackupRig(t)
	logFile := filepath.Join(t.TempDir(), "sftp.log")
	rig.installFake(t, "sftp", fakeSftp(logFile))
	sftpRoot := filepath.Join(t.TempDir(), "sftpbase") // absolute base dir the fake uses as fs path
	if err := os.MkdirAll(sftpRoot, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(rig.home, "f.txt"), []byte("sftp-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": map[string]any{
			"type": "sftp", "host": "bk.example.net", "username": "bkuser",
			"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----",
			"base_dir":    sftpRoot,
		},
		"owner_username": "alice",
	})
	if res.Status != "created" {
		t.Fatalf("sftp create failed: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(sftpRoot, res.Artifact)); err != nil {
		t.Fatalf("artifact must land at the sftp base dir: %v", err)
	}

	log, _ := os.ReadFile(logFile)
	// The private key rides env/temp files — never argv, never the log.
	if strings.Contains(string(log), "fakekey") {
		t.Fatal("private key leaked into sftp argv log")
	}
	if !strings.Contains(string(log), "ARGV:") {
		t.Fatal("sftp fake did not log argv")
	}
}

func TestBackupS3TransportEnvNotArgv(t *testing.T) {
	rig := newBackupRig(t)
	logFile := filepath.Join(t.TempDir(), "rclone.log")
	storeRoot := t.TempDir()
	rig.installFake(t, "rclone", fakeRclone(logFile, storeRoot))

	if err := os.WriteFile(filepath.Join(rig.home, "f.txt"), []byte("s3-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": map[string]any{
			"type": "s3", "bucket": "nexus-backups", "prefix": "alpha",
			"access_key_id": "AKIAFAKE", "secret_access_key": "s3cr3t-key",
			"endpoint": "https://s3.example.net", "region": "us-east-1",
		},
		"owner_username": "alice",
	})
	if res.Status != "created" {
		t.Fatalf("s3 create failed: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(storeRoot, "nexus-backups", "alpha", res.Artifact)); err != nil {
		t.Fatalf("artifact must land under bucket/prefix at the store root: %v", err)
	}
	// What matters most is the secret discipline:
	log, _ := os.ReadFile(logFile)
	if !strings.Contains(string(log), "RCLONE_CONFIG_NEXUSPANELBK_SECRET_ACCESS_KEY=s3cr3t-key") {
		t.Fatal("secret must ride the child env (rclone env config)")
	}
	for _, line := range strings.Split(string(log), "\n") {
		if strings.HasPrefix(line, "ARGV:") && strings.Contains(line, "s3cr3t-key") {
			t.Fatal("secret leaked into rclone argv")
		}
	}
}

func TestBackupAbsentBinariesAreLoud(t *testing.T) {
	rig := newBackupRig(t)
	// No age binary injected: encrypted create must be a loud precondition.
	if err := os.WriteFile(filepath.Join(rig.home, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rig.r.deps.AgeBinary = ""
	if _, err := exec.LookPath("age"); err != nil {
		_, _, err := rig.r.backupCreate("id", backupCreateReq(t, map[string]any{
			"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
			"destination": localDest(rig.backupRoot, "age1key"), "owner_username": "alice",
		}))
		if err == nil || !strings.Contains(err.Error(), "age binary not found") {
			t.Fatalf("absent age must be loud: %v", err)
		}
	}
	// s3 without rclone → loud precondition.
	rig.r.deps.RcloneBinary = ""
	_, _, err := rig.r.backupTestDestination("id", backupCreateReq(t, map[string]any{
		"destination": map[string]any{"type": "s3", "bucket": "b", "access_key_id": "a", "secret_access_key": "s"},
	}))
	if err == nil || !strings.Contains(err.Error(), "rclone") {
		t.Fatalf("absent rclone must be loud: %v", err)
	}
	// sftp without a client → loud precondition.
	rig.r.deps.SftpBinary = ""
	if _, err := exec.LookPath("sftp"); err != nil {
		_, _, err := rig.r.backupTestDestination("id", backupCreateReq(t, map[string]any{
			"destination": map[string]any{"type": "sftp", "host": "h", "username": "u", "private_key": "k"},
		}))
		if err == nil || !strings.Contains(err.Error(), "sftp") {
			t.Fatalf("absent sftp must be loud: %v", err)
		}
	}
}

func TestBackupValidationRejectsBeforeAnyIO(t *testing.T) {
	rig := newBackupRig(t)
	good := map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": localDest(rig.backupRoot), "owner_username": "alice",
	}
	// bad scope
	bad := cloneMap(good)
	bad["scope"] = "galaxy"
	if _, _, err := rig.r.backupCreate("id", backupCreateReq(t, bad)); err == nil {
		t.Fatal("bad scope must be rejected")
	}
	// account scope without owner
	bad2 := cloneMap(good)
	delete(bad2, "owner_username")
	if _, _, err := rig.r.backupCreate("id", backupCreateReq(t, bad2)); err == nil {
		t.Fatal("account scope without owner must be rejected")
	}
	// source escape
	bad3 := cloneMap(good)
	bad3["sources"] = []string{"../../etc"}
	if _, _, err := rig.r.backupCreate("id", backupCreateReq(t, bad3)); err == nil {
		t.Fatal("source escape must be rejected")
	}
	// destination root outside the backup root
	bad4 := cloneMap(good)
	bad4["destination"] = localDest("/etc/evil")
	if _, _, err := rig.r.backupCreate("id", backupCreateReq(t, bad4)); err == nil {
		t.Fatal("destination root outside the backup root must be rejected")
	}
	// no destination type
	bad5 := cloneMap(good)
	bad5["destination"] = map[string]any{}
	if _, _, err := rig.r.backupCreate("id", backupCreateReq(t, bad5)); err == nil {
		t.Fatal("missing destination type must be rejected")
	}
}

func cloneMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TestBackupAgeRealRoundTrip runs a REAL age encrypt/decrypt cycle when the
// age binary is installed on the build host; otherwise it skips honestly.
// This is the true-C15 proof: an artifact encrypted with a real recipient
// key cannot be restored without the matching identity file.
func TestBackupAgeRealRoundTrip(t *testing.T) {
	agePath, err := exec.LookPath("age")
	if err != nil {
		t.Skip("age not installed on this host — fake-binary C15 coverage runs instead")
	}
	keygen, err := exec.LookPath("age-keygen")
	if err != nil {
		t.Skip("age-keygen not installed on this host")
	}
	rig := newBackupRig(t)
	rig.r.deps.AgeBinary = agePath

	idFile := filepath.Join(t.TempDir(), "identity.txt")
	out, err := exec.Command(keygen, "-o", idFile).CombinedOutput()
	if err != nil {
		t.Fatalf("age-keygen: %v (%s)", err, out)
	}
	pubBytes, err := os.ReadFile(idFile + ".pub")
	if err != nil {
		// age-keygen prints the public key as a comment; extract it.
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "# public key: ") {
				pubBytes = []byte(strings.TrimSpace(strings.TrimPrefix(l, "# public key: ")))
			}
		}
	}
	if len(pubBytes) == 0 {
		t.Skip("could not derive an age recipient key")
	}
	if err := os.WriteFile(filepath.Join(rig.home, "real.txt"), []byte("real-age"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.r.deps.AgeIdentityPath = idFile
	res := rig.mustCreate(t, map[string]any{
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"destination": localDest(rig.backupRoot, string(pubBytes)), "owner_username": "alice",
	})
	if !res.Encrypted {
		t.Fatal("real age run must encrypt")
	}
	// Restore without the identity must fail (C15), with it must succeed.
	rig.r.deps.AgeIdentityPath = ""
	if _, _, err := rig.r.backupRestore("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"owner_username": "alice", "dry_run": true,
	})); err == nil {
		t.Fatal("real-age restore without identity must fail (C15)")
	}
	rig.r.deps.AgeIdentityPath = idFile
	out2, _, err := rig.r.backupRestore("id", backupCreateReq(t, map[string]any{
		"artifact_path": res.Artifact, "destination": localDest(rig.backupRoot),
		"scope": "account", "scope_id": "01900000-0000-7000-8000-00000000a001",
		"owner_username": "alice", "dry_run": true,
	}))
	if err != nil {
		t.Fatalf("real-age dry-run restore failed: %v", err)
	}
	if len(out2.(backupRestoreResult).Extracted) == 0 {
		t.Fatal("real-age restore must extract entries")
	}
}
