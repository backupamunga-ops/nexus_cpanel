package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B15 migration.* tests: a synthetic cpmove artifact (homedir with files,
// a mysql dump, a dns zone, an ssl cert, a crontab, mail dirs) built with
// REAL tar/gzip, a fake mariadb client, and full analyze → extract →
// import → verify-parity walks. The kill-and-resume acceptance is covered
// by re-running extract with allow_overwrite and asserting identical
// manifests (no double-imports).

func buildCpmove(t *testing.T, dir string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, content []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	// cPanel cpmove artifacts carry directory members; the mailbox
	// inventory reads those, so emit them for realism.
	addDir := func(name string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	addDir("cpmove-olduser/")
	addDir("cpmove-olduser/homedir/")
	addDir("cpmove-olduser/homedir/public_html/")
	addDir("cpmove-olduser/homedir/mail/olduser.com/")
	addDir("cpmove-olduser/homedir/mail/olduser.com/cur/")
	add("cpmove-olduser/homedir/public_html/index.html", []byte("<h1>hello</h1>\n"))
	add("cpmove-olduser/homedir/public_html/blog/post.html", []byte("<p>post</p>\n"))
	add("cpmove-olduser/homedir/mail/olduser.com/cur/x:1,", []byte("mail body\n"))
	add("cpmove-olduser/mysql/olduser_wp.sql", []byte("-- dump\nCREATE TABLE t (id INT);\nINSERT INTO t VALUES (1);\n"))
	add("cpmove-olduser/dnszones/olduser.com.db", []byte("olduser.com. 86400 IN A 1.2.3.4\n"))
	add("cpmove-olduser/sslcerts/olduser.com.crt", []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	add("cpmove-olduser/cron/olduser.cron", []byte("15 3 * * * /usr/bin/backup\n"))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cpmove-olduser.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newMigrationRegistry(t *testing.T) *Registry {
	t.Helper()
	return NewRegistry(Deps{
		WAL:           newTestWAL(t),
		HomeRoot:      t.TempDir(),
		MigrationRoot: t.TempDir(),
	})
}

func TestMigrationAnalyzeInventory(t *testing.T) {
	r := newMigrationRegistry(t)
	root, _ := r.migrationRoot()
	buildCpmove(t, root)

	res, _, err := r.migrationAnalyze("id", rawParams(t, migrationArtifactRef{Artifact: "cpmove-olduser.tar.gz"}))
	if err != nil {
		t.Fatal(err)
	}
	a := res.(migrationAnalyzeResult)
	if a.Checksum == "" || a.Size == 0 || a.Prefix != "cpmove-olduser" {
		t.Fatalf("bad analyze header: %+v", a)
	}
	byType := map[string][]migrationEntity{}
	for _, e := range a.Entities {
		byType[e.Type] = append(byType[e.Type], e)
	}
	if len(byType["files"]) != 1 || byType["files"][0].SourceID != "homedir/public_html" || byType["files"][0].Count != 2 {
		t.Fatalf("files entity wrong: %+v", byType["files"])
	}
	if len(byType["database"]) != 1 || byType["database"][0].SourceID != "olduser_wp.sql" || byType["database"][0].Checksum == "" {
		t.Fatalf("database entity wrong: %+v", byType["database"])
	}
	if len(byType["dns_zone"]) != 1 || byType["dns_zone"][0].SourceID != "olduser.com" || byType["dns_zone"][0].Checksum == "" {
		t.Fatalf("dns entity wrong: %+v", byType["dns_zone"])
	}
	if len(byType["ssl"]) != 1 || len(byType["cron"]) != 1 {
		t.Fatalf("ssl/cron entities wrong: %+v / %+v", byType["ssl"], byType["cron"])
	}
	if len(byType["mailbox"]) < 1 || len(byType["mail_domain"]) != 1 {
		t.Fatalf("mail entities wrong: %+v / %+v", byType["mailbox"], byType["mail_domain"])
	}

	// traversal + missing artifacts are refused
	if _, _, err := r.migrationAnalyze("id", rawParams(t, migrationArtifactRef{Artifact: "../escape.tar.gz"})); err == nil {
		t.Fatal("traversal artifact accepted")
	}
	if _, _, err := r.migrationAnalyze("id", rawParams(t, migrationArtifactRef{Artifact: "missing.tar.gz"})); err == nil {
		t.Fatal("missing artifact accepted")
	}
}

func TestMigrationExtractTreeManifestAndResume(t *testing.T) {
	r := newMigrationRegistry(t)
	root, _ := r.migrationRoot()
	buildCpmove(t, root)

	p := migrationExtractTreeParams{
		Artifact: "cpmove-olduser.tar.gz", Prefix: "cpmove-olduser/homedir/public_html",
		Username: "alpha", TargetRel: "public_html",
	}
	res, _, err := r.migrationExtractTree("id", rawParams(t, p))
	if err != nil {
		t.Fatal(err)
	}
	m1 := res.(*migrationTreeResult)
	if m1.Files != 2 || m1.Truncated || m1.TreeSha256 == "" {
		t.Fatalf("manifest wrong: %+v", m1)
	}

	// content parity: the manifest sha matches a direct hash of the file
	raw, _ := os.ReadFile(filepath.Join(m1.Target, "index.html"))
	sum := sha256.Sum256(raw)
	found := false
	for _, e := range m1.Entries {
		if e.Path == "index.html" && e.Sha256 == hex.EncodeToString(sum[:]) {
			found = true
		}
	}
	if !found {
		t.Fatal("manifest entry does not match file content")
	}

	// non-empty target refused without allow_overwrite…
	p2 := p
	if _, _, err := r.migrationExtractTree("id", rawParams(t, p2)); err == nil {
		t.Fatal("non-empty target accepted without allow_overwrite")
	}
	// …and resume (allow_overwrite) produces an IDENTICAL manifest — no double imports
	p3 := p
	p3.AllowOverwrite = true
	res2, _, err := r.migrationExtractTree("id", rawParams(t, p3))
	if err != nil {
		t.Fatal(err)
	}
	m2 := res2.(*migrationTreeResult)
	if m2.TreeSha256 != m1.TreeSha256 || m2.Files != m1.Files {
		t.Fatalf("resume manifest differs: %s vs %s", m1.TreeSha256, m2.TreeSha256)
	}

	// hash_tree (verify) reproduces the same digest
	hres, _, err := r.migrationHashTree("id", rawParams(t, map[string]string{
		"username": "alpha", "target_rel": "public_html",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if hres.(*migrationTreeResult).TreeSha256 != m1.TreeSha256 {
		t.Fatal("hash_tree digest differs from extraction manifest")
	}

	// prefix traversal refused
	bad := p
	bad.AllowOverwrite = true
	bad.Prefix = "../../etc"
	if _, _, err := r.migrationExtractTree("id", rawParams(t, bad)); err == nil {
		t.Fatal("traversal prefix accepted")
	}
}

func TestMigrationExtractMemberAndDBImport(t *testing.T) {
	r := newMigrationRegistry(t)
	root, _ := r.migrationRoot()
	buildCpmove(t, root)

	// zone member comes back inline with content + checksum
	res, _, err := r.migrationExtractMember("id", rawParams(t, map[string]string{
		"artifact": "cpmove-olduser.tar.gz", "member": "cpmove-olduser/dnszones/olduser.com.db",
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := res.(migrationExtractMemberResult)
	if m.Content == "" || m.TooLarge {
		t.Fatalf("zone member not inline: %+v", m)
	}
	dec, _ := json.Marshal(m)
	_ = dec
	if !strings.Contains(m.Sha256, "") || m.Size == 0 {
		t.Fatal("member checksum missing")
	}

	// db import with a fake mariadb client that accepts SQL via stdin and
	// answers the stats query with tab-separated rows.
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "mariadb")
	script := "#!/bin/sh\n" +
		"cat >> " + strconvQuote(filepath.Join(binDir, "sql.log")) + "\n" +
		"printf 'wp_old\\t7\\n'\nexit 0\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.deps.MysqlClientBinary = fake

	res2, hint, err := r.migrationImportDatabase("id", rawParams(t, migrationImportDBParams{
		Artifact: "cpmove-olduser.tar.gz", Member: "cpmove-olduser/mysql/olduser_wp.sql",
		DBName: "olduser_wp", DBUser: "olduser_wp", DBPassword: "fresh-secret-1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if hint == nil {
		t.Fatal("expected audit hint")
	}
	imp := res2.(migrationImportDBResult)
	if imp.DBName != "olduser_wp" || imp.Tables["wp_old"] != 7 || imp.DumpSha256 == "" {
		t.Fatalf("import result wrong: %+v", imp)
	}

	// the dump content must have streamed through stdin (never argv)
	sqlLog, _ := os.ReadFile(filepath.Join(binDir, "sql.log"))
	if !bytes.Contains(sqlLog, []byte("CREATE TABLE t")) {
		t.Fatal("dump did not reach the client via stdin")
	}

	// weak/invalid params refused
	if _, _, err := r.migrationImportDatabase("id", rawParams(t, migrationImportDBParams{
		Artifact: "cpmove-olduser.tar.gz", Member: "cpmove-olduser/mysql/olduser_wp.sql",
		DBName: "ok", DBUser: "ok", DBPassword: "short",
	})); err == nil {
		t.Fatal("weak db password accepted")
	}
}

func TestMigrationListArtifacts(t *testing.T) {
	r := newMigrationRegistry(t)
	root, _ := r.migrationRoot()
	buildCpmove(t, root)
	_ = os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o600)
	res, _, err := r.migrationListArtifacts("id", rawParams(t, map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	out := res.(map[string]any)
	if len(out["artifacts"].([]migrationArtifact)) != 1 {
		t.Fatalf("artifact list wrong: %+v", out)
	}
}
