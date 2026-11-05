package commands

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

// ftp.* tests (ADR-0011). openssl and db_load are injected as fake shell
// scripts so the tests never depend on host tooling: the fake openssl
// prints a deterministic $6$ hash, the fake db_load "builds" the DB by
// copying the source file to the target path.

func newFtpRegistry(t *testing.T) (*Registry, string) {
        t.Helper()
        binDir := t.TempDir()
        fakeOpenSSL := filepath.Join(binDir, "openssl")
        if err := os.WriteFile(fakeOpenSSL, []byte("#!/bin/sh\necho '$6$'$4'$fakehash'\n"), 0o755); err != nil {
                t.Fatal(err)
        }
        fakeDbLoad := filepath.Join(binDir, "db_load")
        if err := os.WriteFile(fakeDbLoad, []byte("#!/bin/sh\ncp \"$5\" \"$6\"\n"), 0o755); err != nil {
                t.Fatal(err)
        }
        cfgDir := t.TempDir()
        dbPath := filepath.Join(t.TempDir(), "vusers")
        r := NewRegistry(Deps{
                WAL:           newTestWAL(t),
                HomeRoot:      t.TempDir(),
                VhostRoot:     t.TempDir(),
                FtpConfigDir:  cfgDir,
                FtpUserDbPath: dbPath,
                OpensslBinary: fakeOpenSSL,
                DbLoadBinary:  fakeDbLoad,
        })
        return r, cfgDir
}

func ftpCreateReq(t *testing.T, owner, ftpUser, password, rootDir string, readOnly bool) json.RawMessage {
        t.Helper()
        return rawParams(t, map[string]any{
                "owner_username": owner, "ftp_username": ftpUser, "password": password,
                "root_dir": rootDir, "read_only": readOnly,
        })
}

func TestFtpCreateAccount(t *testing.T) {
        r, cfgDir := newFtpRegistry(t)
        home := mkHome(t, r, "alice")
        root := filepath.Join(home, "sites")
        if err := os.MkdirAll(root, 0o755); err != nil {
                t.Fatal(err)
        }

        res, hint, err := r.ftpCreateAccount("id", ftpCreateReq(t, "alice", "alice.web", "s3cretpass", "sites", false))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(ftpOpResult)
        if out.Status != "created" || out.ReadOnly || !out.Userdb.Rebuilt {
                t.Fatalf("unexpected result: %+v", out)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("create must queue a WAL audit entry")
        }

        cfg, err := os.ReadFile(filepath.Join(cfgDir, "alice.web"))
        if err != nil {
                t.Fatal(err)
        }
        s := string(cfg)
        if !strings.Contains(s, "local_root="+root) || !strings.Contains(s, "write_enable=yes") {
                t.Fatalf("config wrong: %q", s)
        }

        source, _ := r.ftpSourcePath()
        b, err := os.ReadFile(source + ".source")
        if err != nil {
                t.Fatal(err)
        }
        lines := strings.Split(strings.TrimSpace(string(b)), "\n")
        if len(lines) != 2 || lines[0] != "alice.web" || !strings.HasPrefix(lines[1], "$6$") {
                t.Fatalf("userdb source wrong: %q", lines)
        }
        if _, err := os.Stat(source); err != nil {
                t.Fatalf("db file must be built: %v", err)
        }
}

func TestFtpCreateReadOnlyAndValidation(t *testing.T) {
        r, cfgDir := newFtpRegistry(t)
        home := mkHome(t, r, "bob")
        if err := os.MkdirAll(filepath.Join(home, "www"), 0o755); err != nil {
                t.Fatal(err)
        }

        res, _, err := r.ftpCreateAccount("id", ftpCreateReq(t, "bob", "bob.readonly", "s3cretpass", "www", true))
        if err != nil {
                t.Fatal(err)
        }
        cfg, _ := os.ReadFile(filepath.Join(cfgDir, "bob.readonly"))
        if !strings.Contains(string(cfg), "write_enable=no") {
                t.Fatalf("read-only account must set write_enable=no: %q", cfg)
        }
        _ = res.(ftpOpResult)

        cases := []struct {
                name string
                raw  json.RawMessage
        }{
                {"bad ftp username", ftpCreateReq(t, "bob", "Not Valid", "s3cretpass", "www", false)},
                {"short password", ftpCreateReq(t, "bob", "bob.x", "short", "www", false)},
                {"missing root dir", ftpCreateReq(t, "bob", "bob.x", "s3cretpass", "nope/deep", false)},
                {"root escapes home", ftpCreateReq(t, "bob", "bob.x", "s3cretpass", "../../etc", false)},
                {"invalid owner", ftpCreateReq(t, "root", "bob.x", "s3cretpass", "www", false)},
        }
        for _, c := range cases {
                if _, _, err := r.ftpCreateAccount("id", c.raw); err == nil {
                        t.Fatalf("%s: must be rejected", c.name)
                }
        }

        // duplicate login → conflict
        if _, _, err := r.ftpCreateAccount("id", ftpCreateReq(t, "bob", "bob.readonly", "s3cretpass", "www", false)); err == nil {
                t.Fatal("duplicate ftp login must conflict")
        }
}

func TestFtpMissingOpensslIsPrecondition(t *testing.T) {
        r := NewRegistry(Deps{
                WAL: newTestWAL(t), HomeRoot: t.TempDir(), VhostRoot: t.TempDir(),
                FtpConfigDir: t.TempDir(), FtpUserDbPath: filepath.Join(t.TempDir(), "vusers"),
                OpensslBinary: filepath.Join(t.TempDir(), "definitely-missing-openssl"),
        })
        home := mkHome(t, r, "carol")
        if err := os.MkdirAll(home, 0o755); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.ftpCreateAccount("id", ftpCreateReq(t, "carol", "carol.ftp", "s3cretpass", ".", false)); err == nil {
                t.Fatal("missing openssl must fail loudly — a login that cannot hash cannot exist")
        }
}

func TestFtpMissingDbLoadIsHonestSkipped(t *testing.T) {
        r := NewRegistry(Deps{
                WAL: newTestWAL(t), HomeRoot: t.TempDir(), VhostRoot: t.TempDir(),
                FtpConfigDir: t.TempDir(), FtpUserDbPath: filepath.Join(t.TempDir(), "vusers"),
                OpensslBinary: mustFakeOpenSSL(t),
                // DbLoadBinary unset and not on PATH in test environments → skipped
        })
        home := mkHome(t, r, "dave")
        if err := os.MkdirAll(home, 0o755); err != nil {
                t.Fatal(err)
        }
        res, _, err := r.ftpCreateAccount("id", ftpCreateReq(t, "dave", "dave.ftp", "s3cretpass", ".", false))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(ftpOpResult)
        if out.Userdb.Rebuilt || out.Userdb.Skipped == "" {
                t.Fatalf("missing db_load must be reported honestly, got %+v", out.Userdb)
        }
}

func TestFtpSetPasswordAndDelete(t *testing.T) {
        r, cfgDir := newFtpRegistry(t)
        home := mkHome(t, r, "erin")
        if err := os.MkdirAll(home, 0o755); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.ftpCreateAccount("id", ftpCreateReq(t, "erin", "erin.ftp", "firstpass1", ".", false)); err != nil {
                t.Fatal(err)
        }
        _, entries := r.ftpSourcePath()
        oldHash := entries["erin.ftp"]

        if _, _, err := r.ftpSetPassword("id", rawParams(t, map[string]any{"ftp_username": "erin.ftp", "password": "secondpass2"})); err != nil {
                t.Fatal(err)
        }
        _, entries = r.ftpSourcePath()
        if entries["erin.ftp"] == oldHash {
                t.Fatal("password rotation must change the stored hash")
        }
        if _, _, err := r.ftpSetPassword("id", rawParams(t, map[string]any{"ftp_username": "ghost", "password": "secondpass2"})); err == nil {
                t.Fatal("set_password on an unknown login must be a precondition error")
        }

        res, _, err := r.ftpDeleteAccount("id", rawParams(t, map[string]any{"ftp_username": "erin.ftp"}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(ftpOpResult).Status != "removed" {
                t.Fatalf("want removed, got %+v", res)
        }
        if _, err := os.Stat(filepath.Join(cfgDir, "erin.ftp")); !os.IsNotExist(err) {
                t.Fatalf("config must be removed: %v", err)
        }
        if _, entries := r.ftpSourcePath(); len(entries) != 0 {
                t.Fatalf("userdb entry must be gone: %v", entries)
        }

        res, _, err = r.ftpDeleteAccount("id", rawParams(t, map[string]any{"ftp_username": "erin.ftp"}))
        if err != nil || res.(ftpOpResult).Status != "absent" {
                t.Fatalf("deleting an absent login must answer absent, got %v / %v", res, err)
        }
}

func TestFtpListAccounts(t *testing.T) {
        r, cfgDir := newFtpRegistry(t)
        home := mkHome(t, r, "frank")
        if err := os.MkdirAll(home, 0o755); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.ftpCreateAccount("id", ftpCreateReq(t, "frank", "frank.aaa", "s3cretpass", ".", false)); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.ftpCreateAccount("id", ftpCreateReq(t, "frank", "frank.bbb", "s3cretpass", ".", true)); err != nil {
                t.Fatal(err)
        }
        // a stray staging file must not appear as an account
        if err := os.WriteFile(filepath.Join(cfgDir, "junk.nexus-staging"), []byte("x"), 0o644); err != nil {
                t.Fatal(err)
        }

        res, _, err := r.ftpListAccounts("id", rawParams(t, map[string]any{}))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(ftpListResult)
        if len(out.Accounts) != 2 {
                t.Fatalf("want 2 accounts, got %+v", out.Accounts)
        }
        if out.Accounts[0].Username != "frank.aaa" || out.Accounts[1].Username != "frank.bbb" {
                t.Fatalf("accounts must be name-sorted: %+v", out.Accounts)
        }
        if !out.Accounts[1].ReadOnly || out.Accounts[0].ReadOnly {
                t.Fatalf("read_only flags wrong: %+v", out.Accounts)
        }
}

func mustFakeOpenSSL(t *testing.T) string {
        t.Helper()
        p := filepath.Join(t.TempDir(), "openssl")
        script := fmt.Sprintf("#!/bin/sh\necho '$6$fakesalt$%s'\n", "fakehash")
        if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
                t.Fatal(err)
        }
        return p
}
