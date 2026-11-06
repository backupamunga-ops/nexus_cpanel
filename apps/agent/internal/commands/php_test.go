package commands

import (
        "encoding/json"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

// php.* handler tests: version dirs under a temp PhpRoot stand in for
// installed PHP versions; pool rendering is validated byte-for-byte.

func newPhpRegistry(t *testing.T, installed ...string) *Registry {
        t.Helper()
        root := t.TempDir()
        for _, v := range installed {
                if err := os.MkdirAll(filepath.Join(root, v), 0o755); err != nil {
                        t.Fatal(err)
                }
        }
        return NewRegistry(Deps{
                WAL:             newTestWAL(t),
                HomeRoot:        t.TempDir(),
                VhostRoot:       t.TempDir(),
                CertRoot:        t.TempDir(),
                PhpRoot:         root,
                SystemctlBinary: "/bin/true", // fpm reload succeeds (tests may override)
        })
}

func TestPhpListVersions(t *testing.T) {
        r := newPhpRegistry(t, "8.1", "8.3", "9.9") // 9.9 must be ignored
        res, _, err := r.phpListVersions("id", nil)
        if err != nil {
                t.Fatal(err)
        }
        got := res.(listVersionsResult).Installed
        if len(got) != 2 || got[0] != "8.1" || got[1] != "8.3" {
                t.Fatalf("installed versions: %v", got)
        }
}

func TestPhpCreatePoolRendersAndEnforces(t *testing.T) {
        r := newPhpRegistry(t, "8.2")
        config := map[string]any{
                "pm":              "dynamic",
                "pm.max_children": 10,
                "memory_limit":    "128M",
        }
        res, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.2",
                Config: mustJSON(t, config),
        }))
        if err != nil {
                t.Fatal(err)
        }
        got := res.(poolResult)
        poolFile := filepath.Join(r.deps.PhpRoot, "8.2", "pools", "example.com.conf")
        if got.PoolFile != poolFile {
                t.Fatalf("pool file: %q", got.PoolFile)
        }
        onDisk, _ := os.ReadFile(poolFile)
        if string(onDisk) != got.ConfContent {
                t.Fatal("returned content must match the bytes on disk")
        }
        for _, want := range []string{
                "[example.com]", "user = alice", "listen = /run/php/php8.2-fpm-example.com.sock",
                "listen.owner = www-data", "listen.group = www-data", "listen.mode = 0660",
                "pm = dynamic", "pm.max_children = 10", "php_admin_value[memory_limit] = 128M",
        } {
                if !strings.Contains(string(onDisk), want) {
                        t.Fatalf("pool conf missing %q:\n%s", want, onDisk)
                }
        }
        if got.FpmReload != "reloaded" {
                t.Fatalf("fpm reload status: %q (%q)", got.FpmReload, got.FpmDetail)
        }

        // Duplicate create → conflict.
        if _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.2", Config: mustJSON(t, config),
        })); err == nil {
                t.Fatal("duplicate pool must conflict")
        }

        // Uninstalled version → precondition.
        if _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.4", Config: mustJSON(t, config),
        })); err == nil || !strings.Contains(err.Error(), "not installed") {
                t.Fatal("uninstalled version must be a precondition")
        }

        // Unknown config keys are a protocol violation, not a guess.
        bad := map[string]any{"pm": "dynamic", "hacker_key": true}
        if _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.2", Config: mustJSON(t, bad),
        })); err == nil {
                t.Fatal("unknown config keys must be rejected")
        }

        // Out-of-range values rejected.
        badRange := map[string]any{"pm.max_children": 1000}
        if _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.2", Config: mustJSON(t, badRange),
        })); err == nil {
                t.Fatal("out-of-range pm.max_children must be rejected")
        }
        badSize := map[string]any{"memory_limit": "999999G"}
        if _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.2", Config: mustJSON(t, badSize),
        })); err == nil {
                t.Fatal("malformed memory_limit must be rejected")
        }
}

func TestPhpCreatePoolAcceptsDistroPhp85(t *testing.T) {
        // Ubuntu 26.04 ships PHP 8.5 in the distro archive (ondrej/php has no
        // resolute dist) — 8.5 must be a first-class version.
        r := newPhpRegistry(t, "8.5")
        res, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.5",
                Config: mustJSON(t, map[string]any{"pm": "dynamic"}),
        }))
        if err != nil {
                t.Fatal(err)
        }
        if got := res.(poolResult); got.FpmReload != "reloaded" || got.Version != "8.5" {
                t.Fatalf("8.5 pool: %+v", got)
        }
        onDisk, _ := os.ReadFile(filepath.Join(r.deps.PhpRoot, "8.5", "pools", "example.com.conf"))
        if !strings.Contains(string(onDisk), "listen = /run/php/php8.5-fpm-example.com.sock") {
                t.Fatalf("8.5 pool socket wrong:\n%s", onDisk)
        }
        // 8.6 stays outside the allowlist.
        if _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "other.com", Version: "8.6",
                Config: mustJSON(t, map[string]any{}),
        })); err == nil || !strings.Contains(err.Error(), "8.1..8.5") {
                t.Fatal("8.6 must be rejected as out of range")
        }
}

func TestPhpCreatePoolRollsBackWhenFpmReloadFails(t *testing.T) {
        // The nginx health-gate pattern: a pool whose fpm refuses to load is
        // rolled back, not left half-applied.
        r := newPhpRegistry(t, "8.2")
        r.deps.SystemctlBinary = "/bin/false"
        _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.2",
                Config: mustJSON(t, map[string]any{"pm": "dynamic"}),
        }))
        if err == nil || !strings.Contains(err.Error(), "rolled back") {
                t.Fatalf("failed reload must roll the pool back: %v", err)
        }
        if _, statErr := os.Stat(filepath.Join(r.deps.PhpRoot, "8.2", "pools", "example.com.conf")); !os.IsNotExist(statErr) {
                t.Fatal("pool file must be gone after the rollback")
        }

        // Delete rolls the file back the same way.
        r2 := newPhpRegistry(t, "8.2")
        r2.deps.SystemctlBinary = "/bin/false"
        poolFile := filepath.Join(r2.deps.PhpRoot, "8.2", "pools", "example.com.conf")
        if err := os.MkdirAll(filepath.Dir(poolFile), 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(poolFile, []byte("[example.com]\n"), 0o644); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r2.phpDeletePool("id", rawParams(t, map[string]any{
                "username": "alice", "domain": "example.com", "version": "8.2",
        })); err == nil || !strings.Contains(err.Error(), "rolled back") {
                t.Fatalf("failed delete reload must roll back: %v", err)
        }
        if onDisk, statErr := os.ReadFile(poolFile); statErr != nil || string(onDisk) != "[example.com]\n" {
                t.Fatal("deleted pool file must be restored byte-for-byte")
        }
}

func TestPhpModifyAndDeletePool(t *testing.T) {
        r := newPhpRegistry(t, "8.3")
        base := map[string]any{"pm": "dynamic", "pm.max_children": 5}

        // Modify before create → precondition.
        if _, _, err := r.phpModifyPool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.3", Config: mustJSON(t, base),
        })); err == nil || !strings.Contains(err.Error(), "does not exist") {
                t.Fatal("modify of a missing pool must be a precondition")
        }

        if _, _, err := r.phpCreatePool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.3", Config: mustJSON(t, base),
        })); err != nil {
                t.Fatal(err)
        }

        base["pm.max_children"] = 20
        if _, _, err := r.phpModifyPool("id", rawParams(t, createPoolParams{
                Username: "alice", Domain: "example.com", Version: "8.3", Config: mustJSON(t, base),
        })); err != nil {
                t.Fatal(err)
        }
        onDisk, _ := os.ReadFile(filepath.Join(r.deps.PhpRoot, "8.3", "pools", "example.com.conf"))
        if !strings.Contains(string(onDisk), "pm.max_children = 20") {
                t.Fatalf("modify not applied:\n%s", onDisk)
        }

        res, _, err := r.phpDeletePool("id", rawParams(t, map[string]any{
                "username": "alice", "domain": "example.com", "version": "8.3",
        }))
        if err != nil {
                t.Fatal(err)
        }
        if res.(poolResult).Status != "removed" {
                t.Fatalf("delete result: %+v", res)
        }
        if _, err := os.Stat(filepath.Join(r.deps.PhpRoot, "8.3", "pools", "example.com.conf")); !os.IsNotExist(err) {
                t.Fatal("pool file must be gone")
        }

        // Idempotent delete.
        if _, _, err := r.phpDeletePool("id", rawParams(t, map[string]any{
                "username": "alice", "domain": "example.com", "version": "8.3",
        })); err != nil {
                t.Fatalf("idempotent delete: %v", err)
        }
}

func mustJSON(t *testing.T, v any) json.RawMessage {
        t.Helper()
        b, err := json.Marshal(v)
        if err != nil {
                t.Fatal(err)
        }
        return b
}
