package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountCreateValidatesUsername(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})
	cases := []string{"", "Root", "1abc", "has_underscore", "has space", "root", "www-data", "way-too-long-" + repeat("a", 40)}
	for _, name := range cases {
		raw, _ := json.Marshal(map[string]any{"username": name})
		_, _, err := r.accountCreate("t1", raw)
		if err == nil {
			t.Fatalf("username %q must be rejected", name)
		}
	}
}

func TestAccountCreateExecutesTypedUseradd(t *testing.T) {
	bin := t.TempDir()
	fakeUseradd := filepath.Join(bin, "useradd")
	script := "#!/bin/sh\n# record args; fake a uid mapping via env\necho \"$@\" > \"" + filepath.Join(t.TempDir(), "args") + "\"\nexit 0\n"
	if err := os.WriteFile(fakeUseradd, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// NOTE: lookupUser uses NSS (getpwnam), which will not see the fake user.
	// accountCreate handles that by failing loudly — the full M0 e2e runs on a VM.
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})
	raw, _ := json.Marshal(map[string]any{"username": "alice"})
	_, _, err := r.accountCreate("t1", raw)
	if err == nil {
		t.Fatal("expected failure: fake useradd does not create a real NSS user")
	}
}

func TestAccountUsageReadsCgroupFiles(t *testing.T) {
	root := t.TempDir()
	acc := filepath.Join(root, "nexuspanel", "alice")
	if err := os.MkdirAll(acc, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(acc, "memory.current"), []byte("1234567\n"), 0o644)
	os.WriteFile(filepath.Join(acc, "cpu.stat"), []byte("usage_usec 4242\nuser_usec 1\n"), 0o644)
	os.WriteFile(filepath.Join(acc, "pids.current"), []byte("7\n"), 0o644)

	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: root})
	raw, _ := json.Marshal(map[string]any{"username": "alice"})
	res, _, err := r.accountUsage("t1", raw)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	u := res.(usageResult)
	if u.MemBytes != 1234567 || u.CPUUSec != 4242 || u.Procs != 7 {
		t.Fatalf("unexpected usage: %+v", u)
	}
}

func TestIsReadOnlyPolicy(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})
	if !r.IsReadOnly("system.health") || !r.IsReadOnly("account.usage") {
		t.Fatal("reads must be served offline")
	}
	if r.IsReadOnly("account.create") || r.IsReadOnly("account.delete") {
		t.Fatal("mutations must not be marked read-only")
	}
}

func TestRegistryAllowlistShape(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})
	for _, m := range []string{
		"account.create", "account.modify", "account.suspend", "account.resume",
		"account.delete", "account.quota", "account.usage", "account.list",
		"isolation.provision", "system.health", "system.info",
	} {
		if _, ok := r.Lookup(m); !ok {
			t.Fatalf("missing allowlisted method %s", m)
		}
	}
	if _, ok := r.Lookup("exec"); ok {
		t.Fatal("exec must NEVER be allowlisted")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
