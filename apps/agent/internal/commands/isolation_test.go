package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsolationProvisionCreatesSlice(t *testing.T) {
	root := t.TempDir()
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: root})
	raw, _ := json.Marshal(map[string]any{"username": "alice", "profile": "standard"})
	res, hint, err := r.isolationProvision("t1", raw)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	out := res.(isolationProvisionResult)
	if want := filepath.Join(root, "nexuspanel", "alice"); out.Path != want {
		t.Fatalf("path = %s, want %s", out.Path, want)
	}
	if fi, err := os.Stat(out.Path); err != nil || !fi.IsDir() {
		t.Fatalf("slice dir missing: %v", err)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("expected WAL audit hint for provisioned slice")
	}

	// Idempotent by path — a second provision must succeed.
	if _, _, err := r.isolationProvision("t2", raw); err != nil {
		t.Fatalf("second provision: %v", err)
	}
}

func TestIsolationProvisionValidates(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})
	for _, name := range []string{"", "Root", "has space", "root", "www-data"} {
		raw, _ := json.Marshal(map[string]any{"username": name})
		if _, _, err := r.isolationProvision("t1", raw); err == nil {
			t.Fatalf("username %q must be rejected", name)
		}
	}
	raw, _ := json.Marshal(map[string]any{"username": "alice", "profile": "hypervisor"})
	if _, _, err := r.isolationProvision("t1", raw); err == nil {
		t.Fatal("unknown isolation profile must be rejected")
	}
}

func TestRemoveAccountCgroup(t *testing.T) {
	root := t.TempDir()
	slice := filepath.Join(root, "nexuspanel", "alice")
	if err := os.MkdirAll(slice, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removeAccountCgroup(root, "alice"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(slice); !os.IsNotExist(err) {
		t.Fatal("slice still present after teardown")
	}
	// A missing slice is a no-op, not an error.
	if err := removeAccountCgroup(root, "ghost"); err != nil {
		t.Fatalf("missing slice: %v", err)
	}
}

func TestAccountResumeValidation(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})
	raw, _ := json.Marshal(map[string]any{"username": "ghostuser"})
	if _, _, err := r.accountResume("t1", raw); err == nil {
		t.Fatal("resume of a nonexistent user must fail")
	}
	bad, _ := json.Marshal(map[string]any{"username": "NOT-VALID"})
	if _, _, err := r.accountResume("t1", bad); err == nil {
		t.Fatal("invalid username must be rejected")
	}
}
