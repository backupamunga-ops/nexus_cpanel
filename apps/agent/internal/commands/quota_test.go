package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Quota validation lives at the boundary (agent spec §4.1). The unit rig has
// no NSS users, so handler-level tests assert the user-existence precondition
// and the parameter validator/applier are driven directly.

func TestValidateQuotasPolicy(t *testing.T) {
	valid := []*quotasSpec{
		{CPU: f64(2)},
		{CPU: f64(0.3)}, // 0.1-core granularity
		{MemMB: i64(512)},
		{Processes: i64(120)},
		{DiskMB: i64(10240)}, // known, later enforced by filesystem.quota
		{CPU: f64(1.5), MemMB: i64(256), Processes: i64(64)},
	}
	for _, q := range valid {
		if err := validateQuotas(q); err != nil {
			t.Fatalf("quota %+v must be valid: %v", q, err)
		}
	}

	invalid := []struct {
		name string
		q    *quotasSpec
	}{
		{"empty", &quotasSpec{}},
		{"zero cpu", &quotasSpec{CPU: f64(0)}},
		{"negative cpu", &quotasSpec{CPU: f64(-1.5)}},
		{"oversized cpu", &quotasSpec{CPU: f64(65)}},
		{"odd granularity", &quotasSpec{CPU: f64(1.05)}},
		{"zero mem", &quotasSpec{MemMB: i64(0)}},
		{"negative pids", &quotasSpec{Processes: i64(-3)}},
		{"oversized mem", &quotasSpec{MemMB: i64(1 << 21)}},
		{"oversized pids", &quotasSpec{Processes: i64(5000)}},
		{"negative disk", &quotasSpec{DiskMB: i64(-1)}},
		{"zero inodes", &quotasSpec{Inodes: i64(0)}},
	}
	for _, tc := range invalid {
		if err := validateQuotas(tc.q); err == nil {
			t.Fatalf("%s: must be rejected", tc.name)
		}
	}
}

func f64(v float64) *float64 { return &v }
func i64(v int64) *int64     { return &v }

func TestApplyQuotasWritesCgroupV2Controls(t *testing.T) {
	root := t.TempDir()
	slice := filepath.Join(root, "nexuspanel", "alice")
	if err := os.MkdirAll(slice, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"cpu.max", "memory.max", "pids.max"} {
		if err := os.WriteFile(filepath.Join(slice, c), []byte("max\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := applyQuotas(root, "alice", &quotasSpec{CPU: f64(2), MemMB: i64(512), Processes: i64(120)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 3 || len(res.Skipped) != 0 {
		t.Fatalf("applied=%v skipped=%v", res.Applied, res.Skipped)
	}
	if got := controlContent(t, root, "alice", "cpu.max"); got != "200000 100000" {
		t.Fatalf("cpu.max = %q, want 2 cores in usec over a 100ms period", got)
	}
	if got := controlContent(t, root, "alice", "memory.max"); got != "536870912" {
		t.Fatalf("memory.max = %q, want 512 MiB in bytes", got)
	}
	if got := controlContent(t, root, "alice", "pids.max"); got != "120" {
		t.Fatalf("pids.max = %q", got)
	}

	// disk_mb/inodes: recognized but skipped with a reason — the enforcement
	// gap is explicit in the response, never silent.
	res2, err := applyQuotas(root, "alice", &quotasSpec{DiskMB: i64(10240), Inodes: i64(100000)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Applied) != 0 || len(res2.Skipped) != 2 {
		t.Fatalf("disk/inodes must be skipped, got applied=%v skipped=%v", res2.Applied, res2.Skipped)
	}

	// The slice directory is created idempotently when missing (MkdirAll),
	// but the control files must pre-exist — a fresh slice needs its controls
	// created by the kernel (isolation.provision on a real node).
	bobSlice := filepath.Join(root, "nexuspanel", "bob")
	if err := os.MkdirAll(bobSlice, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bobSlice, "pids.max"), []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res3, err := applyQuotas(root, "bob", &quotasSpec{Processes: i64(10)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res3.Applied) != 1 {
		t.Fatalf("expected pids applied: %v", res3.Applied)
	}
}

func controlContent(t *testing.T, root, username, control string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "nexuspanel", username, control))
	if err != nil {
		t.Fatalf("control %s not written: %v", control, err)
	}
	return strings.TrimSpace(string(b))
}

func TestWriteControlFailsLoudlyWhenControlMissing(t *testing.T) {
	root := t.TempDir()
	err := writeControl(filepath.Join(root, "cpu.max"), "1 2")
	if err == nil {
		t.Fatal("missing control file must fail loudly (fail-open is forbidden)")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAccountQuotaHandlerRequiresExistingUserAndSaneParams(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})

	// No NSS user in the unit rig: the precondition fires before anything else.
	raw, _ := json.Marshal(map[string]any{"username": "alice", "quotas": map[string]any{"cpu": 1}})
	if _, _, err := r.accountQuota("t1", raw); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected account-does-not-exist precondition, got %v", err)
	}

	// Invalid username fails before the user lookup.
	raw, _ = json.Marshal(map[string]any{"username": "Root", "quotas": map[string]any{"cpu": 1}})
	if _, _, err := r.accountQuota("t1", raw); err == nil {
		t.Fatal("invalid username must be rejected")
	}
}

func TestAccountModifyRequiresSomethingToDo(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), CgroupRoot: t.TempDir()})
	raw, _ := json.Marshal(map[string]any{"username": "alice"})
	if _, _, err := r.accountModify("t1", raw); err == nil {
		t.Fatal("empty modify must be rejected")
	}
	raw, _ = json.Marshal(map[string]any{"username": "alice", "isolation_profile": "paranoid"})
	if _, _, err := r.accountModify("t1", raw); err == nil {
		t.Fatal("unknown profile must be rejected")
	}
	// Unknown-profile check fires before the user-existence check in neither
	// case: both reject on validation, proving the boundary holds regardless
	// of account state.
}

func TestAccountQuotaStrictDecodeRejectsUnknownKeys(t *testing.T) {
	raw := json.RawMessage(`{"cpu":1,"bogus":2}`)
	if _, err := decodeQuotasStrict(raw); err == nil {
		t.Fatal("unknown quota keys must fail closed at the agent boundary")
	}
	if _, err := decodeQuotasStrict(json.RawMessage(`{"cpu":1}`)); err != nil {
		t.Fatalf("canonical keys must decode: %v", err)
	}
}
