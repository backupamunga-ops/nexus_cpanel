package wal

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAppendAndDrainOrder(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	var ops []string
	var chain [][32]byte
	for _, op := range []string{"account.create", "account.suspend", "account.delete"} {
		e := q.NewEntry(op, map[string]any{"username": "alice"})
		// Chain integrity: each entry's prior must equal the previous this-hash.
		if len(chain) > 0 && e.PriorHash != chain[len(chain)-1] {
			t.Fatalf("chain break at %s", op)
		}
		if err := q.Append(e); err != nil {
			t.Fatalf("append %s: %v", op, err)
		}
		chain = append(chain, e.ThisHash)
		ops = append(ops, op)
	}

	n, err := q.Drain(func(e *Entry) error {
		if e.Operation != ops[0] {
			t.Fatalf("out of order: got %s want %s", e.Operation, ops[0])
		}
		ops = ops[1:]
		return nil
	})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n != 3 {
		t.Fatalf("drained %d, want 3", n)
	}
	files, _ := walFiles(dir)
	if len(files) != 0 {
		t.Fatalf("wal dir not empty after drain: %v", files)
	}
}

func TestChainBreakDetection(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir, 100)
	e1 := q.NewEntry("account.create", map[string]any{"username": "alice"})
	_ = q.Append(e1)
	e2 := q.NewEntry("account.suspend", map[string]any{"username": "alice"})
	if e2.PriorHash != e1.ThisHash {
		t.Fatal("e2 must chain to e1")
	}
	// Tamper: recompute e1 with different params — hashes must diverge.
	forged := hashEntry(e1.PriorHash, e1.Occurred, e1.Operation, map[string]any{"username": "ROOT"}, e1.Outcome)
	if forged == e1.ThisHash {
		t.Fatal("tampered params must produce a different hash")
	}
}

func TestResumeRestoresChainHead(t *testing.T) {
	dir := t.TempDir()
	q1, _ := Open(dir, 100)
	e := q1.NewEntry("account.create", map[string]any{"username": "bob"})
	_ = q1.Append(e)

	q2, err := Open(dir, 100)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	e2 := q2.NewEntry("account.delete", map[string]any{"username": "bob"})
	if e2.PriorHash != e.ThisHash {
		t.Fatal("resumed queue lost chain head")
	}
}

func TestCapDropsOldest(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir, 3)
	for i := 0; i < 5; i++ {
		e := q.NewEntry("account.quota", map[string]any{"n": i})
		_ = q.Append(e)
	}
	files, _ := walFiles(dir)
	if len(files) != 3 {
		t.Fatalf("cap not enforced: %d files", len(files))
	}
	if q.Dropped() == 0 {
		t.Fatal("dropped counter must increase")
	}
}

func TestEntryJSONRoundtrip(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir, 10)
	e := q.NewEntry("account.create", map[string]any{"username": "carol"})
	b, _ := json.Marshal(e)
	s := string(b)
	if len(s) == 0 {
		t.Fatal("empty json")
	}
	if !strings.Contains(s, "account.create") {
		t.Fatal("operation missing from json")
	}
	if strings.Contains(s, "e_seq") {
		t.Fatal("unexported sequence must not serialize")
	}
}
