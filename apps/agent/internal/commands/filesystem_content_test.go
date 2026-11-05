package commands

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// filesystem content-op tests (ADR-0008). No NSS users: the mkdir-to-disk
// paths run up to the chown boundary, so write tests use the pre-created
// parent trick and assert the contract around it.

func newFsRegistry(t *testing.T) *Registry {
	t.Helper()
	return NewRegistry(Deps{WAL: newTestWAL(t), HomeRoot: t.TempDir(), VhostRoot: t.TempDir()})
}

func mkHome(t *testing.T, r *Registry, username string) string {
	t.Helper()
	home := filepath.Join(r.deps.HomeRoot, username)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestFilesystemListSortsAndTypes(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.MkdirAll(filepath.Join(home, "zdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "afile.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("afile.txt", filepath.Join(home, "alink")); err != nil {
		t.Fatal(err)
	}

	raw := rawParams(t, map[string]any{"username": "alice", "path": "."})
	res, _, err := r.filesystemList("id", raw)
	if err != nil {
		t.Fatal(err)
	}
	list := res.(listResult)
	if list.Total != 3 || len(list.Entries) != 3 {
		t.Fatalf("want 3 entries, got %d/%d", len(list.Entries), list.Total)
	}
	// dirs first, then name order: zdir, afile.txt, alink
	if list.Entries[0].Name != "zdir" || list.Entries[0].Type != "dir" {
		t.Fatalf("dir must sort first: %+v", list.Entries[0])
	}
	if list.Entries[1].Name != "afile.txt" || list.Entries[2].Name != "alink" {
		t.Fatalf("file/symlink order wrong: %+v", list.Entries)
	}
}

func TestFilesystemListRejectsEscapesAndFiles(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.WriteFile(filepath.Join(home, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.filesystemList("id", rawParams(t, map[string]any{"username": "alice", "path": "../etc"})); err == nil {
		t.Fatal("escape must be rejected")
	}
	if _, _, err := r.filesystemList("id", rawParams(t, map[string]any{"username": "alice", "path": "f"})); err == nil {
		t.Fatal("listing a file must be rejected")
	}
}

func TestFilesystemWriteReadRoundtrip(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.MkdirAll(filepath.Join(home, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := base64.StdEncoding.EncodeToString([]byte("hello nexus"))

	raw := rawParams(t, map[string]any{"username": "alice", "path": "docs/notes.txt", "content_b64": content})
	res, _, err := r.filesystemWrite("id", raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.(writeResult).WrittenBytes != 11 {
		t.Fatalf("written bytes: %+v", res)
	}
	got, _ := os.ReadFile(filepath.Join(home, "docs/notes.txt"))
	if string(got) != "hello nexus" {
		t.Fatalf("content mismatch: %q", got)
	}

	// Read back.
	rr, _, err := r.filesystemRead("id", rawParams(t, map[string]any{"username": "alice", "path": "docs/notes.txt"}))
	if err != nil {
		t.Fatal(err)
	}
	back, err := base64.StdEncoding.DecodeString(rr.(readResult).ContentB64)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != "hello nexus" {
		t.Fatalf("roundtrip mismatch: %q", back)
	}
}

func TestFilesystemWriteRefusesOverwriteWithoutFlag(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.WriteFile(filepath.Join(home, "keep.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"username": "alice", "path": "keep.txt", "content_b64": base64.StdEncoding.EncodeToString([]byte("new"))}
	if _, _, err := r.filesystemWrite("id", rawParams(t, body)); err == nil {
		t.Fatal("overwrite without the flag must conflict")
	}
	got, _ := os.ReadFile(filepath.Join(home, "keep.txt"))
	if string(got) != "original" {
		t.Fatal("original content must be intact")
	}
	body["overwrite"] = true
	if _, _, err := r.filesystemWrite("id", rawParams(t, body)); err != nil {
		t.Fatalf("overwrite with the flag must succeed: %v", err)
	}
}

func TestFilesystemWriteRejectsBadBase64AndBigContent(t *testing.T) {
	r := newFsRegistry(t)
	mkHome(t, r, "alice")
	if _, _, err := r.filesystemWrite("id", rawParams(t, map[string]any{"username": "alice", "path": "x", "content_b64": "!!!"})); err == nil {
		t.Fatal("bad base64 must be rejected")
	}
	big := base64.StdEncoding.EncodeToString(make([]byte, maxContentBytes+1))
	if _, _, err := r.filesystemWrite("id", rawParams(t, map[string]any{"username": "alice", "path": "x", "content_b64": big})); err == nil {
		t.Fatal("oversized content must be rejected")
	}
}

func TestFilesystemDeleteToTrash(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.WriteFile(filepath.Join(home, "gone.txt"), []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, _, err := r.filesystemDelete("id", rawParams(t, map[string]any{"username": "alice", "path": "gone.txt"}))
	if err != nil {
		t.Fatal(err)
	}
	dr := res.(deleteResult)
	if dr.Purged || dr.TrashPath == "" || dr.SizeBytes != 3 {
		t.Fatalf("trash delete result: %+v", dr)
	}
	if !strings.Contains(dr.TrashPath, trashDirName) {
		t.Fatalf("trash path must live in the trash dir: %q", dr.TrashPath)
	}
	if _, err := os.Stat(filepath.Join(home, "gone.txt")); !os.IsNotExist(err) {
		t.Fatal("source must be gone")
	}
	if _, err := os.Stat(dr.TrashPath); err != nil {
		t.Fatal("trash copy must exist")
	}

	// Home and trash root are protected.
	if _, _, err := r.filesystemDelete("id", rawParams(t, map[string]any{"username": "alice", "path": "."})); err == nil {
		t.Fatal("deleting the home must be refused")
	}
	if _, _, err := r.filesystemDelete("id", rawParams(t, map[string]any{"username": "alice", "path": ".nexus-trash"})); err == nil {
		t.Fatal("deleting the trash root must be refused")
	}
}

func TestFilesystemDeleteHardPurge(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.WriteFile(filepath.Join(home, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _, err := r.filesystemDelete("id", rawParams(t, map[string]any{"username": "alice", "path": "x.txt", "to_trash": false}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.(deleteResult).Purged {
		t.Fatalf("hard delete must report purged: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(home, "x.txt")); !os.IsNotExist(err) {
		t.Fatal("file must be gone")
	}
}

func TestFilesystemMoveAndRestore(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	trash := filepath.Join(home, trashDirName)
	if err := os.MkdirAll(trash, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "a.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// move a.txt into trash (simulating a delete) and back (restore).
	if _, _, err := r.filesystemMove("id", rawParams(t, map[string]any{"username": "alice", "from": "a.txt", "to": ".nexus-trash/x-a.txt"})); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.filesystemMove("id", rawParams(t, map[string]any{"username": "alice", "from": ".nexus-trash/x-a.txt", "to": "restored.txt"})); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(home, "restored.txt"))
	if string(got) != "data" {
		t.Fatalf("restored content: %q", got)
	}
	// same-path move refused
	if _, _, err := r.filesystemMove("id", rawParams(t, map[string]any{"username": "alice", "from": "restored.txt", "to": "restored.txt"})); err == nil {
		t.Fatal("same path move must be rejected")
	}
}

func TestFilesystemChmod(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.WriteFile(filepath.Join(home, "s.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mode := uint32(0o644)
	if _, _, err := r.filesystemChmod("id", rawParams(t, map[string]any{"username": "alice", "path": "s.txt", "mode": &mode})); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(home, "s.txt"))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode not applied: %v", fi.Mode().Perm())
	}
	zero := uint32(0)
	if _, _, err := r.filesystemChmod("id", rawParams(t, map[string]any{"username": "alice", "path": "s.txt", "mode": &zero})); err == nil {
		t.Fatal("mode 0 must be rejected")
	}
	big := uint32(0o10000)
	if _, _, err := r.filesystemChmod("id", rawParams(t, map[string]any{"username": "alice", "path": "s.txt", "mode": &big})); err == nil {
		t.Fatal("special bits must be rejected")
	}
}

func TestFilesystemUsageAndPurge(t *testing.T) {
	r := newFsRegistry(t)
	home := mkHome(t, r, "alice")
	if err := os.WriteFile(filepath.Join(home, "u1"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	ur, _, err := r.filesystemUsage("id", rawParams(t, map[string]any{"username": "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	if ur.(fsUsageResult).Bytes < 100 || ur.(fsUsageResult).Inodes < 2 {
		t.Fatalf("usage: %+v", ur)
	}

	// Purge: old trash entries go, fresh ones stay.
	trash := filepath.Join(home, trashDirName)
	if err := os.MkdirAll(trash, 0o700); err != nil {
		t.Fatal(err)
	}
	oldName := "20200101T000000.000000000-old.txt"
	freshName := "20990101T000000.000000000-new.txt"
	if err := os.WriteFile(filepath.Join(trash, oldName), []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trash, freshName), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trash, "random-name"), []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	pr, _, err := r.trashPurge("id", rawParams(t, map[string]any{"username": "alice", "before_date": "2026-01-01T00:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	removed := pr.(purgeResult).Removed
	if len(removed) != 1 || removed[0] != oldName {
		t.Fatalf("only the old panel-named entry must go: %v", removed)
	}
	if _, err := os.Stat(filepath.Join(trash, freshName)); err != nil {
		t.Fatal("fresh entry must stay")
	}
	if _, err := os.Stat(filepath.Join(trash, "random-name")); err != nil {
		t.Fatal("non-panel names must never be touched")
	}
}
