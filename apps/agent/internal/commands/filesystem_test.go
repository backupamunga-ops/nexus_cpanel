package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// confineUnderHome is C13 round 2: lexical policy + symlink-aware walk of
// the existing prefix. The rig runs as an unprivileged user, which is
// exactly the adversary model for planted symlinks.

func TestConfineUnderHomeLexical(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}

	ok := []struct{ requested, want string }{
		{filepath.Join(home, "domains/x.com"), filepath.Join(home, "domains/x.com")},
		{"sites/blog", filepath.Join(home, "sites/blog")}, // relative → home
		{home, home},
		{filepath.Join(home, "a/../b"), filepath.Join(home, "b")},
		{home + "//./x/", filepath.Join(home, "x")},
	}
	for _, tc := range ok {
		got, err := confineUnderHome(root, "alice", tc.requested)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", tc.requested, err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.requested, got, tc.want)
		}
	}

	bad := []string{
		"",
		"/etc/nginx",                 // outside home
		filepath.Join(root, "bob/x"), // sibling account
		home + "/../../etc",          // lexical escape after clean
		"homedir\x00nul",             // NUL
		"back\\slash",                // backslash
	}
	for _, b := range bad {
		if _, err := confineUnderHome(root, "alice", b); err == nil {
			t.Fatalf("%q: must be rejected", b)
		}
	}
}

func TestConfineUnderHomeBlocksPlantedSymlink(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}

	// Attacker plants a symlink INSIDE the home pointing outside.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := confineUnderHome(root, "alice", filepath.Join(home, "escape", "payload")); err == nil {
		t.Fatal("symlink escape must be rejected")
	}

	// A home that is itself a symlink is the OS's normal topology (the
	// resolved home IS the confinement target — every check below it stays
	// relative to the resolved location), so it must PASS:
	root2 := t.TempDir()
	realHome := t.TempDir()
	symlinkedHome := filepath.Join(root2, "alice")
	if err := os.Symlink(realHome, symlinkedHome); err != nil {
		t.Fatal(err)
	}
	got, err := confineUnderHome(root2, "alice", "x")
	if err != nil {
		t.Fatalf("symlinked home must resolve consistently: %v", err)
	}
	want := filepath.Join(symlinkedHome, "x")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	// But a symlink INSIDE the resolved home pointing elsewhere must FAIL.
	if err := os.Symlink(t.TempDir(), filepath.Join(realHome, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := confineUnderHome(root2, "alice", "escape/payload"); err == nil {
		t.Fatal("symlink escape below the home must be rejected")
	}
}

func TestConfineUnderHomeFreshAccount(t *testing.T) {
	root := t.TempDir() // no home yet — fresh account
	got, err := confineUnderHome(root, "alice", "domains/x.com/public_html")
	if err != nil {
		t.Fatalf("relative path on a fresh account must resolve: %v", err)
	}
	want := filepath.Join(root, "alice", "domains/x.com/public_html")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// Absolute escape still rejected even though home doesn't exist.
	if _, err := confineUnderHome(root, "alice", "/etc"); err == nil {
		t.Fatal("absolute escape must be rejected on a fresh account")
	}
}

func TestFilesystemMkdirValidation(t *testing.T) {
	r := NewRegistry(Deps{WAL: newTestWAL(t), HomeRoot: t.TempDir(), VhostRoot: t.TempDir()})

	if _, _, err := r.filesystemMkdir("id", rawParams(t, mkdirParams{Username: "BAD NAME", Path: "x"})); err == nil {
		t.Fatal("invalid username must be rejected")
	}
	if _, _, err := r.filesystemMkdir("id", rawParams(t, mkdirParams{Username: "alice", Path: "x", Owner: "bob"})); err == nil {
		t.Fatal("owner != account must be rejected")
	}
	mode := uint32(0o10000) // sticky/setuid territory
	if _, _, err := r.filesystemMkdir("id", rawParams(t, mkdirParams{Username: "alice", Path: "x", Mode: &mode})); err == nil {
		t.Fatal("mode above 0777 must be rejected")
	}
	if _, _, err := r.filesystemMkdir("id", rawParams(t, mkdirParams{Username: "alice", Path: "/etc/nginx"})); err == nil {
		t.Fatal("path outside home must be rejected")
	}
}

func TestFilesystemMkdirIdempotentAndConflict(t *testing.T) {
	// No NSS users in the rig: exercise up to the user-lookup boundary by
	// pre-creating the target as a directory (idempotent branch) and as a
	// file (conflict branch) — both answer before lookupUser.
	homeRoot := t.TempDir()
	home := filepath.Join(homeRoot, "alice")
	if err := os.MkdirAll(filepath.Join(home, "exists"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "afile"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry(Deps{WAL: newTestWAL(t), HomeRoot: homeRoot, VhostRoot: t.TempDir()})

	res, _, err := r.filesystemMkdir("id", rawParams(t, mkdirParams{Username: "alice", Path: "exists"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(mkdirResult).Created {
		t.Fatal("existing directory must answer created:false")
	}

	if _, _, err := r.filesystemMkdir("id", rawParams(t, mkdirParams{Username: "alice", Path: "afile"})); err == nil {
		t.Fatal("existing file must conflict")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("conflict must name the problem: %v", err)
	}
}
