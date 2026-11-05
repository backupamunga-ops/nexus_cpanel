package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- confineHomeDir --------------------------------------------------------

func TestConfineHomeDirAcceptsConfinement(t *testing.T) {
	root := "/home"
	cases := []struct{ in, want string }{
		{"", "/home/alice"},
		{"/home/alice", "/home/alice"},
		{"/home/alice/", "/home/alice"},
		{"/home//alice", "/home/alice"},
		{"/home/./alice", "/home/alice"},
		// Resolves into the confined location — allowed per C13.
		{"/home/x/../alice", "/home/alice"},
		{"/home/../home/alice", "/home/alice"},
	}
	for _, c := range cases {
		got, err := confineHomeDir(c.in, "alice", root)
		if err != nil {
			t.Fatalf("confineHomeDir(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("confineHomeDir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestConfineHomeDirRejectsEscapeAttempts(t *testing.T) {
	cases := []string{
		"/etc",
		"/etc/passwd",
		"/home/bob",             // another account's home
		"/home/alice/../bob",    // resolves to another account
		"/home/alice/../../etc", // resolves to /etc
		"/home/alice/..",        // resolves to the root itself
		"/home",
		"home/alice",  // relative
		"./alice",     // relative
		"~/alice",     // not expanded by the agent, ever
		"/Home/alice", // case-sensitive fs: outside root
		"/home/alice\\x",
		"/home/alice\x00/etc",
		"/opt/data/alice",
		strings.Repeat("/home/alice/", 200) + "deep",
	}
	for _, in := range cases {
		if _, err := confineHomeDir(in, "alice", "/home"); err == nil {
			t.Fatalf("confineHomeDir(%q) must be rejected", in)
		}
	}
}

func TestConfineHomeDirAllowsRootItselfAsSymlink(t *testing.T) {
	// Some distros legitimately make /home a symlink (e.g. to /var/home).
	// Resolution is then CONSISTENT — root and parent resolve to the same
	// target — and must be allowed.
	base := t.TempDir()
	real := filepath.Join(base, "var-home")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "home")
	if err := os.Symlink(real, root); err != nil {
		t.Fatal(err)
	}
	got, err := confineHomeDir("", "alice", root)
	if err != nil {
		t.Fatalf("root-as-symlink must be allowed: %v", err)
	}
	if want := filepath.Join(root, "alice"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// ---- confineShell ----------------------------------------------------------

func TestConfineShellAllowlist(t *testing.T) {
	if got, err := confineShell(""); err != nil || got != "/usr/sbin/nologin" {
		t.Fatalf("empty shell = %q, %v", got, err)
	}
	if got, err := confineShell("/usr/sbin/nologin"); err != nil || got != "/usr/sbin/nologin" {
		t.Fatalf("nologin = %q, %v", got, err)
	}
	for _, shell := range []string{"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/python3", "../../bin/bash", "/bin/bash\x00"} {
		if _, err := confineShell(shell); err == nil {
			t.Fatalf("shell %q must be rejected", shell)
		}
	}
}

// ---- end-to-end through account.create -------------------------------------

// recorder builds a PATH where every listed tool records its arguments into
// dir/args-<tool> and exits 0 — proving validation happens BEFORE any exec.
func recorder(t *testing.T, tools ...string) string {
	t.Helper()
	bin := t.TempDir()
	for _, tool := range tools {
		tool := tool
		script := "#!/bin/sh\necho \"$@\" >> \"" + filepath.Join(bin, "args-"+tool) + "\"\nexit 0\n"
		if err := os.WriteFile(filepath.Join(bin, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return bin
}

func TestAccountCreateRejectsEscapingHomedirBeforeExec(t *testing.T) {
	bin := recorder(t, "useradd")
	r := NewRegistry(Deps{WAL: newTestWAL(t), HomeRoot: "/home"})
	raw, _ := json.Marshal(map[string]any{"username": "alice", "homedir": "/etc", "shell": "/usr/sbin/nologin"})
	_, _, err := r.accountCreate("t1", raw)
	if err == nil {
		t.Fatal("escaping homedir must be rejected")
	}
	if _, err := os.Stat(filepath.Join(bin, "args-useradd")); !os.IsNotExist(err) {
		t.Fatal("useradd must not have been executed")
	}
}

func TestAccountCreateRejectsForbiddenShellBeforeExec(t *testing.T) {
	bin := recorder(t, "useradd")
	r := NewRegistry(Deps{WAL: newTestWAL(t), HomeRoot: "/home"})
	raw, _ := json.Marshal(map[string]any{"username": "alice", "shell": "/bin/bash"})
	_, _, err := r.accountCreate("t1", raw)
	if err == nil {
		t.Fatal("non-allowlisted shell must be rejected")
	}
	if _, err := os.Stat(filepath.Join(bin, "args-useradd")); !os.IsNotExist(err) {
		t.Fatal("useradd must not have been executed")
	}
}

func TestAccountCreateRejectsPrePlantedHomeSymlink(t *testing.T) {
	// The direct C13 attack: /home/alice already exists as a symlink to
	// somewhere outside — useradd -m would place files through it.
	base := t.TempDir()
	root := filepath.Join(base, "home")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(base, "etc")
	if err := os.Mkdir(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, filepath.Join(root, "alice")); err != nil {
		t.Fatal(err)
	}

	bin := recorder(t, "useradd")
	r := NewRegistry(Deps{WAL: newTestWAL(t), HomeRoot: root})
	raw, _ := json.Marshal(map[string]any{"username": "alice"})
	_, _, err := r.accountCreate("t1", raw)
	if err == nil {
		t.Fatal("pre-planted home symlink must be rejected")
	}
	if _, err := os.Stat(filepath.Join(bin, "args-useradd")); !os.IsNotExist(err) {
		t.Fatal("useradd must not have been executed")
	}
}

// ---- C13 fuzz targets (native fuzzing; seeds run in CI via `go test`) ------

func FuzzConfineHomeDir(f *testing.F) {
	seeds := []string{
		"", "/home/alice", "../../../etc/passwd", "/etc", "/home/../etc/passwd",
		"/home/alice/../../..", "alice", "/home//alice//", "/home/./alice",
		"/home/alice\x00x", "\\", "/HOME/ALICE", "/home/alice/../../../../var/www",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, homedir string) {
		got, err := confineHomeDir(homedir, "alice", "/home")
		if err != nil {
			return // rejected is always acceptable
		}
		// INVARIANT: any accepted path is exactly the confined canonical form.
		if got != filepath.Clean("/home/alice") {
			t.Fatalf("accepted unconfined path %q -> %q", homedir, got)
		}
		if strings.Contains(got, "\x00") || strings.Contains(got, "..") {
			t.Fatalf("accepted path with hostile segments: %q", got)
		}
	})
}

func FuzzUsernamePolicy(f *testing.F) {
	seeds := []string{
		"alice", "", "Root", "1abc", "a", "has space", "has/slash", "../etc",
		"root", "www-data", "a_b", "Ärger", strings.Repeat("a", 33), strings.Repeat("a", 32),
		"user-1", "-leading", "trailing-",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, username string) {
		if !usernameRe.MatchString(username) || reservedNames[username] {
			return // rejected
		}
		// INVARIANT: every accepted username can never traverse or escape —
		// it contains no separators, dots or whitespace by construction.
		if strings.ContainsAny(username, "/\\. ") {
			t.Fatalf("accepted username with separator: %q", username)
		}
		if username == "" || username == ".." || username == "." {
			t.Fatalf("accepted hostile username: %q", username)
		}
	})
}
