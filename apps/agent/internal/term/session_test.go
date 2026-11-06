package term

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/wal"
)

// ---- frame codec ------------------------------------------------------------

func TestFrameRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		t Frame
		p []byte
	}{
		{FrameInput, []byte("ls -la\r")},
		{FramePing, nil},
		{FrameOutput, bytes.Repeat([]byte{0x00, 0xff, 0x1b}, 1000)},
		{FrameExit, []byte(`{"status":0}`)},
	} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, tc.t, tc.p); err != nil {
			t.Fatalf("write %v: %v", tc.t, err)
		}
		got, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read %v: %v", tc.t, err)
		}
		if got != tc.t || !bytes.Equal(payload, tc.p) {
			t.Fatalf("roundtrip mismatch: got (%v, %d bytes) want (%v, %d bytes)", got, len(payload), tc.t, len(tc.p))
		}
	}
}

func TestReadFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{byte(FrameInput), 0xff, 0xff, 0x00, 0x00}) // 16 MiB declared
	if _, _, err := ReadFrame(&buf); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("want errFrameTooLarge, got %v", err)
	}
}

func TestWriteFrameRejectsOversize(t *testing.T) {
	if err := WriteFrame(io.Discard, FrameOutput, make([]byte, maxFrameSize+1)); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("want errFrameTooLarge, got %v", err)
	}
}

// ---- params validation --------------------------------------------------------

func TestClampDim(t *testing.T) {
	if clampDim(0, minCols, maxCols, 80) != 80 {
		t.Fatal("0 must take the default")
	}
	if clampDim(1, minCols, maxCols, 80) != 2 || clampDim(60000, minCols, maxCols, 80) != maxCols {
		t.Fatal("clamping broken")
	}
}

func TestUsernamePattern(t *testing.T) {
	for _, ok := range []string{"amunga", "a_b-c", "_x"} {
		if !usernameRE.MatchString(ok) {
			t.Fatalf("%q should match", ok)
		}
	}
	for _, bad := range []string{"Amunga", "1abc", "a b", "-x", strings.Repeat("a", 33), ""} {
		if usernameRE.MatchString(bad) {
			t.Fatalf("%q should NOT match", bad)
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.MaxSessions != 3 || c.IdleTimeout != 15*time.Minute || c.MaxLifetime != 8*time.Hour {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

// ---- live session (linux) --------------------------------------------------------

// TestSessionEcho exercises a real pty round trip: open a shell as the current
// user, type an echo command, read the echo back, then exit and observe the
// exit frame + close audit. Skipped outside linux.
func TestSessionEcho(t *testing.T) {
	if runtime.GOOS != "linux" || !ptyProbeOK(t) {
		t.Skip("pty requires linux with unrestricted TIOCSPTLCK")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}
	uid, _, _, shell, ok := passwdEntry(me.Username)
	if !ok {
		t.Skip("no passwd entry for the test user")
	}
	if baseName(shell) == "nologin" || baseName(shell) == "false" {
		t.Skip("test user has no usable shell")
	}

	mgr := NewManager(Config{IdleTimeout: time.Hour, MaxLifetime: time.Hour, AllowRoot: uid == 0}, newWAL(t))
	params, _ := json.Marshal(openParams{Username: me.Username, Cols: 80, Rows: 24})
	prep, err := mgr.Prepare("req_test_1", params)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	c1, c2 := net.Pipe() // c1 = test client end, c2 = the session's stream
	done := make(chan struct{})
	go func() { prep.Attach(c2); close(done) }()

	if err := WriteFrame(c1, FrameInput, []byte("echo nexus_term_ok\n")); err != nil {
		t.Fatalf("input: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	sawOutput := false
	for !sawOutput && time.Now().Before(deadline) {
		t1, payload, err := ReadFrame(c1)
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		if t1 == FrameOutput && bytes.Contains(payload, []byte("nexus_term_ok")) {
			sawOutput = true
		}
	}
	if !sawOutput {
		t.Fatal("timed out waiting for shell output")
	}

	if err := WriteFrame(c1, FrameInput, []byte("exit\n")); err != nil {
		t.Fatalf("exit input: %v", err)
	}
	for {
		select {
		case <-done:
			return
		case <-time.After(15 * time.Second):
			t.Fatal("session did not end after exit")
		default:
			t1, _, err := ReadFrame(c1)
			if err != nil {
				select {
				case <-done:
					return
				case <-time.After(5 * time.Second):
					t.Fatalf("client read after exit: %v", err)
				}
			}
			if t1 == FrameExit {
				return
			}
		}
	}
}

// TestPrepareValidation covers the fail-fast rejection paths that must stay
// clean JSON-RPC errors (never a half-open stream).
func TestPrepareValidation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("agent targets linux")
	}
	mgr := NewManager(Config{MaxSessions: 1}, newWAL(t))

	if _, err := mgr.Prepare("req_1", nil); err == nil {
		t.Fatal("nil params must be rejected")
	}
	bad, _ := json.Marshal(openParams{Username: "Amunga"})
	if _, err := mgr.Prepare("req_2", bad); err == nil {
		t.Fatal("uppercase username must be rejected")
	}
	ghost, _ := json.Marshal(openParams{Username: "nexus_no_such_user_zz"})
	if _, err := mgr.Prepare("req_3", ghost); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing user must be a clear precondition error, got %v", err)
	}
}

// TestSessionLimit proves the node-side cap is enforced regardless of what
// the control plane asks for.
func TestSessionLimit(t *testing.T) {
	if runtime.GOOS != "linux" || !ptyProbeOK(t) {
		t.Skip("pty requires linux with unrestricted TIOCSPTLCK")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}
	uid, _, _, shell, ok := passwdEntry(me.Username)
	if !ok || baseName(shell) == "nologin" || baseName(shell) == "false" {
		t.Skip("no usable shell for the test user")
	}
	mgr := NewManager(Config{MaxSessions: 1, AllowRoot: uid == 0}, newWAL(t))
	params, _ := json.Marshal(openParams{Username: me.Username})

	firstAny, err := mgr.Prepare("req_s1", params)
	if err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	first := firstAny.(*Prepared)
	defer func() { _ = first.s.master.Close(); killShell(first.s.cmd) }()

	if _, err := mgr.Prepare("req_s2", params); err == nil || !strings.Contains(err.Error(), "limit reached") {
		t.Fatalf("second session must hit the cap, got %v", err)
	}
}

// ---- helpers ----------------------------------------------------------------

// ptyProbeOK reports whether this host permits the full pty handshake. Some
// hardened sandboxes (CI seccomp filters) allow TIOCGPTN but reject
// TIOCSPTLCK, which makes every slave open fail with EIO — a host property,
// not a code property, so the live tests skip with a clear reason there and
// run on real nodes.
func ptyProbeOK(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS != "linux" {
		return false
	}
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return false
	}
	defer m.Close()
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), 0x80045430, uintptr(unsafe.Pointer(&n))); errno != 0 {
		return false // TIOCGPTN itself unavailable
	}
	var unlocked uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), 0x80045431, uintptr(unsafe.Pointer(&unlocked))); errno != 0 {
		t.Logf("pty unlock ioctl unavailable on this host (%v) — live pty tests skipped", errno)
		return false
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Logf("pty slave open unavailable on this host (%v) — live pty tests skipped", err)
		return false
	}
	_ = s.Close()
	return true
}

func newWAL(t *testing.T) *wal.Queue {
	t.Helper()
	q, err := wal.Open(t.TempDir(), 1000)
	if err != nil {
		t.Fatalf("wal: %v", err)
	}
	return q
}
