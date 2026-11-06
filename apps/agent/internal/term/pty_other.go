//go:build !linux

package term

import (
	"errors"
	"os"
	"os/exec"
)

// The agent ships on Linux only (cgroup v2, systemd, docs/release/
// SUPPORT_MATRIX.md); these stubs keep the package compiling on other
// development hosts while making every terminal operation fail loudly.

var errUnsupported = errors.New("terminal sessions require linux (pty syscalls)")

func openPTY() (*os.File, *os.File, error) { return nil, nil, errUnsupported }

func setWinsize(_, _ uintptr, _, _ uint16) error { return errUnsupported }

func startShell(_, _, _ string, _, _ int, _, _ uint16) (*os.File, *exec.Cmd, error) {
	return nil, nil, errUnsupported
}

func killShell(_ *exec.Cmd) {}

func lookAlive(_ string) error { return errUnsupported }
