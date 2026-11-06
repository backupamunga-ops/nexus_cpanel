//go:build linux

package term

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// PTY allocation with the standard library only (go.mod is deliberately
// dependency-free; CGO_ENABLED=0 build). /dev/ptmx + two ioctls is exactly
// what the posix_openpt(3) family does; TIOCGPTN and TIOCSPTLCK are not in
// the stdlib syscall package, so they are spelled out here. The encodings
// below are identical on linux/amd64 and linux/arm64 — the only targets the
// installer ships (docs/release/SUPPORT_MATRIX.md).
const (
	tiocgptn   = 0x80045430 // TIOCGPTN — read the allocated pty number
	tiocsptlck = 0x80045431 // TIOCSPTLCK — 0 unlocks the slave device
)

func ioctlPtr(fd, req, arg uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}

// openPTY allocates a pty pair. The caller owns both files and must close
// them; on the child side the slave becomes stdin/out/err and its controlling
// terminal (SysProcAttr.Setsid + Setctty in startShell).
func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	master = m
	defer func() {
		if err != nil {
			master.Close()
		}
	}()

	var n uint32
	if err = ioctlPtr(master.Fd(), tiocgptn, uintptr(unsafe.Pointer(&n))); err != nil {
		return nil, nil, fmt.Errorf("TIOCGPTN: %w", err)
	}
	var unlocked uint32 // 0 = remove the lock
	if err = ioctlPtr(master.Fd(), tiocsptlck, uintptr(unsafe.Pointer(&unlocked))); err != nil {
		return nil, nil, fmt.Errorf("TIOCSPTLCK: %w", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open slave: %w", err)
	}
	return master, s, nil
}

// setWinsize applies cols×rows to the tty behind fd.
func setWinsize(fd uintptr, cols, rows uint16) error {
	type winsize struct{ Row, Col, X, Y uint16 }
	ws := winsize{Row: rows, Col: cols}
	return ioctlPtr(fd, syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}

// startShell spawns shell on the pty as the given user. When the agent runs
// unprivileged (dev rigs) the credential is omitted and only sessions for the
// agent's own user can start. Because Setsid makes the child a session
// leader, its pgid equals its pid: killShell uses that to take down the whole
// process tree. The caller MUST eventually call cmd.Wait() exactly once (the
// attach loop does).
func startShell(shell, username, home string, uid, gid int, cols, rows uint16) (master *os.File, cmd *exec.Cmd, err error) {
	if err := lookAlive(shell); err != nil {
		return nil, nil, err
	}
	m, s, err := openPTY()
	if err != nil {
		return nil, nil, err
	}
	master = m
	defer func() {
		if err != nil {
			master.Close()
		}
	}()
	if err = setWinsize(master.Fd(), cols, rows); err != nil {
		return nil, nil, fmt.Errorf("initial winsize: %w", err)
	}

	cmd = exec.Command(shell)
	cmd.Dir = home
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s
	cmd.Env = []string{
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"HOME=" + home,
		"USER=" + username,
		"LOGNAME=" + username,
		"SHELL=" + shell,
		"LANG=C.UTF-8",
		// Deliberately minimal: nothing is inherited from the agent process.
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	sa := &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if os.Geteuid() == 0 && (uid != 0 || gid != 0) {
		sa.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}
	cmd.SysProcAttr = sa

	if err = cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start %s: %w", shell, err)
	}
	if err = s.Close(); err != nil { // parent keeps only the master
		killShell(cmd)
		_ = cmd.Wait()
		return nil, nil, err
	}
	return master, cmd, nil
}

// killShell terminates the child's process group: SIGTERM now, SIGKILL after
// a grace period. It never waits — the attach loop's cmd.Wait() is the single
// reaper — and a late SIGKILL on an already-exited pgid is an ignored ESRCH.
func killShell(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pgid := -cmd.Process.Pid
	_ = syscall.Kill(pgid, syscall.SIGTERM)
	go func() {
		time.Sleep(3 * time.Second)
		_ = syscall.Kill(pgid, syscall.SIGKILL)
	}()
}

// lookAlive fails loudly when the shell binary is missing — the "clear error,
// never silent" rule applied to the terminal's one hard dependency.
func lookAlive(shell string) error {
	if shell == "" {
		return fmt.Errorf("no shell configured")
	}
	if _, err := exec.LookPath(shell); err != nil {
		return fmt.Errorf("shell %s not found on this node: %w", shell, err)
	}
	return nil
}
