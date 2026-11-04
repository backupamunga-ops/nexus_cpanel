package commands

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// lookupUser resolves a username to uid/gid via NSS.
func lookupUser(username string) (int, int, bool) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// readFirstUint reads a single integer from a file (cgroup controls).
func readFirstUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readCpuUsec parses cgroup v2 cpu.stat ("usage_usec N" first line).
func readCpuUsec(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "usage_usec" {
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

func splitLines(b []byte) []string {
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func splitColon(line string) []string {
	return strings.Split(line, ":")
}

func atoiSafe(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

// ensureProcname is a compile-time guard that syscall stays linked (used by
// future kill-based suspend); keeps imports honest in the M0 skeleton.
var _ = syscall.Getpid

var _ = bytes.MinRead
var _ = fmt.Sprintf
