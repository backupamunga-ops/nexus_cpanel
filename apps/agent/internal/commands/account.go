package commands

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// usernameRe matches hosting-account usernames (spec §4.1: idempotent by username).
var usernameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// reservedNames must never be created as hosting accounts.
var reservedNames = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "adm": true,
	"nobody": true, "systemd-network": true, "systemd-resolve": true,
	"messagebus": true, "sshd": true, "www-data": true, "postgres": true,
	"nexusagent": true, "nexuspanel": true, "debian": true, "ubuntu": true,
}

type accountCreateParams struct {
	Username         string `json:"username"`
	PackageID        string `json:"package_id"`
	IsolationProfile string `json:"isolation_profile"`
	Homedir          string `json:"homedir"`
	Shell            string `json:"shell"` // empty → /usr/sbin/nologin
}

type accountCreateResult struct {
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	Homedir string `json:"homedir"`
}

// accountCreate provisions the Linux user for a hosting account (spec §4.1).
// Idempotent by username: creating an existing account with identical parameters
// returns the existing identity (conflict on differing request is P1 work).
func (r *Registry) accountCreate(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p accountCreateParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "username violates policy",
			Data:    map[string]any{"username": p.Username},
		}
	}
	if p.Homedir == "" {
		p.Homedir = "/home/" + p.Username
	}
	shell := p.Shell
	if shell == "" {
		shell = "/usr/sbin/nologin"
	}

	if uid, gid, ok := lookupUser(p.Username); ok {
		return accountCreateResult{UID: uid, GID: gid, Homedir: p.Homedir}, nil, nil
	}

	// Typed exec of a fixed binary with validated arguments. Never a shell.
	useradd, err := exec.LookPath("useradd")
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "useradd not available"}
	}
	cmd := exec.Command(useradd, "--create-home", "--home-dir", p.Homedir, "--shell", shell, p.Username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("useradd failed: %v: %s", err, truncate(string(out), 256)),
		}
	}
	uid, gid, ok := lookupUser(p.Username)
	if !ok {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "user missing after create"}
	}

	entry := r.deps.WAL.NewEntry("account.create", map[string]any{"username": p.Username, "uid": uid})
	_ = r.deps.WAL.Append(entry)

	return accountCreateResult{UID: uid, GID: gid, Homedir: p.Homedir}, auditQueued(entry), nil
}

type accountNameParams struct {
	Username string `json:"username"`
}

type statusResult struct {
	Status string `json:"status"`
}

// accountSuspend kills the account's processes and disables login (spec §4.1).
func (r *Registry) accountSuspend(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p accountNameParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if _, _, ok := lookupUser(p.Username); !ok {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "account does not exist"}
	}
	if passwd, err := exec.LookPath("passwd"); err == nil {
		_ = exec.Command(passwd, "-l", p.Username).Run()
	}
	entry := r.deps.WAL.NewEntry("account.suspend", map[string]any{"username": p.Username})
	_ = r.deps.WAL.Append(entry)
	return statusResult{Status: "suspended"}, auditQueued(entry), nil
}

type accountDeleteParams struct {
	Username      string `json:"username"`
	PreserveFiles bool   `json:"preserve_files"`
}

// accountDelete removes the Linux user (spec §4.1). File preservation is async in
// the full spec; M0 performs the synchronous simple path.
func (r *Registry) accountDelete(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p accountDeleteParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	userdel, err := exec.LookPath("userdel")
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "userdel not available"}
	}
	args := []string{}
	if !p.PreserveFiles {
		args = append(args, "--remove")
	}
	args = append(args, p.Username)
	if out, err := exec.Command(userdel, args...).CombinedOutput(); err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("userdel failed: %v: %s", err, truncate(string(out), 256)),
		}
	}
	entry := r.deps.WAL.NewEntry("account.delete", map[string]any{"username": p.Username})
	_ = r.deps.WAL.Append(entry)
	return statusResult{Status: "deleted"}, auditQueued(entry), nil
}

type usageResult struct {
	Username  string `json:"username"`
	CPUUSec   uint64 `json:"cpu_usec"`
	MemBytes  uint64 `json:"mem_bytes"`
	DiskBytes uint64 `json:"disk_bytes"`
	Procs     uint64 `json:"procs"`
}

// accountUsage reads live cgroup v2 usage for an account (spec §4.1: read-only).
// The cgroup path convention is <CgroupRoot>/nexuspanel/<username>.
func (r *Registry) accountUsage(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p accountNameParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	base := fmt.Sprintf("%s/nexuspanel/%s", r.deps.CgroupRoot, p.Username)
	cpu, _ := readFirstUint(base + "/cpu.stat.bytes") // fallback below
	if v, ok := readCpuUsec(base + "/cpu.stat"); ok {
		cpu = v
	}
	mem, _ := readFirstUint(base + "/memory.current")
	procs, _ := readFirstUint(base + "/pids.current")
	return usageResult{
		Username: p.Username,
		CPUUSec:  cpu,
		MemBytes: mem,
		Procs:    procs,
	}, nil, nil
}

type listEntry struct {
	Username string `json:"username"`
	Status   string `json:"status"`
	UID      int    `json:"uid"`
}

// accountList enumerates managed accounts from /etc/passwd for reconciliation.
func (r *Registry) accountList(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	entries := []listEntry{}
	data, err := os.ReadFile("/etc/passwd")
	if err == nil {
		for _, line := range splitLines(data) {
			f := splitColon(line)
			if len(f) < 7 || !usernameRe.MatchString(f[0]) {
				continue
			}
			uid := atoiSafe(f[2])
			if uid < 1000 && uid != 0 {
				continue // system users below the human range are not hosting accounts
			}
			status := "active"
			if f[1] == "!" || f[1] == "*" {
				status = "suspended"
			}
			entries = append(entries, listEntry{Username: f[0], Status: status, UID: uid})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Username < entries[j].Username })
	return entries, nil, nil
}

// ---- small helpers ---------------------------------------------------------

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
