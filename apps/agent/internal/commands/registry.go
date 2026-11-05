// Package commands implements the typed command allowlist (agent spec §4).
// Every method is registered explicitly; the registry IS the allowlist.
// There is deliberately no generic exec method anywhere in this package.
package commands

import (
	"encoding/json"
	"fmt"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/auth"
	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/wal"
)

// Deps carries everything handlers need.
type Deps struct {
	Verifier    *auth.Verifier
	WAL         *wal.Queue
	CgroupRoot  string // cgroup v2 root; overridable in tests
	HomeRoot    string // C13 confined root for hosting-account home dirs
	VhostRoot   string // nginx vhost include dir; overridable in tests
	NginxBinary string // nginx path; empty = exec.LookPath (tests inject a fake)
}

// Registry maps method names to handlers.
type Registry struct {
	deps Deps
	m    map[string]rpc.Handler
}

// NewRegistry registers every M0 allowlisted method. Additional methods require
// an amendment to the agent spec (§4 preamble).
func NewRegistry(deps Deps) *Registry {
	if deps.CgroupRoot == "" {
		deps.CgroupRoot = "/sys/fs/cgroup"
	}
	if deps.HomeRoot == "" {
		deps.HomeRoot = defaultHomeRoot
	}
	if deps.VhostRoot == "" {
		deps.VhostRoot = "/etc/nginx/conf.d"
	}
	r := &Registry{deps: deps, m: map[string]rpc.Handler{}}

	// account.* (§4.1)
	r.m["account.create"] = r.accountCreate
	r.m["account.modify"] = r.accountModify
	r.m["account.suspend"] = r.accountSuspend
	r.m["account.resume"] = r.accountResume
	r.m["account.delete"] = r.accountDelete
	r.m["account.quota"] = r.accountQuota
	r.m["account.usage"] = r.accountUsage
	r.m["account.list"] = r.accountList

	// isolation.* (§4.2) — M0: cgroup v2 slice provisioning only
	r.m["isolation.provision"] = r.isolationProvision

	// filesystem.* (§4.3 + ADR-0008 content-ops amendment) — P3
	r.m["filesystem.mkdir"] = r.filesystemMkdir
	r.m["filesystem.list"] = r.filesystemList
	r.m["filesystem.read"] = r.filesystemRead
	r.m["filesystem.write"] = r.filesystemWrite
	r.m["filesystem.move"] = r.filesystemMove
	r.m["filesystem.delete"] = r.filesystemDelete
	r.m["filesystem.chmod"] = r.filesystemChmod
	r.m["filesystem.usage"] = r.filesystemUsage
	r.m["filesystem.trash_purge"] = r.trashPurge

	// nginx.* (§4.7) — P3: vhost lifecycle via the config-apply primitive
	r.m["nginx.test"] = r.nginxTest
	r.m["nginx.reload"] = r.nginxReload
	r.m["nginx.apply_vhost"] = r.nginxApplyVhost
	r.m["nginx.remove_vhost"] = r.nginxRemoveVhost

	// system.* (§4.15) — M0 subset
	r.m["system.health"] = r.systemHealth
	r.m["system.info"] = r.systemInfo

	return r
}

// Lookup resolves a method on the allowlist.
func (r *Registry) Lookup(method string) (rpc.Handler, bool) {
	h, ok := r.m[method]
	return h, ok
}

// IsReadOnly reports whether a method is safe to serve while the control plane is
// unreachable (spec §6: *.status, *.list, *.usage, *.health stay available).
func (r *Registry) IsReadOnly(method string) bool {
	switch method {
	case "account.usage", "account.list", "system.health", "system.info",
		"filesystem.list", "filesystem.read", "filesystem.usage":
		return true
	}
	return false
}

// ---- shared helpers --------------------------------------------------------

func decodeParams(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "missing params"}
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	return nil
}

func (r *Registry) notImplementedYet(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	return nil, nil, &rpc.RPCError{
		Code:    rpc.CodePrecondition,
		Message: "method registered but not implemented until a later milestone",
	}
}

// auditQueued is the audit hint returned when an entry is queued offline.
func auditQueued(w *wal.Entry) *rpc.AuditHint {
	return &rpc.AuditHint{EntryID: w.ID, ThisHash: w.Hash()}
}

func kv(format string, args ...any) map[string]any {
	return map[string]any{"message": fmt.Sprintf(format, args...)}
}
