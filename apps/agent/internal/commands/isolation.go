package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// cgroupPath is the account's cgroup v2 slice under the delegated root.
// The convention <root>/nexuspanel/<username> is shared with account.usage
// (spec §4.1: read-only usage counters) and the M0 runbook.
func cgroupPath(root, username string) string {
	return filepath.Join(root, "nexuspanel", username)
}

type isolationProvisionParams struct {
	Username string `json:"username"`
	Profile  string `json:"profile"`
}

type isolationProvisionResult struct {
	Path    string `json:"path"`
	Profile string `json:"profile"`
}

// isolationProvision creates the account's cgroup v2 slice (M0 spec §2.4).
// On Linux, mkdir inside the delegated cgroup v2 hierarchy materializes the
// slice; the operation is idempotent by path. Profile "standard" applies no
// limits in M0 — quota enforcement arrives with account.quota in P1.
func (r *Registry) isolationProvision(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p isolationProvisionParams
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
	if p.Profile == "" {
		p.Profile = "standard"
	}
	if p.Profile != "standard" {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "unknown isolation profile: " + p.Profile,
		}
	}

	dir := cgroupPath(r.deps.CgroupRoot, p.Username)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("cgroup slice create failed: %v", err),
		}
	}

	entry := r.deps.WAL.NewEntry("isolation.provision", map[string]any{
		"username": p.Username,
		"profile":  p.Profile,
	})
	_ = r.deps.WAL.Append(entry)

	return isolationProvisionResult{Path: dir, Profile: p.Profile}, auditQueued(entry), nil
}

// removeAccountCgroup tears down the account's cgroup slice. A missing path is
// a no-op; the error is surfaced to callers that treat cleanup as best-effort.
func removeAccountCgroup(root, username string) error {
	return os.RemoveAll(cgroupPath(root, username))
}
