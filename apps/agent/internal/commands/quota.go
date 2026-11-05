package commands

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// account.quota + account.modify (spec §4.1) — cgroup v2 limit enforcement.
//
// The agent is the enforcement boundary: it decodes quotas STRICTLY (unknown
// keys are a protocol violation, not an opportunity to guess) and applies the
// limits it can actually enforce with cgroup v2:
//
//      cpu       → cpu.max    ("<quota_usec> 100000", period 100 ms)
//      mem_mb    → memory.max (MiB → bytes)
//      processes → pids.max
//
// disk_mb / inodes are recognized but NOT cgroup-expressible — they are
// reported in `skipped` (filesystem.quota enforcement lands with the file
// service). Skipping-and-reporting beats failing the whole command: the
// control plane persists the full quota set in the database and surfaces the
// enforcement gap; a silent no-limit state is impossible because every skip
// appears in the response and the WAL entry.
//
// The wire shape of account.quota's result is therefore
//   {applied: string[], skipped: [{key, reason}]}
// — a documented amendment of spec §4.1's placeholder `{applied}`.

const (
	cpuPeriodUsec      = 100_000 // 100 ms scheduling period
	maxCPUCores        = 64
	maxMemMB           = 1 << 20 // 1 TiB
	maxProcessPids     = 4096
	quotaPeriodUsecDiv = 10 // minimum granularity: 0.1 core
)

// quotasSpec is the canonical quota object (schema comment on
// packages.quotas). Pointers distinguish "absent" from zero; zero limits are
// always invalid (a zero limit would freeze the account).
type quotasSpec struct {
	CPU       *float64 `json:"cpu"`
	MemMB     *int64   `json:"mem_mb"`
	DiskMB    *int64   `json:"disk_mb"`
	Inodes    *int64   `json:"inodes"`
	Processes *int64   `json:"processes"`
}

// empty reports whether no enforceable key is set.
func (q *quotasSpec) empty() bool {
	return q.CPU == nil && q.MemMB == nil && q.Processes == nil &&
		q.DiskMB == nil && q.Inodes == nil
}

type skippedLimit struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

type accountQuotaResult struct {
	Applied []string       `json:"applied"`
	Skipped []skippedLimit `json:"skipped"`
}

type accountQuotaParams struct {
	Username string          `json:"username"`
	Quotas   json.RawMessage `json:"quotas"`
}

// decodeQuotasStrict unmarshals with DisallowUnknownFields — the agent must
// understand everything it is told to enforce (C13 lesson: the signed
// command is the boundary, so anything unrecognized fails closed).
func decodeQuotasStrict(raw json.RawMessage) (*quotasSpec, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var q quotasSpec
	if err := dec.Decode(&q); err != nil {
		return nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "quotas: " + err.Error(),
		}
	}
	return &q, nil
}

// validateQuotas enforces the value policy; nil fields are allowed (partial
// updates) but at least one enforceable key must be present.
func validateQuotas(q *quotasSpec) error {
	if q.empty() {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "quotas must set at least one limit"}
	}
	if q.CPU != nil {
		if *q.CPU <= 0 || *q.CPU > maxCPUCores {
			return &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: fmt.Sprintf("cpu must be > 0 and <= %d", maxCPUCores),
			}
		}
		// 0.1-core granularity, tolerant of float representation noise.
		scaled := *q.CPU * float64(quotaPeriodUsecDiv)
		if math.Abs(scaled-math.Round(scaled)) > 1e-6 {
			return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "cpu must be a multiple of 0.1 cores"}
		}
	}
	for name, v := range map[string]*int64{"mem_mb": q.MemMB, "disk_mb": q.DiskMB, "inodes": q.Inodes, "processes": q.Processes} {
		if v == nil {
			continue
		}
		if *v <= 0 {
			return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: name + " must be > 0"}
		}
	}
	if q.MemMB != nil && *q.MemMB > maxMemMB {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "mem_mb exceeds the 1 TiB ceiling"}
	}
	if q.Processes != nil && *q.Processes > maxProcessPids {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "processes exceeds the 4096 ceiling"}
	}
	return nil
}

// applyQuotas writes the cgroup v2 controls for the account slice. The slice
// directory is created idempotently (same convention as isolation.provision).
// Missing controls (controller not delegated) fail LOUDLY — a limit that
// silently does not apply is fail-open.
func applyQuotas(root, username string, q *quotasSpec) (*accountQuotaResult, error) {
	slice := cgroupPath(root, username)
	if err := os.MkdirAll(slice, 0o755); err != nil {
		return nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("cgroup slice create failed: %v", err),
		}
	}

	res := &accountQuotaResult{Applied: []string{}, Skipped: []skippedLimit{}}
	if q.CPU != nil {
		quotaUsec := int64(math.Round(*q.CPU * float64(cpuPeriodUsec)))
		if err := writeControl(filepath.Join(slice, "cpu.max"), fmt.Sprintf("%d %d", quotaUsec, cpuPeriodUsec)); err != nil {
			return nil, err
		}
		res.Applied = append(res.Applied, "cpu")
	}
	if q.MemMB != nil {
		if err := writeControl(filepath.Join(slice, "memory.max"), fmt.Sprintf("%d", *q.MemMB<<20)); err != nil {
			return nil, err
		}
		res.Applied = append(res.Applied, "mem_mb")
	}
	if q.Processes != nil {
		if err := writeControl(filepath.Join(slice, "pids.max"), fmt.Sprintf("%d", *q.Processes)); err != nil {
			return nil, err
		}
		res.Applied = append(res.Applied, "processes")
	}
	if q.DiskMB != nil {
		res.Skipped = append(res.Skipped, skippedLimit{Key: "disk_mb", Reason: "requires filesystem.quota (not yet enforced)"})
	}
	if q.Inodes != nil {
		res.Skipped = append(res.Skipped, skippedLimit{Key: "inodes", Reason: "requires filesystem.quota (not yet enforced)"})
	}
	return res, nil
}

// writeControl writes a cgroup control file; the file MUST exist (the
// controller is required for the limit to be real).
func writeControl(path, value string) error {
	if _, err := os.Stat(path); err != nil {
		return &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: fmt.Sprintf("cgroup control %s unavailable: %v", filepath.Base(path), err),
		}
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("writing %s failed: %v", filepath.Base(path), err),
		}
	}
	return nil
}

// accountQuota applies cgroup v2 limits for an account (spec §4.1).
func (r *Registry) accountQuota(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p accountQuotaParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if _, _, ok := lookupUser(p.Username); !ok {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "account does not exist"}
	}
	quotas, err := decodeQuotasStrict(p.Quotas)
	if err != nil {
		return nil, nil, err
	}
	if err := validateQuotas(quotas); err != nil {
		return nil, nil, err
	}

	result, err := applyQuotas(r.deps.CgroupRoot, p.Username, quotas)
	if err != nil {
		return nil, nil, err
	}

	entry := r.deps.WAL.NewEntry("account.quota", map[string]any{
		"username": p.Username,
		"applied":  result.Applied,
		"skipped":  result.Skipped,
	})
	_ = r.deps.WAL.Append(entry)
	return result, auditQueued(entry), nil
}

type accountModifyParams struct {
	Username         string      `json:"username"`
	Quotas           *quotasSpec `json:"quotas"`
	IsolationProfile *string     `json:"isolation_profile"`
}

// accountModify changes quotas and/or the isolation profile for an existing
// account (spec §4.1). Profile "standard" is the only profile in M0; the
// operation is idempotent.
func (r *Registry) accountModify(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p accountModifyParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if _, _, ok := lookupUser(p.Username); !ok {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "account does not exist"}
	}
	if p.Quotas == nil && p.IsolationProfile == nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "nothing to modify (set quotas and/or isolation_profile)"}
	}
	if p.IsolationProfile != nil && *p.IsolationProfile != "standard" {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "unknown isolation profile: " + *p.IsolationProfile,
		}
	}

	var applied []string
	var skipped []skippedLimit
	if p.Quotas != nil {
		if err := validateQuotas(p.Quotas); err != nil {
			return nil, nil, err
		}
		result, err := applyQuotas(r.deps.CgroupRoot, p.Username, p.Quotas)
		if err != nil {
			return nil, nil, err
		}
		applied = result.Applied
		skipped = result.Skipped
	}

	entry := r.deps.WAL.NewEntry("account.modify", map[string]any{
		"username": p.Username,
		"applied":  applied,
		"skipped":  skipped,
	})
	_ = r.deps.WAL.Append(entry)

	status := "active"
	if suspended, ok := shadowLocked(p.Username); ok && suspended {
		status = "suspended"
	}
	return struct {
		Status  string         `json:"status"`
		Applied []string       `json:"applied"`
		Skipped []skippedLimit `json:"skipped,omitempty"`
	}{Status: status, Applied: applied, Skipped: skipped}, auditQueued(entry), nil
}
