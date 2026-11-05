package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// nginx.* (agent spec §4.7) — vhost lifecycle through the configuration
// engine's apply primitive: staging write → atomic swap → health check →
// auto-rollback. nginx.apply_vhost is the first consumer of that pipeline
// (spec §4.7: "via config.apply"); the config.* allowlist methods generalize
// it in the config-engine milestone.
//
// Security posture:
//   - The domain IS the filename (<fqdn>.conf). The FQDN regex makes path
//     traversal structurally impossible — no sanitization, only validation.
//   - Content is size-capped (64 KiB), NUL-free, valid UTF-8. It is signed
//     by the control plane, but the signature proves the SENDER, not the
//     syntax — the health check is the semantic boundary.
//   - A failed health check restores the previous file byte-for-byte
//     (auto-rollback, master spec §"Configuration Engine"). The write is
//     never left half-applied.
//
// Dev environments without an nginx binary report health_check:"skipped"
// with the reason — explicitly surfaced in the result and the WAL entry,
// never silent (D-11 honesty extends to the agent).

const (
	maxVhostBytes = 64 << 10
	vhostExt      = ".conf"
)

// fqdnRe mirrors the control plane's domain validation (sites.service).
// Lowercase FQDN, no wildcard, label-by-label RFC-1129 hostnames.
var fqdnRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type applyVhostParams struct {
	Domain  string `json:"domain"`
	Content string `json:"content"`
}

type vhostOpResult struct {
	Status          string `json:"status"`       // applied | removed | absent
	HealthCheck     string `json:"health_check"` // passed | skipped
	HealthDetail    string `json:"health_detail,omitempty"`
	PreviousExisted bool   `json:"previous_existed"`
}

type testParams struct{} // nginx.test takes no params

type simpleStatus struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// validateVhostContent is the shared content policy for vhost writes.
func validateVhostContent(content string) error {
	if strings.TrimSpace(content) == "" {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "content is empty"}
	}
	if len(content) > maxVhostBytes {
		return &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: fmt.Sprintf("content exceeds %d bytes", maxVhostBytes),
		}
	}
	if strings.ContainsRune(content, 0) {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "content contains NUL"}
	}
	if !utf8.ValidString(content) {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "content is not valid UTF-8"}
	}
	return nil
}

// healthCheck runs the nginx config test. Binary resolution order: the Deps
// override (tests), then exec.LookPath. Absent binary = skipped, reported.
func (r *Registry) healthCheck() (status string, detail string, failed bool) {
	bin := r.deps.NginxBinary
	if bin == "" {
		found, err := exec.LookPath("nginx")
		if err != nil {
			return "skipped", "nginx binary not found on this node", false
		}
		bin = found
	}
	cmd := exec.Command(bin, "-t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if len(trimmed) > 400 {
			trimmed = trimmed[:397] + "..."
		}
		return "failed", trimmed, true
	}
	return "passed", strings.TrimSpace(string(out)), false
}

// atomicWrite is the config-engine apply primitive: stage in the target
// directory, rename over the final path (atomic on the same filesystem),
// then hand the decision to the caller's health gate. restore() puts the
// previous bytes back byte-for-byte.
func atomicWrite(final string, content []byte) (prev []byte, prevOk bool, restore func(), err error) {
	if old, err := os.ReadFile(final); err == nil {
		prev, prevOk = old, true
	}
	staging := final + ".nexus-staging"
	if err := os.WriteFile(staging, content, 0o644); err != nil {
		return nil, false, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("staging write failed: %v", err),
		}
	}
	if err := os.Rename(staging, final); err != nil {
		_ = os.Remove(staging)
		return nil, false, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("atomic swap failed: %v", err),
		}
	}
	restore = func() {
		if prevOk {
			_ = os.WriteFile(staging, prev, 0o644)
			_ = os.Rename(staging, final)
		} else {
			_ = os.Remove(final)
		}
	}
	return prev, prevOk, restore, nil
}

// nginxApplyVhost writes (or replaces) the vhost for a domain.
func (r *Registry) nginxApplyVhost(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p applyVhostParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}
	if err := validateVhostContent(p.Content); err != nil {
		return nil, nil, err
	}

	final := filepath.Join(r.deps.VhostRoot, p.Domain+vhostExt)
	_, prevOk, restore, err := atomicWrite(final, []byte(p.Content))
	if err != nil {
		return nil, nil, err
	}

	status, detail, failed := r.healthCheck()
	if failed {
		restore()
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "health check failed; vhost change rolled back: " + detail,
		}
	}

	entry := r.deps.WAL.NewEntry("nginx.apply_vhost", map[string]any{
		"domain": p.Domain, "health_check": status,
		"previous_existed": prevOk, "bytes": len(p.Content),
	})
	_ = r.deps.WAL.Append(entry)
	return vhostOpResult{
		Status:          "applied",
		HealthCheck:     status,
		HealthDetail:    detail,
		PreviousExisted: prevOk,
	}, auditQueued(entry), nil
}

// nginxRemoveVhost deletes a domain's vhost. Idempotent: removing an absent
// vhost answers {status:"absent"} — the desired state is already met.
func (r *Registry) nginxRemoveVhost(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p applyVhostParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}

	final := filepath.Join(r.deps.VhostRoot, p.Domain+vhostExt)
	if _, err := os.Lstat(final); err != nil {
		// Absent: desired state already met. Still WAL-audited so the control
		// plane's timeline shows the reconciliation attempt.
		entry := r.deps.WAL.NewEntry("nginx.remove_vhost", map[string]any{
			"domain": p.Domain, "absent": true,
		})
		_ = r.deps.WAL.Append(entry)
		return vhostOpResult{Status: "absent"}, auditQueued(entry), nil
	}

	prev, readErr := os.ReadFile(final)
	if readErr != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("vhost read failed: %v", readErr),
		}
	}
	if err := os.Remove(final); err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("vhost remove failed: %v", err),
		}
	}

	status, detail, failed := r.healthCheck()
	if failed {
		// Restore the removed vhost byte-for-byte.
		_ = os.WriteFile(final, prev, 0o644)
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "health check failed; vhost removal rolled back: " + detail,
		}
	}

	entry := r.deps.WAL.NewEntry("nginx.remove_vhost", map[string]any{
		"domain": p.Domain, "health_check": status,
	})
	_ = r.deps.WAL.Append(entry)
	return vhostOpResult{Status: "removed", HealthCheck: status, HealthDetail: detail, PreviousExisted: true}, auditQueued(entry), nil
}

// nginxTest runs the health check on demand.
func (r *Registry) nginxTest(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	status, detail, failed := r.healthCheck()
	if failed {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "nginx config test failed: " + detail,
		}
	}
	return simpleStatus{Status: status, Detail: detail}, nil, nil
}

// nginxReload gracefully reloads nginx. Skipped (with reason) when no
// binary is present — a dev node cannot reload what it does not have.
func (r *Registry) nginxReload(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	bin := r.deps.NginxBinary
	if bin == "" {
		found, err := exec.LookPath("nginx")
		if err != nil {
			return simpleStatus{Status: "skipped", Detail: "nginx binary not found on this node"}, nil, nil
		}
		bin = found
	}
	out, err := exec.Command(bin, "-s", "reload").CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if len(trimmed) > 400 {
			trimmed = trimmed[:397] + "..."
		}
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "nginx reload failed: " + trimmed,
		}
	}
	entry := r.deps.WAL.NewEntry("nginx.reload", map[string]any{"status": "reloaded"})
	_ = r.deps.WAL.Append(entry)
	return simpleStatus{Status: "reloaded"}, auditQueued(entry), nil
}
