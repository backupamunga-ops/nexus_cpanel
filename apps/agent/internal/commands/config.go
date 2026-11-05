package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// config.* (agent spec §4.5) — the inspection half of the configuration
// engine. The apply half already exists as nginx.apply_vhost /
// php.*_pool with their health gates and auto-rollback; rollback of a
// version is the control plane re-applying stored bytes through those
// commands (it owns the version history — the agent never stores one).
//
// What the agent uniquely knows is THE DISK:
//
//   - config.validate: static syntax checks per target type, so bad config
//     is rejected before it ever reaches a staging write.
//   - config.drift_check: hash of the file on disk vs the expected content
//     the control plane supplies from its active version record. The agent
//     REPORTS drift (§P.7 constitutional rule) — it never silently
//     overwrites.
//   - config.list_active: the current file content for a target.
//
// config.render stays unimplemented deliberately: rendering is
// deterministic and panel-owned (sites.service renderVhost), and a second
// renderer would be two sources of truth for the same bytes.

type configValidateResult struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

type configValidateParams struct {
	TargetType string `json:"target_type"`
	Content    string `json:"content"`
}

// validateNginxConf is a pragmatic structural check: balanced braces,
// non-empty server block, no stray control characters. It is NOT nginx -t
// (that is the health gate at apply time with the real binary); this is
// the cheap pre-flight the control plane can run before staging anything.
func validateNginxConf(content string) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("empty configuration")
	}
	if strings.ContainsRune(content, 0) {
		return fmt.Errorf("NUL byte in configuration")
	}
	depth := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, r := range trimmed {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					return fmt.Errorf("unbalanced braces (extra '}' before line %q)", trimmed)
				}
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced braces (%d unclosed)", depth)
	}
	return nil
}

// validatePhpPoolConf checks the INI-style pool syntax: one section
// header, key = value lines, no NUL bytes.
func validatePhpPoolConf(content string) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("empty pool configuration")
	}
	if strings.ContainsRune(content, 0) {
		return fmt.Errorf("NUL byte in pool configuration")
	}
	sections := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if !strings.HasSuffix(trimmed, "]") || len(trimmed) < 3 {
				return fmt.Errorf("malformed section header: %q", trimmed)
			}
			sections++
			continue
		}
		if !strings.Contains(trimmed, "=") {
			return fmt.Errorf("pool line is neither comment, section nor key=value: %q", trimmed)
		}
	}
	if sections != 1 {
		return fmt.Errorf("pool configuration must contain exactly one section, found %d", sections)
	}
	return nil
}

func (r *Registry) configValidate(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p configValidateParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if len(p.Content) > maxVhostBytes {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "content exceeds the size cap"}
	}
	var err error
	switch p.TargetType {
	case "nginx_vhost":
		err = validateNginxConf(p.Content)
	case "php_pool":
		err = validatePhpPoolConf(p.Content)
	default:
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "target_type must be nginx_vhost | php_pool (more targets land with their features)",
		}
	}
	if err != nil {
		return configValidateResult{Valid: false, Error: err.Error()}, nil, nil
	}
	return configValidateResult{Valid: true}, nil, nil
}

type driftCheckParams struct {
	TargetType      string `json:"target_type"`
	TargetName      string `json:"target_name"` // file stem: the FQDN
	ExpectedContent string `json:"expected_content"`
}

type driftCheckResult struct {
	Matches      bool   `json:"matches"`
	Exists       bool   `json:"exists"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`
	FilePath     string `json:"file_path"`
}

// targetFile maps (target_type, name) to the managed file. The FQDN regex
// makes the stem a safe filename; no other target shapes exist yet.
func (r *Registry) targetFile(targetType, name string) (string, error) {
	if !fqdnRe.MatchString(name) || len(name) > 253 {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid target_name (want the FQDN)"}
	}
	switch targetType {
	case "nginx_vhost":
		return filepath.Join(r.deps.VhostRoot, name+vhostExt), nil
	case "php_pool":
		return "", &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "php_pool drift checks need a version; use the vhost target or wait for the pool-target amendment",
		}
	default:
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "target_type must be nginx_vhost | php_pool"}
	}
}

func (r *Registry) configDriftCheck(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p driftCheckParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := r.targetFile(p.TargetType, p.TargetName)
	if err != nil {
		return nil, nil, err
	}
	expectedSum := sha256.Sum256([]byte(p.ExpectedContent))
	expectedHash := hex.EncodeToString(expectedSum[:])

	actual, err := os.ReadFile(path)
	if err != nil {
		return driftCheckResult{
			Matches: false, Exists: false,
			ExpectedHash: expectedHash, ActualHash: "", FilePath: path,
		}, nil, nil
	}
	actualSum := sha256.Sum256(actual)
	actualHash := hex.EncodeToString(actualSum[:])
	return driftCheckResult{
		Matches:      actualHash == expectedHash,
		Exists:       true,
		ExpectedHash: expectedHash,
		ActualHash:   actualHash,
		FilePath:     path,
	}, nil, nil
}

type listActiveResult struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Exists     bool   `json:"exists"`
	Content    string `json:"content,omitempty"`
	FilePath   string `json:"file_path"`
}

func (r *Registry) configListActive(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p driftCheckParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := r.targetFile(p.TargetType, p.TargetName)
	if err != nil {
		return nil, nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return listActiveResult{TargetType: p.TargetType, TargetName: p.TargetName, Exists: false, FilePath: path}, nil, nil
	}
	return listActiveResult{
		TargetType: p.TargetType, TargetName: p.TargetName,
		Exists: true, Content: string(content), FilePath: path,
	}, nil, nil
}
