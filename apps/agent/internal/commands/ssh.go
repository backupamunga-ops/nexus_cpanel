package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// ssh.* (ADR-0010 amendment to agent spec §4) — authorized_keys lifecycle.
//
// SSH public keys are IMPORTED panel-side (API spec §4.13, SHA-256
// fingerprint computed at import) and DEPLOYED to the account's
// ~/.ssh/authorized_keys here. Design invariants:
//
//   - Managed-key convention: every line the panel writes carries a
//     trailing ` nexus-managed:<fingerprint>` marker (a comment token as
//     far as sshd is concerned). deploy_keys rewrites ONLY managed lines
//     and preserves every foreign line verbatim — the panel can never
//     delete a key a user added by hand on the node, and it can never
//     claim (or silently keep) a key it did not deploy itself.
//   - Empty keys list = remove all managed keys; the file survives if
//     foreign keys remain (idempotent reconciliation, not a wipe).
//   - ~/.ssh is 0700, authorized_keys is 0600, both owned by the account
//     user via chownToUserBestEffort: mandatory on root agents, reported
//     skip on dev rigs — the result states which happened (D-11 honesty).
//   - The path is confined with the same fsTarget primitive as every
//     other content op; there is no way to address a file outside the
//     account home through this method.
//
// The fingerprint string is opaque to the agent (the control plane owns
// its format); it only has to be a single whitespace-free token so the
// managed line stays a valid OpenSSH entry.

const (
	sshDirMode        = 0o700
	sshFileMode       = 0o600
	maxAuthorizedKeys = 50 // a hosting account, not a shared bastion
	maxKeyLineBytes   = 8 << 10
	managedMarker     = " nexus-managed:"
)

// Same key-type allowlist as the panel-side import (sshkeys.service).
var sshKeyTypeRe = regexp.MustCompile(
	`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,2}(?: [^ \t\n].*)?$`)

type sshDeployKey struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}

type sshDeployResult struct {
	File         string `json:"file"`
	ManagedCount int    `json:"managed_count"`
	ForeignCount int    `json:"foreign_count"`
	Ownership    string `json:"ownership"`
}

type sshDeployedKey struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}

type sshListResult struct {
	File         string           `json:"file"`
	Exists       bool             `json:"exists"`
	Managed      []sshDeployedKey `json:"managed"`
	ForeignCount int              `json:"foreign_count"`
	Ownership    string           `json:"ownership,omitempty"`
}

// sshDeployKeys reconciles the managed lines of the account's
// authorized_keys with the provided key set (full replace of managed
// lines, foreign lines preserved).
func (r *Registry) sshDeployKeys(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string         `json:"username"`
		Keys     []sshDeployKey `json:"keys"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if len(p.Keys) > maxAuthorizedKeys {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: fmt.Sprintf("at most %d keys per deploy", maxAuthorizedKeys),
		}
	}

	seen := map[string]bool{}
	managed := make([]string, 0, len(p.Keys))
	for _, k := range p.Keys {
		key := strings.TrimSpace(k.PublicKey)
		fp := strings.TrimSpace(k.Fingerprint)
		if !sshKeyTypeRe.MatchString(key) || len(key) > maxKeyLineBytes {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: "public_key must be a single-line OpenSSH key (ed25519, rsa, ecdsa nistp256/384/521)",
			}
		}
		if fp == "" || strings.ContainsAny(fp, " \t\r\n") {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: "fingerprint must be a single token (SHA256:... from the panel import)",
			}
		}
		if seen[fp] {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeConflict,
				Message: "duplicate fingerprint in deploy set: " + fp,
			}
		}
		seen[fp] = true
		managed = append(managed, key+managedMarker+fp)
	}
	sort.Strings(managed)

	akPath, err := fsTarget(r.deps.HomeRoot, p.Username, ".ssh/authorized_keys")
	if err != nil {
		return nil, nil, err
	}
	sshDir := filepath.Dir(akPath)
	if err := os.MkdirAll(sshDir, sshDirMode); err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("ssh dir create failed: %v", err),
		}
	}
	dirOwnership, err := chownToUserBestEffort(sshDir, p.Username)
	if err != nil {
		return nil, nil, err
	}
	_ = os.Chmod(sshDir, sshDirMode) // reassert even if the dir pre-existed

	// Foreign lines survive untouched; managed lines are replaced wholesale.
	foreign := []string{}
	if b, readErr := os.ReadFile(akPath); readErr == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if !strings.Contains(line, managedMarker) {
				foreign = append(foreign, line)
			}
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("authorized_keys read failed: %v", readErr),
		}
	}

	lines := append(append([]string{}, foreign...), managed...)
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}

	staging := akPath + ".nexus-staging"
	if err := os.WriteFile(staging, []byte(content), sshFileMode); err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("staging write failed: %v", err),
		}
	}
	if err := os.Rename(staging, akPath); err != nil {
		_ = os.Remove(staging)
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("atomic swap failed: %v", err),
		}
	}
	ownership, err := chownToUserBestEffort(akPath, p.Username)
	if err != nil {
		_ = os.Remove(akPath)
		return nil, nil, err
	}
	_ = os.Chmod(akPath, sshFileMode)

	entry := r.deps.WAL.NewEntry("ssh.deploy_keys", map[string]any{
		"username": p.Username, "managed": len(managed), "foreign": len(foreign),
		"dir_ownership": dirOwnership, "ownership": ownership,
	})
	_ = r.deps.WAL.Append(entry)
	return sshDeployResult{
		File:         akPath,
		ManagedCount: len(managed),
		ForeignCount: len(foreign),
		Ownership:    ownership,
	}, auditQueued(entry), nil
}

// sshListDeployed reports what is actually in authorized_keys right now,
// split into panel-managed and foreign lines. Read-only (spec §6).
func (r *Registry) sshListDeployed(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string `json:"username"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	akPath, err := fsTarget(r.deps.HomeRoot, p.Username, ".ssh/authorized_keys")
	if err != nil {
		return nil, nil, err
	}

	b, readErr := os.ReadFile(akPath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("authorized_keys read failed: %v", readErr),
		}
	}
	ownership, _ := chownToUserBestEffort(akPath, p.Username)

	res := sshListResult{File: akPath, Exists: readErr == nil, Managed: []sshDeployedKey{}, Ownership: ownership}
	if readErr == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimRight(line, "\r")
			if strings.TrimSpace(line) == "" {
				continue
			}
			if i := strings.Index(line, managedMarker); i >= 0 {
				res.Managed = append(res.Managed, sshDeployedKey{
					Fingerprint: strings.TrimSpace(line[i+len(managedMarker):]),
					PublicKey:   strings.TrimSpace(line[:i]),
				})
			} else {
				res.ForeignCount++
			}
		}
	}
	return res, nil, nil
}
