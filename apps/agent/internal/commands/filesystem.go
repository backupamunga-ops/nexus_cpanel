package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// filesystem.* (agent spec §4.3) — metadata and permission operations on
// hosting-account files. P3 slice: filesystem.mkdir (site document roots).
//
// Spec note: file CONTENT operations (upload/download/edit) are orchestrated
// by the control plane's file service; the agent handles metadata and
// permission ops. filesystem.list/read/write land with the file-service
// amendment (ADR-0008) — they are NOT silently added here.
//
// Every path is confined to the account home (C13). Round-2 confinement
// (confineUnderHome) walks the EXISTING prefix with symlink resolution, so
// a symlink planted anywhere between the home root and the target cannot
// redirect a privileged write outside the account.

const (
	maxPathLen     = 4000
	maxFileMode    = 0o777
	defaultDirMode = 0o755
)

type mkdirParams struct {
	Username string  `json:"username"`
	Path     string  `json:"path"`
	Mode     *uint32 `json:"mode"`
	Owner    string  `json:"owner"`
}

type mkdirResult struct {
	Path      string `json:"path"`
	Created   bool   `json:"created"`
	Ownership string `json:"ownership"`
}

// filesystemMkdir creates a directory (and parents) inside the account's
// home. Idempotent: an existing directory answers {created:false}; an
// existing non-directory is a conflict, never silently replaced.
func (r *Registry) filesystemMkdir(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p mkdirParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}

	// Owner is the account user, full stop. Chowning panel-created paths to
	// arbitrary users is a P4 privileged operation with its own audit story.
	if p.Owner != "" && p.Owner != p.Username {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "owner must be the account user (arbitrary chown is not permitted)",
		}
	}

	mode := uint32(defaultDirMode)
	if p.Mode != nil {
		mode = *p.Mode
		if mode > maxFileMode {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: fmt.Sprintf("mode must be <= 0%o", maxFileMode),
			}
		}
	}

	path, err := confineUnderHome(r.deps.HomeRoot, p.Username, p.Path)
	if err != nil {
		return nil, nil, err
	}
	if len(path) > maxPathLen {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path too long"}
	}

	if fi, err := os.Lstat(path); err == nil {
		if !fi.IsDir() {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeConflict,
				Message: "path exists and is not a directory",
			}
		}
		entry := r.deps.WAL.NewEntry("filesystem.mkdir", map[string]any{
			"username": p.Username, "path": path, "created": false,
		})
		_ = r.deps.WAL.Append(entry)
		return mkdirResult{Path: path, Created: false, Ownership: "existing"}, auditQueued(entry), nil
	}

	if err := os.MkdirAll(path, os.FileMode(mode)); err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("mkdir failed: %v", err),
		}
	}
	ownership, err := chownToUserBestEffort(path, p.Username)
	if err != nil {
		// Root agent + failed ownership: the directory exists but is
		// root-owned — unusable by the account. Fail loudly and clean up.
		_ = os.RemoveAll(path)
		return nil, nil, err
	}

	entry := r.deps.WAL.NewEntry("filesystem.mkdir", map[string]any{
		"username": p.Username, "path": path, "mode": mode, "created": true, "ownership": ownership,
	})
	_ = r.deps.WAL.Append(entry)
	return mkdirResult{Path: path, Created: true, Ownership: ownership}, auditQueued(entry), nil
}

// chownToUser hands a path to the account's uid/gid.
func chownToUser(path, username string) error {
	uid, gid, ok := lookupUser(username)
	if !ok {
		return &rpc.RPCError{Code: rpc.CodePrecondition, Message: "account does not exist"}
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("chown %s failed: %v", filepath.Base(path), err),
		}
	}
	return nil
}

// chownToUserBestEffort is the ownership policy for panel-created files in
// filesystem.write/mkdir: on a root agent (production) ownership is mandatory
// — a root-owned docroot/file the account cannot write is fail-open, so any
// miss fails loudly. On an unprivileged agent (dev rigs, CI) ownership is
// structurally impossible, so it is SKIPPED WITH A REPORTED REASON — the
// same honesty contract as the nginx health check.
func chownToUserBestEffort(path, username string) (ownership string, err error) {
	uid, gid, ok := lookupUser(username)
	if !ok {
		if os.Geteuid() == 0 {
			return "", &rpc.RPCError{Code: rpc.CodePrecondition, Message: "account does not exist"}
		}
		return "skipped: user lookup unavailable (not running as root)", nil
	}
	if err := os.Chown(path, uid, gid); err != nil {
		if os.Geteuid() != 0 {
			return "skipped: chown requires root (not running as root)", nil
		}
		return "", &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("chown %s failed: %v", filepath.Base(path), err),
		}
	}
	return "account-owned", nil
}

// safePathSummary collapses user-controlled paths for audit metadata.
func safePathSummary(path string) string {
	if len(path) > 256 {
		return path[:253] + "..."
	}
	return strings.ReplaceAll(path, "\n", " ")
}
