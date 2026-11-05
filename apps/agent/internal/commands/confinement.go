package commands

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// C13 — Path confinement (security model §C13): "All file operations
// restricted to explicit path roots … Agent resolves paths against confined
// roots per operation type; rejects any resolved path outside."
//
// In M0 the confinement surface is account.create's homedir and shell: both
// arrive inside a signed command, and the signature only proves the control
// plane sent them — not that they are safe. The agent is the boundary.

// defaultHomeRoot is the only parent under which hosting-account home
// directories may live. Custom layouts (e.g. /srv/vhosts) require a
// confinement-roots amendment to the agent spec (registry preamble).
const defaultHomeRoot = "/home"

// allowedShells is the M0 login-shell allowlist. Hosting accounts are
// service identities; anything beyond the nologin shell is P2 work with its
// own amendment.
var allowedShells = map[string]bool{
	"/usr/sbin/nologin": true,
}

// confineHomeDir validates a requested home directory for username against
// the confined root. It returns the canonical path to use.
//
// Round 1 (this file) enforces, in order:
//  1. lexical: absolute, no NUL, no backslash; filepath.Clean must resolve
//     to exactly <root>/<username> (paths that merely resolve INTO the
//     confined location — "/home//./alice/", "/home/x/../alice" — pass;
//     anything resolving outside is rejected);
//  2. filesystem: if the parent chain already exists, its symlink-resolved
//     form must stay under the resolved root (blocks a planted
//     /home -> /etc symlink).
//
// Round 2 (P3, with filesystem.*) walks the full existing prefix.
func confineHomeDir(homedir, username, root string) (string, error) {
	if homedir == "" {
		homedir = filepath.Join(root, username)
	}
	if strings.ContainsRune(homedir, 0) {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "homedir contains NUL"}
	}
	if strings.ContainsRune(homedir, '\\') {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "homedir contains backslash"}
	}
	if !filepath.IsAbs(homedir) {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "homedir must be absolute"}
	}

	cleanRoot := filepath.Clean(root)
	want := filepath.Join(cleanRoot, username)
	got := filepath.Clean(homedir)
	if got != want {
		return "", &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "homedir escapes the confined root",
			Data:    map[string]any{"requested": got, "confined": want},
		}
	}

	// Symlink resolve of the deepest existing ancestor (best effort, round 1):
	// if an attacker pre-plants a symlink anywhere along the parent chain, the
	// resolved parent must still live under the resolved root.
	parent := filepath.Dir(got)
	if resolvedParent, err := filepath.EvalSymlinks(parent); err == nil {
		resolvedRoot, err2 := filepath.EvalSymlinks(cleanRoot)
		if err2 != nil {
			// Root itself missing is an operator problem, not confinement.
			resolvedRoot = cleanRoot
		}
		if resolvedParent != resolvedRoot &&
			!strings.HasPrefix(resolvedParent, resolvedRoot+string(filepath.Separator)) {
			return "", &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: "homedir parent resolves outside the confined root",
				Data:    map[string]any{"resolved_parent": resolvedParent},
			}
		}
	}
	return got, nil
}

// confineShell validates the requested login shell against the allowlist.
// An empty request means the default nologin shell.
func confineShell(shell string) (string, error) {
	if shell == "" {
		return "/usr/sbin/nologin", nil
	}
	if !allowedShells[shell] {
		return "", &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "shell is not in the allowlist",
			Data:    map[string]any{"shell": shell},
		}
	}
	return shell, nil
}

// existingSymlink reports whether path currently exists and is a symlink.
// useradd would place files through such a symlink; confineHomeDir's parent
// resolution catches the common cases, this is the direct final check.
func existingSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}
