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

// confineUnderHome is the round-2 path confinement for filesystem.* and
// config-engine writes inside an account's home (C13). It accepts absolute
// paths under <root>/<username> and relative paths resolved against that
// home, then walks the EXISTING prefix with symlink resolution: the deepest
// existing ancestor must resolve INSIDE the resolved home, so a planted
// symlink at any level (including the home root itself) cannot redirect the
// operation. Non-existent tails are safe: they can only be created after the
// parent chain has been re-validated by the kernel.
func confineUnderHome(root, username, requested string) (string, error) {
	if requested == "" {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path is required"}
	}
	if strings.ContainsRune(requested, 0) {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path contains NUL"}
	}
	if strings.ContainsRune(requested, '\\') {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path contains backslash"}
	}

	home := filepath.Join(filepath.Clean(root), username)
	p := requested
	if !filepath.IsAbs(p) {
		p = filepath.Join(home, p)
	}
	p = filepath.Clean(p)

	if p != home && !strings.HasPrefix(p, home+string(filepath.Separator)) {
		return "", &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "path escapes the account home",
			Data:    map[string]any{"requested": p, "confined": home},
		}
	}

	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		// Home itself missing (fresh account): no existing prefix can redirect
		// anything yet — fall back to the lexical form.
		resolvedHome = home
	}

	deepest := ""
	probe := p
	for {
		if _, err := os.Lstat(probe); err == nil {
			deepest = probe
			break
		}
		// Walk DOWN TO the home boundary only: everything at or above `home`
		// is panel-controlled topology (confinement root, account parent),
		// not attacker-planted. A fresh account has no existing prefix at
		// all — nothing below home exists, so there is nothing to resolve.
		if probe == home {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	if deepest != "" {
		resolved, err := filepath.EvalSymlinks(deepest)
		if err == nil &&
			resolved != resolvedHome &&
			!strings.HasPrefix(resolved, resolvedHome+string(filepath.Separator)) {
			return "", &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: "path resolves outside the account home",
				Data:    map[string]any{"resolved": resolved},
			}
		}
	}
	return p, nil
}
