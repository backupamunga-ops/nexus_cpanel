package commands

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// filesystem.* content operations (ADR-0008 amendment to agent spec §4.3).
//
// The spec's §4.3 note routes file content through "the control plane's
// file service" — but the bytes live on the node, and the agent is the only
// I/O path into a hosting account. ADR-0008 therefore amends §4.3 with
// filesystem.list/read/write/move/restore/usage/purge: the control-plane
// file service ORCHESTRATES (permissions, ownership, trash rows, audit),
// the agent EXECUTES. Every path is confined (confineUnderHome, C13 round
// 2), every content payload is size-capped and base64-transported, and
// everything lands in the WAL.
//
// filesystem.chown stays out: handing arbitrary uid/gid to a signed command
// is a P4 privileged-operation decision with its own story.

const (
	maxListEntries   = 2000
	maxContentBytes  = 10 << 20 // 10 MiB per read/write — the manager edits, not torrents
	maxWalkEntries   = 200_000  // usage/inodes walk cap; partial flag when hit
	trashDirName     = ".nexus-trash"
	trashTimeLayout  = "20060102T150405.000000000"
	defaultFileMode  = 0o644
	defaultDirModeFs = 0o755
)

// fsTarget resolves and confines a path parameter for an account.
func fsTarget(homeRoot, username, requested string) (string, error) {
	if !usernameRe.MatchString(username) || reservedNames[username] {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	path, err := confineUnderHome(homeRoot, username, requested)
	if err != nil {
		return "", err
	}
	if len(path) > maxPathLen {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path too long"}
	}
	return path, nil
}

// entryJSON is one filesystem.list row.
type entryJSON struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // dir | file | symlink | other
	SizeBytes  int64  `json:"size_bytes"`
	Mode       string `json:"mode"`
	ModifiedAt string `json:"modified_at"`
}

type listResult struct {
	Path    string      `json:"path"`
	Entries []entryJSON `json:"entries"`
	Total   int         `json:"total"` // may exceed len(entries) at the cap
}

func (r *Registry) filesystemList(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string `json:"username"`
		Path     string `json:"path"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := fsTarget(r.deps.HomeRoot, p.Username, p.Path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path does not exist"}
	}
	if !fi.IsDir() {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path is not a directory"}
	}

	dirEntries, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("readdir failed: %v", err)}
	}
	out := make([]entryJSON, 0, len(dirEntries))
	for _, de := range dirEntries {
		if len(out) >= maxListEntries {
			break
		}
		info, err := de.Info()
		if err != nil {
			continue // raced deletion — skip, the next listing tells the truth
		}
		out = append(out, entryJSON{
			Name:       de.Name(),
			Type:       fileTypeOf(info),
			SizeBytes:  info.Size(),
			Mode:       info.Mode().Perm().String(),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339Nano),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Type == "dir") != (out[j].Type == "dir") {
			return out[i].Type == "dir"
		}
		return out[i].Name < out[j].Name
	})

	res := listResult{Path: path, Entries: out, Total: len(dirEntries)}
	return res, nil, nil
}

func fileTypeOf(fi os.FileInfo) string {
	switch {
	case fi.IsDir():
		return "dir"
	case fi.Mode()&os.ModeSymlink != 0:
		return "symlink"
	case fi.Mode().IsRegular():
		return "file"
	default:
		return "other"
	}
}

type readResult struct {
	Path       string `json:"path"`
	SizeBytes  int64  `json:"size_bytes"`
	ContentB64 string `json:"content_b64"`
	Truncated  bool   `json:"truncated"`
}

// filesystemRead returns file bytes (base64). Reads are capped at
// maxContentBytes with an explicit truncated flag — a silent partial file
// would be worse than an error.
func (r *Registry) filesystemRead(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string `json:"username"`
		Path     string `json:"path"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := fsTarget(r.deps.HomeRoot, p.Username, p.Path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path does not exist"}
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "only regular files can be read"}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePermission, Message: "file is not readable"}
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, maxContentBytes+1)
	n, readErr := f.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("read failed: %v", readErr)}
	}
	truncated := n > maxContentBytes
	if truncated {
		n = maxContentBytes
	}
	return readResult{
		Path:       path,
		SizeBytes:  fi.Size(),
		ContentB64: base64.StdEncoding.EncodeToString(buf[:n]),
		Truncated:  truncated,
	}, nil, nil
}

type writeResult struct {
	Path         string `json:"path"`
	WrittenBytes int    `json:"written_bytes"`
	Overwritten  bool   `json:"overwritten"`
	Ownership    string `json:"ownership"`
}

// filesystemWrite stores file bytes (base64). The parent directory must
// already exist (explicit mkdir keeps creation deliberate); overwrite is
// opt-in; the file is chowned to the account user after the atomic swap.
func (r *Registry) filesystemWrite(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username   string  `json:"username"`
		Path       string  `json:"path"`
		ContentB64 string  `json:"content_b64"`
		Mode       *uint32 `json:"mode"`
		Overwrite  bool    `json:"overwrite"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := fsTarget(r.deps.HomeRoot, p.Username, p.Path)
	if err != nil {
		return nil, nil, err
	}
	content, err := base64.StdEncoding.DecodeString(p.ContentB64)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "content_b64 is not valid base64"}
	}
	if len(content) > maxContentBytes {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: fmt.Sprintf("content exceeds the %d byte cap", maxContentBytes),
		}
	}

	mode := uint32(defaultFileMode)
	if p.Mode != nil {
		mode = *p.Mode
		if mode > maxFileMode {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: fmt.Sprintf("mode must be <= 0%o", maxFileMode),
			}
		}
	}

	parent := filepath.Dir(path)
	if fi, err := os.Lstat(parent); err != nil || !fi.IsDir() {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "parent directory does not exist (mkdir first)"}
	}
	_, overwritten := os.Lstat(path)
	if overwritten == nil && !p.Overwrite {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "path exists (overwrite not requested)"}
	}

	staging := path + ".nexus-staging"
	if err := os.WriteFile(staging, content, os.FileMode(mode)); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("staging write failed: %v", err)}
	}
	if err := os.Rename(staging, path); err != nil {
		_ = os.Remove(staging)
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("atomic swap failed: %v", err)}
	}
	ownership, err := chownToUserBestEffort(path, p.Username)
	if err != nil {
		_ = os.Remove(path)
		return nil, nil, err
	}

	entry := r.deps.WAL.NewEntry("filesystem.write", map[string]any{
		"username": p.Username, "path": safePathSummary(path),
		"bytes": len(content), "overwritten": overwritten == nil, "ownership": ownership,
	})
	_ = r.deps.WAL.Append(entry)
	return writeResult{Path: path, WrittenBytes: len(content), Overwritten: overwritten == nil, Ownership: ownership}, auditQueued(entry), nil
}

type moveResult struct {
	From      string `json:"from"`
	To        string `json:"to"`
	TrashPath string `json:"trash_path,omitempty"`
}

// filesystemMove renames within the account (trash restore, /files/move).
// Both endpoints are confined; the trash dir is inside the home, so restore
// needs no special case. Overwrite is opt-in, mirroring write.
func (r *Registry) filesystemMove(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username  string `json:"username"`
		From      string `json:"from"`
		To        string `json:"to"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	from, err := fsTarget(r.deps.HomeRoot, p.Username, p.From)
	if err != nil {
		return nil, nil, err
	}
	to, err := fsTarget(r.deps.HomeRoot, p.Username, p.To)
	if err != nil {
		return nil, nil, err
	}
	if from == to {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "source and destination are the same"}
	}
	if _, err := os.Lstat(from); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "source does not exist"}
	}
	if _, err := os.Lstat(to); err == nil && !p.Overwrite {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "destination exists (overwrite not requested)"}
	}
	if err := os.MkdirAll(filepath.Dir(to), defaultDirModeFs); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("destination mkdir failed: %v", err)}
	}
	if err := os.Rename(from, to); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("move failed: %v", err)}
	}

	entry := r.deps.WAL.NewEntry("filesystem.move", map[string]any{
		"username": p.Username,
		"from":     safePathSummary(from),
		"to":       safePathSummary(to),
	})
	_ = r.deps.WAL.Append(entry)
	return moveResult{From: from, To: to}, auditQueued(entry), nil
}

type deleteResult struct {
	Path      string `json:"path"`
	TrashPath string `json:"trash_path"`
	SizeBytes int64  `json:"size_bytes"`
	Purged    bool   `json:"purged"` // true when hard-deleted (to_trash=false)
}

// filesystemDelete (agent spec §4.3) — to_trash moves the path into
// /home/<user>/.nexus-trash/<timestamp>-<name>; hard delete is explicit
// (to_trash=false) and the control plane only uses it for trash purging.
func (r *Registry) filesystemDelete(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string `json:"username"`
		Path     string `json:"path"`
		ToTrash  *bool  `json:"to_trash"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	path, err := fsTarget(r.deps.HomeRoot, p.Username, p.Path)
	if err != nil {
		return nil, nil, err
	}
	home := filepath.Join(filepath.Clean(r.deps.HomeRoot), p.Username)
	if path == home {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "refusing to delete the account home"}
	}
	if filepath.Base(path) == trashDirName {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "refusing to delete the trash root"}
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path does not exist"}
	}
	size := treeSize(path, fi)

	if p.ToTrash == nil || *p.ToTrash {
		trashDir := filepath.Join(home, trashDirName)
		if err := os.MkdirAll(trashDir, 0o700); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("trash mkdir failed: %v", err)}
		}
		name := fmt.Sprintf("%s-%s", time.Now().UTC().Format(trashTimeLayout), filepath.Base(path))
		trashPath := filepath.Join(trashDir, name)
		if err := os.Rename(path, trashPath); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("trash move failed: %v", err)}
		}
		entry := r.deps.WAL.NewEntry("filesystem.delete", map[string]any{
			"username": p.Username, "path": safePathSummary(path),
			"trash_path": safePathSummary(trashPath), "size_bytes": size,
		})
		_ = r.deps.WAL.Append(entry)
		return deleteResult{Path: path, TrashPath: trashPath, SizeBytes: size}, auditQueued(entry), nil
	}

	if err := os.RemoveAll(path); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("delete failed: %v", err)}
	}
	entry := r.deps.WAL.NewEntry("filesystem.delete", map[string]any{
		"username": p.Username, "path": safePathSummary(path), "purged": true, "size_bytes": size,
	})
	_ = r.deps.WAL.Append(entry)
	return deleteResult{Path: path, TrashPath: "", SizeBytes: size, Purged: true}, auditQueued(entry), nil
}

// treeSize sums file sizes under a path (capped walk; directories report
// their own entry count via a separate mechanism if it ever matters).
func treeSize(path string, fi os.FileInfo) int64 {
	if !fi.IsDir() {
		return fi.Size()
	}
	var total int64
	count := 0
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries contribute nothing we can know
		}
		count++
		if count > maxWalkEntries {
			return filepath.SkipAll
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

type chmodResult struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// filesystemChmod (agent spec §4.3) — permission bits only, ≤ 0o777, no
// special bits: panel chmod is for web files, not for setuid games.
func (r *Registry) filesystemChmod(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string  `json:"username"`
		Path     string  `json:"path"`
		Mode     *uint32 `json:"mode"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if p.Mode == nil || *p.Mode == 0 || *p.Mode > maxFileMode {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "mode must be 1..0777"}
	}
	path, err := fsTarget(r.deps.HomeRoot, p.Username, p.Path)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, os.FileMode(*p.Mode)); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("chmod failed: %v", err)}
	}
	entry := r.deps.WAL.NewEntry("filesystem.chmod", map[string]any{
		"username": p.Username, "path": safePathSummary(path), "mode": fmt.Sprintf("%04o", *p.Mode),
	})
	_ = r.deps.WAL.Append(entry)
	return chmodResult{Path: path, Mode: fmt.Sprintf("%04o", *p.Mode)}, auditQueued(entry), nil
}

type fsUsageResult struct {
	Bytes   int64 `json:"bytes"`
	Inodes  int64 `json:"inodes"`
	Partial bool  `json:"partial"` // true when the walk hit the entry cap
}

// filesystemUsage (agent spec §4.3) — {bytes, inodes} over the account home.
func (r *Registry) filesystemUsage(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string `json:"username"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	home := filepath.Join(filepath.Clean(r.deps.HomeRoot), p.Username)
	fi, err := os.Lstat(home)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "account home does not exist"}
	}

	var bytes, inodes int64
	partial := false
	count := 0
	if fi.IsDir() {
		_ = filepath.WalkDir(home, func(_ string, d os.DirEntry, err error) error {
			count++
			if count > maxWalkEntries {
				partial = true
				return filepath.SkipAll
			}
			if err != nil {
				return nil
			}
			inodes++
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				bytes += info.Size()
			}
			return nil
		})
	}
	return fsUsageResult{Bytes: bytes, Inodes: inodes, Partial: partial}, nil, nil
}

type purgeResult struct {
	Removed []string `json:"removed"`
}

// trashPurge removes .nexus-trash entries older than before_date. The
// control plane owns the trash_entries ledger and reconciles it against the
// returned removed list — the agent reports exactly what it removed.
func (r *Registry) trashPurge(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username   string `json:"username"`
		BeforeDate string `json:"before_date"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	before, err := time.Parse(time.RFC3339, p.BeforeDate)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "before_date must be RFC3339"}
	}
	home := filepath.Join(filepath.Clean(r.deps.HomeRoot), p.Username)
	trashDir := filepath.Join(home, trashDirName)

	removed := []string{}
	dirEntries, err := os.ReadDir(trashDir)
	if err != nil {
		// No trash dir: nothing to purge is a success.
		return purgeResult{Removed: removed}, nil, nil
	}
	for _, de := range dirEntries {
		name := de.Name()
		ts, err := time.Parse(trashTimeLayout, trashTimestampOf(name))
		if err != nil {
			continue // not panel-managed naming — leave it alone
		}
		if !ts.Before(before) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(trashDir, name)); err != nil {
			continue // reported absent from the removed list; ledger reconciles
		}
		removed = append(removed, name)
	}

	entry := r.deps.WAL.NewEntry("filesystem.trash_purge", map[string]any{
		"username": p.Username, "removed": len(removed), "before": p.BeforeDate,
	})
	_ = r.deps.WAL.Append(entry)
	return purgeResult{Removed: removed}, auditQueued(entry), nil
}

// trashTimestampOf extracts the leading timestamp token from a trash name
// ("<layout>-<original name>"). The layout is exactly 25 chars
// (20060102T150405.000000000). Returns "" for non-panel names.
func trashTimestampOf(name string) string {
	if len(name) < 26 || name[25] != '-' {
		return ""
	}
	return name[:25]
}
