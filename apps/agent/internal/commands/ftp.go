package commands

import (
        "crypto/rand"
        "encoding/hex"
        "encoding/json"
        "errors"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "regexp"
        "sort"
        "strings"

        "github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// ftp.* (ADR-0011 amendment to agent spec §4) — vsftpd virtual users.
//
// The panel owns the registry (file_accounts); the agent owns the machine
// state that makes those logins real:
//
//   - one per-user config file per FTP login (<config_dir>/<ftp_username>):
//     local_root (confined to the owning account's home), write_enable,
//     local_umask — the vsftpd user_config_dir convention;
//   - a pam_userdb source file (<userdb>.source, "user\nhash\n…" pairs) and
//     the BerkeleyDB built from it via db_load — the hash is SHA-512-crypt
//     produced by `openssl passwd -6` (binary precondition-checked; dev
//     rigs without it get an honest skipped-rebuild result, never a silent
//     one: the response states whether logins can authenticate).
//
// Passwords travel only over the signed, local, mTLS command channel and
// are hashed immediately; they are never written to disk or the WAL.
// Every mutation rebuilds the DB; a failed rebuild fails the command
// loudly (the source file is the recovery artifact).

const (
        maxFtpPasswordBytes = 1024
        minFtpPasswordLen   = 8
        ftpConfigFileMode   = 0o644 // read by vsftpd running as root
        ftpSourceFileMode   = 0o600 // contains password hashes
        ftpVuserRe          = `^[a-z0-9][a-z0-9._-]{0,62}$`
        ftpUserdbDetailCap  = 400
)

var ftpUsernameRe = regexp.MustCompile(ftpVuserRe)

type ftpUserdbResult struct {
        Rebuilt bool   `json:"rebuilt"`
        Skipped string `json:"skipped,omitempty"` // reason when not rebuilt (dev rig)
}

type ftpOpResult struct {
        Status          string         `json:"status"` // created | updated | removed | absent
        RootDir         string         `json:"root_dir,omitempty"`
        ReadOnly        bool           `json:"read_only,omitempty"`
        Ownership       string         `json:"ownership,omitempty"`
        Userdb          ftpUserdbResult `json:"userdb"`
}

type ftpAccountEntry struct {
        Username string `json:"username"`
        RootDir  string `json:"root_dir"`
        ReadOnly bool   `json:"read_only"`
}

// opensslSha512Crypt hashes a password into a $6$ crypt string. Binary
// resolution: Deps override (tests), then LookPath. Missing binary is a
// precondition error — hashing is not optional for a login.
func (r *Registry) opensslSha512Crypt(password string) (string, error) {
        bin := r.deps.OpensslBinary
        if bin == "" {
                found, err := exec.LookPath("openssl")
                if err != nil {
                        return "", &rpc.RPCError{
                                Code:    rpc.CodePrecondition,
                                Message: "openssl binary not found on this node — cannot hash FTP passwords",
                        }
                }
                bin = found
        }
        saltRaw := make([]byte, 8)
        if _, err := rand.Read(saltRaw); err != nil {
                return "", &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("salt generation failed: %v", err)}
        }
        salt := hex.EncodeToString(saltRaw)
        cmd := exec.Command(bin, "passwd", "-6", "-salt", salt, "-stdin")
        cmd.Stdin = strings.NewReader(password + "\n")
        out, err := cmd.Output()
        if err != nil {
                trimmed := strings.TrimSpace(err.Error())
                if ee, ok := err.(*exec.ExitError); ok {
                        trimmed = strings.TrimSpace(string(ee.Stderr))
                }
                if len(trimmed) > ftpUserdbDetailCap {
                        trimmed = trimmed[:ftpUserdbDetailCap-3] + "..."
                }
                return "", &rpc.RPCError{Code: rpc.CodeInternalError, Message: "password hashing failed: " + trimmed}
        }
        hash := strings.TrimSpace(string(out))
        if !strings.HasPrefix(hash, "$6$") {
                return "", &rpc.RPCError{Code: rpc.CodeInternalError, Message: "openssl produced an unexpected hash format"}
        }
        return hash, nil
}

func (r *Registry) ftpValidateOwner(owner string) error {
        if !usernameRe.MatchString(owner) || reservedNames[owner] {
                return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid owner username"}
        }
        return nil
}

// ftpSourcePath returns the userdb source file path and its parsed
// "user -> hash" map. The file is the source of truth for rebuilds.
func (r *Registry) ftpSourcePath() (string, map[string]string) {
        path := r.deps.FtpUserDbPath
        if path == "" {
                path = "/etc/vsftpd/nexuspanel-vusers"
        }
        entries := map[string]string{}
        if b, err := os.ReadFile(path + ".source"); err == nil {
                lines := strings.Split(string(b), "\n")
                for i := 0; i+1 < len(lines); i += 2 {
                        if lines[i] != "" {
                                entries[lines[i]] = lines[i+1]
                        }
                }
        }
        return path, entries
}

// ftpWriteUserdb persists the source file and rebuilds the BerkeleyDB.
// A missing db_load is reported (skipped), not fatal: the panel displays
// it and the next mutation on a node with db_load heals the DB.
func (r *Registry) ftpWriteUserdb(entries map[string]string) (ftpUserdbResult, error) {
        path := r.deps.FtpUserDbPath
        if path == "" {
                path = "/etc/vsftpd/nexuspanel-vusers"
        }
        users := make([]string, 0, len(entries))
        for u := range entries {
                users = append(users, u)
        }
        sort.Strings(users)
        var b strings.Builder
        for _, u := range users {
                b.WriteString(u)
                b.WriteByte('\n')
                b.WriteString(entries[u])
                b.WriteByte('\n')
        }
        if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
                return ftpUserdbResult{}, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("userdb dir create failed: %v", err)}
        }
        if err := os.WriteFile(path+".source", []byte(b.String()), ftpSourceFileMode); err != nil {
                return ftpUserdbResult{}, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("userdb source write failed: %v", err)}
        }

        dbload := r.deps.DbLoadBinary
        if dbload == "" {
                found, err := exec.LookPath("db_load")
                if err != nil {
                        return ftpUserdbResult{Rebuilt: false, Skipped: "db_load binary not found — virtual-user DB not rebuilt; logins cannot authenticate until it is"}, nil
                }
                dbload = found
        }
        out, err := exec.Command(dbload, "-T", "-t", "hash", "-f", path+".source", path).CombinedOutput()
        if err != nil {
                trimmed := strings.TrimSpace(string(out))
                if len(trimmed) > ftpUserdbDetailCap {
                        trimmed = trimmed[:ftpUserdbDetailCap-3] + "..."
                }
                return ftpUserdbResult{}, &rpc.RPCError{
                        Code:    rpc.CodePrecondition,
                        Message: "db_load failed: " + trimmed,
                }
        }
        return ftpUserdbResult{Rebuilt: true}, nil
}

// ftpConfigPath resolves the per-user vsftpd config path for a login.
func (r *Registry) ftpConfigPath(ftpUsername string) string {
        dir := r.deps.FtpConfigDir
        if dir == "" {
                dir = "/etc/vsftpd/nexuspanel-users"
        }
        return filepath.Join(dir, ftpUsername)
}

// ftpWriteConfig writes the per-user vsftpd config (atomic, staged).
func ftpWriteConfig(path string, rootDir string, readOnly bool) error {
        writeEnable := "yes"
        if readOnly {
                writeEnable = "no"
        }
        content := "# managed by nexuspanel — do not edit\n" +
                "local_root=" + rootDir + "\n" +
                "write_enable=" + writeEnable + "\n" +
                "local_umask=022\n"
        staging := path + ".nexus-staging"
        if err := os.WriteFile(staging, []byte(content), ftpConfigFileMode); err != nil {
                return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("staging write failed: %v", err)}
        }
        if err := os.Rename(staging, path); err != nil {
                _ = os.Remove(staging)
                return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("atomic swap failed: %v", err)}
        }
        return nil
}

// ftpCreateAccount provisions a vsftpd virtual user for an account.
func (r *Registry) ftpCreateAccount(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                OwnerUsername string `json:"owner_username"`
                FtpUsername   string `json:"ftp_username"`
                Password      string `json:"password"`
                RootDir       string `json:"root_dir"`
                ReadOnly      bool   `json:"read_only"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if err := r.ftpValidateOwner(p.OwnerUsername); err != nil {
                return nil, nil, err
        }
        if !ftpUsernameRe.MatchString(p.FtpUsername) || p.FtpUsername == "" {
                return nil, nil, &rpc.RPCError{
                        Code:    rpc.CodeInvalidParams,
                        Message: "invalid ftp_username (lowercase letters, digits, dot, dash, underscore; 1-63 chars)",
                }
        }
        if len(p.Password) < minFtpPasswordLen || len(p.Password) > maxFtpPasswordBytes || strings.ContainsRune(p.Password, 0) {
                return nil, nil, &rpc.RPCError{
                        Code:    rpc.CodeInvalidParams,
                        Message: fmt.Sprintf("password must be %d-%d bytes", minFtpPasswordLen, maxFtpPasswordBytes),
                }
        }
        rootDir, err := fsTarget(r.deps.HomeRoot, p.OwnerUsername, p.RootDir)
        if err != nil {
                return nil, nil, err
        }
        if fi, lerr := os.Lstat(rootDir); lerr != nil || !fi.IsDir() {
                return nil, nil, &rpc.RPCError{
                        Code:    rpc.CodeInvalidParams,
                        Message: "root_dir does not exist or is not a directory (create it first)",
                }
        }

        cfgPath := r.ftpConfigPath(p.FtpUsername)
        if _, err := os.Lstat(cfgPath); err == nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "ftp account already exists"}
        }

        hash, err := r.opensslSha512Crypt(p.Password)
        if err != nil {
                return nil, nil, err
        }
        if err := ftpWriteConfig(cfgPath, rootDir, p.ReadOnly); err != nil {
                return nil, nil, err
        }
        _, entries := r.ftpSourcePath()
        entries[p.FtpUsername] = hash
        userdb, err := r.ftpWriteUserdb(entries)
        if err != nil {
                _ = os.Remove(cfgPath) // do not leave a config for a login that cannot authenticate
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("ftp.create_account", map[string]any{
                "owner": p.OwnerUsername, "ftp_username": p.FtpUsername,
                "root_dir": safePathSummary(rootDir), "read_only": p.ReadOnly,
                "userdb_rebuilt": userdb.Rebuilt,
        })
        _ = r.deps.WAL.Append(entry)
        return ftpOpResult{
                Status:   "created",
                RootDir:  rootDir,
                ReadOnly: p.ReadOnly,
                Userdb:   userdb,
        }, auditQueued(entry), nil
}

// ftpDeleteAccount removes the login's config and userdb entry. Absent is
// a success (desired state already met) and still WAL-audited.
func (r *Registry) ftpDeleteAccount(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                FtpUsername string `json:"ftp_username"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if !ftpUsernameRe.MatchString(p.FtpUsername) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid ftp_username"}
        }

        cfgPath := r.ftpConfigPath(p.FtpUsername)
        _, statErr := os.Lstat(cfgPath)

        _, entries := r.ftpSourcePath()
        _, inDb := entries[p.FtpUsername]
        if statErr != nil && !inDb {
                entry := r.deps.WAL.NewEntry("ftp.delete_account", map[string]any{
                        "ftp_username": p.FtpUsername, "absent": true,
                })
                _ = r.deps.WAL.Append(entry)
                return ftpOpResult{Status: "absent", Userdb: ftpUserdbResult{Rebuilt: false}}, auditQueued(entry), nil
        }

        delete(entries, p.FtpUsername)
        userdb, err := r.ftpWriteUserdb(entries)
        if err != nil {
                return nil, nil, err
        }
        if statErr == nil {
                if err := os.Remove(cfgPath); err != nil {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("config remove failed: %v", err)}
                }
        }

        entry := r.deps.WAL.NewEntry("ftp.delete_account", map[string]any{
                "ftp_username": p.FtpUsername, "userdb_rebuilt": userdb.Rebuilt,
        })
        _ = r.deps.WAL.Append(entry)
        return ftpOpResult{Status: "removed", Userdb: userdb}, auditQueued(entry), nil
}

// ftpSetPassword rotates a login's password (hash + userdb rebuild only).
func (r *Registry) ftpSetPassword(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                FtpUsername string `json:"ftp_username"`
                Password    string `json:"password"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if !ftpUsernameRe.MatchString(p.FtpUsername) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid ftp_username"}
        }
        if len(p.Password) < minFtpPasswordLen || len(p.Password) > maxFtpPasswordBytes || strings.ContainsRune(p.Password, 0) {
                return nil, nil, &rpc.RPCError{
                        Code:    rpc.CodeInvalidParams,
                        Message: fmt.Sprintf("password must be %d-%d bytes", minFtpPasswordLen, maxFtpPasswordBytes),
                }
        }
        _, entries := r.ftpSourcePath()
        if _, ok := entries[p.FtpUsername]; !ok {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "ftp account does not exist"}
        }
        hash, err := r.opensslSha512Crypt(p.Password)
        if err != nil {
                return nil, nil, err
        }
        entries[p.FtpUsername] = hash
        userdb, err := r.ftpWriteUserdb(entries)
        if err != nil {
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("ftp.set_password", map[string]any{
                "ftp_username": p.FtpUsername, "userdb_rebuilt": userdb.Rebuilt,
        })
        _ = r.deps.WAL.Append(entry)
        return ftpOpResult{Status: "updated", Userdb: userdb}, auditQueued(entry), nil
}

// ftpListAccounts reads the managed per-user configs. Read-only (§6).
func (r *Registry) ftpListAccounts(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        dir := r.deps.FtpConfigDir
        if dir == "" {
                dir = "/etc/vsftpd/nexuspanel-users"
        }
        dirEntries, err := os.ReadDir(dir)
        if errors.Is(err, os.ErrNotExist) {
                return ftpListResult{Accounts: []ftpAccountEntry{}}, nil, nil
        }
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("config dir read failed: %v", err)}
        }
        out := []ftpAccountEntry{}
        for _, de := range dirEntries {
                if de.IsDir() || strings.Contains(de.Name(), ".nexus-staging") {
                        continue
                }
                b, err := os.ReadFile(filepath.Join(dir, de.Name()))
                if err != nil {
                        continue // raced removal — the next listing tells the truth
                }
                rootDir, readOnly := "", false
                for _, line := range strings.Split(string(b), "\n") {
                        if strings.HasPrefix(line, "local_root=") {
                                rootDir = strings.TrimPrefix(line, "local_root=")
                        }
                        if strings.HasPrefix(line, "write_enable=") {
                                readOnly = strings.TrimPrefix(line, "write_enable=") == "no"
                        }
                }
                out = append(out, ftpAccountEntry{Username: de.Name(), RootDir: rootDir, ReadOnly: readOnly})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
        return ftpListResult{Accounts: out}, nil, nil
}

type ftpListResult struct {
        Accounts []ftpAccountEntry `json:"accounts"`
}
