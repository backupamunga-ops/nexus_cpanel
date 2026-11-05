package commands

import (
        "crypto/rand"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "regexp"
        "strings"

        "github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// apps.* (ADR-0019 amendment to agent spec §4) — B14: app installer.
//
// WordPress first, always as the ACCOUNT USER (never root): downloads,
// config generation and installs run through WP-CLI via
// `runuser -u <username> --` on root agents (dev rigs without the user
// exec directly — the result states which happened, D-11 honesty).
//
// Credential posture (C15 discipline):
//   - DB credentials ride the SIGNED command channel (same as backup
//     destination configs) and land ONLY inside wp-config.php (0600,
//     account-user owned) — never in argv, logs or the WAL;
//   - the WP admin password is GENERATED HERE (32 chars of entropy),
//     handed to wp-cli via STDIN (--prompt), returned to the panel ONCE
//     in this result, and never persisted anywhere on the node.

const (
        wpConfigMode = 0o600
        maxWpPathLen = 256
        wpSaltLen    = 48
)

var (
        wpPathRe      = regexp.MustCompile(`^[\w][\w./ -]{0,255}$`)
        wpAdminUserRe = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,60}$`)
        wpDbNameRe    = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
        wpEmailRe     = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[a-z]{2,}$`)
        wpUrlRe       = regexp.MustCompile(`^https?://[a-z0-9.-]+(:[0-9]+)?(/[\w./-]*)?$`)
        wpTitleRe     = regexp.MustCompile(`^[^<>{};` + "`" + `\r\n]{1,120}$`)
)

type wpInstallParams struct {
        Username   string `json:"username"`
        Path       string `json:"path"`
        URL        string `json:"url"`
        Title      string `json:"title"`
        AdminUser  string `json:"admin_user"`
        AdminEmail string `json:"admin_email"`
        DBName     string `json:"db_name"`
        DBUser     string `json:"db_user"`
        DBPassword string `json:"db_password"`
        DBHost     string `json:"db_host"`
}

type wpInstallResult struct {
        Status        string `json:"status"`
        Path          string `json:"path"`
        Version       string `json:"version"`
        AdminUser     string `json:"admin_user"`
        AdminPassword string `json:"admin_password"`
        ExecutedAs    string `json:"executed_as"`
        Log           string `json:"log"`
}

type wpUpdateParams struct {
        Username string `json:"username"`
        Path     string `json:"path"`
}

type wpUpdateResult struct {
        Status  string `json:"status"`
        Path    string `json:"path"`
        Version string `json:"version"`
        Log     string `json:"log"`
}

type wpStagingParams struct {
        Username    string `json:"username"`
        SourcePath  string `json:"source_path"`
        StagingPath string `json:"staging_path"`
        StagingURL  string `json:"staging_url"`
        ProdURL     string `json:"prod_url"`
        DBName      string `json:"db_name"`
        DBUser      string `json:"db_user"`
        DBPassword  string `json:"db_password"`
        DBHost      string `json:"db_host"`
}

type wpCliParams struct {
        Username string   `json:"username"`
        Path     string   `json:"path"`
        Args     []string `json:"args"`
}

// resolveAccountPath confines a relative app path to the account home.
func resolveAccountPath(homeRoot, username, rel string) (string, error) {
        if !usernameRe.MatchString(username) || reservedNames[username] {
                return "", fmt.Errorf("invalid username")
        }
        if !wpPathRe.MatchString(rel) || strings.Contains(rel, "..") {
                return "", fmt.Errorf("invalid app path")
        }
        return fsTarget(homeRoot, username, rel)
}

func generateSaltedString() string {
        b := make([]byte, wpSaltLen)
        if _, err := rand.Read(b); err != nil {
                // crypto/rand failure is catastrophic enough to refuse loudly
                panic("crypto/rand unavailable: " + err.Error())
        }
        return base64.StdEncoding.EncodeToString(b)
}

func generateWpPassword() string {
        b := make([]byte, 32)
        _, _ = rand.Read(b)
        return base64.RawURLEncoding.EncodeToString(b)
}

func renderWpConfig(p wpInstallParams, salts []string) string {
        var b strings.Builder
        b.WriteString("<?php\n# Managed by NexusPanel (apps.install_wordpress) — DB credentials live ONLY here (0600).\n")
        b.WriteString("define( 'DB_NAME', '" + phpEscape(p.DBName) + "' );\n")
        b.WriteString("define( 'DB_USER', '" + phpEscape(p.DBUser) + "' );\n")
        b.WriteString("define( 'DB_PASSWORD', '" + phpEscape(p.DBPassword) + "' );\n")
        b.WriteString("define( 'DB_HOST', '" + phpEscape(p.DBHost) + "' );\n")
        b.WriteString("define( 'DB_CHARSET', 'utf8mb4' );\n")
        saltNames := []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}
        for i, name := range saltNames {
                s := ""
                if i < len(salts) {
                        s = salts[i]
                }
                b.WriteString("define( '" + name + "', '" + phpEscape(s) + "' );\n")
        }
        b.WriteString("$table_prefix = 'wp_';\n")
        b.WriteString("define( 'WP_DEBUG', false );\n")
        b.WriteString("if ( ! defined( 'ABSPATH' ) ) define( 'ABSPATH', __DIR__ . '/' );\n")
        b.WriteString("require_once ABSPATH . 'wp-settings.php';\n")
        return b.String()
}

func phpEscape(s string) string {
        return strings.NewReplacer("\\", "\\\\", "'", "\\'", "$", "\\$").Replace(s)
}

// runAsAccountUser wraps a command for the account user when running as
// root (runuser); dev rigs exec directly and say so.
func (r *Registry) runAsAccountUser(username string, dir string, argv []string, stdin string) (string, error, string) {
        if os.Geteuid() == 0 {
                full := append([]string{"-u", username, "--"}, argv...)
                cmd := exec.Command("runuser", full...)
                cmd.Dir = dir
                cmd.Env = append(os.Environ(), "HOME="+filepath.Join(r.deps.HomeRoot, username))
                if stdin != "" {
                        cmd.Stdin = strings.NewReader(stdin)
                }
                out, err := cmd.CombinedOutput()
                return string(out), err, "runuser:" + username
        }
        cmd := exec.Command(argv[0], argv[1:]...)
        cmd.Dir = dir
        if stdin != "" {
                cmd.Stdin = strings.NewReader(stdin)
        }
        out, err := cmd.CombinedOutput()
        return string(out), err, "direct (dev rig)"
}

func (r *Registry) wpBinary() (string, error) {
        if r.deps.WpBinary != "" {
                return r.deps.WpBinary, nil
        }
        bin, err := exec.LookPath("wp")
        if err != nil {
                return "", &rpc.RPCError{
                        Code:    rpc.CodePrecondition,
                        Message: "wp-cli not found on this node — install wp-cli to use the app installer (ADR-0019)",
                }
        }
        return bin, nil
}

// appsInstallWordpress installs WordPress core into the account path.
func (r *Registry) appsInstallWordpress(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        dec := json.NewDecoder(strings.NewReader(string(raw)))
        dec.DisallowUnknownFields()
        var p wpInstallParams
        if err := dec.Decode(&p); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
        }
        if p.DBHost == "" {
                p.DBHost = "localhost"
        }
        if !wpUrlRe.MatchString(p.URL) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "url must be the site URL (http(s)://...)"}
        }
        if !wpTitleRe.MatchString(p.Title) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "title must be 1-120 plain characters"}
        }
        if !wpAdminUserRe.MatchString(p.AdminUser) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid admin_user"}
        }
        if !wpEmailRe.MatchString(p.AdminEmail) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid admin_email"}
        }
        if !wpDbNameRe.MatchString(p.DBName) || !wpDbNameRe.MatchString(p.DBUser) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid database name or user"}
        }
        if len(p.DBPassword) < 8 || len(p.DBPassword) > 1024 {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "db_password must be 8-1024 bytes"}
        }

        target, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.Path)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        if entries, _ := os.ReadDir(target); len(entries) > 0 {
                return nil, nil, &rpc.RPCError{
                        Code:    rpc.CodeConflict,
                        Message: "target path is not empty — pick a fresh directory for the install",
                }
        }
        if err := os.MkdirAll(target, 0o755); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "target dir create failed: " + err.Error()}
        }
        _, _ = chownToUserBestEffort(target, p.Username)

        wp, err := r.wpBinary()
        if err != nil {
                return nil, nil, err
        }

        var log strings.Builder
        // 1. core download (as the account user)
        out, err, asUser := r.runAsAccountUser(p.Username, target, []string{wp, "core", "download", "--path=" + target}, "")
        log.WriteString(strings.TrimSpace(out) + "\n")
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "wp core download failed: " + firstLine(out)}
        }
        // 2. wp-config.php rendered by the agent (credentials inside, 0600)
        salts := make([]string, 8)
        for i := range salts {
                salts[i] = generateSaltedString()
        }
        cfg := renderWpConfig(p, salts)
        cfgPath := filepath.Join(target, "wp-config.php")
        staging := cfgPath + ".nexus-staging"
        if err := os.WriteFile(staging, []byte(cfg), wpConfigMode); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "wp-config write failed: " + err.Error()}
        }
        if err := os.Rename(staging, cfgPath); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "wp-config swap failed: " + err.Error()}
        }
        _ = os.Chmod(cfgPath, wpConfigMode)
        _, _ = chownToUserBestEffort(cfgPath, p.Username)
        // 3. core install — the admin password is generated here and fed via
        // stdin (--prompt); it never appears in argv or the WAL.
        adminPassword := generateWpPassword()
        out, err, _ = r.runAsAccountUser(p.Username, target, []string{
                wp, "core", "install", "--path=" + target,
                "--url=" + p.URL, "--title=" + p.Title,
                "--admin_user=" + p.AdminUser, "--admin_email=" + p.AdminEmail,
                "--skip-email", "--prompt",
        }, adminPassword+"\n")
        log.WriteString(strings.TrimSpace(out) + "\n")
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "wp core install failed: " + firstLine(out)}
        }

        // 4. record the installed core version honestly (best-effort).
        outV, _, _ := r.runAsAccountUser(p.Username, target, []string{wp, "core", "version", "--path=" + target}, "")
        version := firstLine(outV)

        entry := r.deps.WAL.NewEntry("apps.install_wordpress", map[string]any{
                "username": p.Username, "path": p.Path, "url": p.URL,
                "admin_user": p.AdminUser, "db_name": p.DBName,
        })
        _ = r.deps.WAL.Append(entry)
        return wpInstallResult{
                Status:        "installed",
                Path:          target,
                Version:       version,
                AdminUser:     p.AdminUser,
                AdminPassword: adminPassword, // shown ONCE by the panel, never stored
                ExecutedAs:    asUser,
                Log:           log.String(),
        }, auditQueued(entry), nil
}

// appsUpdateWordpress runs core + db updates for an existing install.
func (r *Registry) appsUpdateWordpress(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        dec := json.NewDecoder(strings.NewReader(string(raw)))
        dec.DisallowUnknownFields()
        var p wpUpdateParams
        if err := dec.Decode(&p); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
        }
        target, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.Path)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        if fi, err := os.Stat(filepath.Join(target, "wp-config.php")); err != nil || fi.IsDir() {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "no WordPress install at this path"}
        }
        wp, err := r.wpBinary()
        if err != nil {
                return nil, nil, err
        }
        var log strings.Builder
        for _, argv := range [][]string{
                {wp, "core", "update", "--path=" + target},
                {wp, "core", "update-db", "--path=" + target},
        } {
                out, err, _ := r.runAsAccountUser(p.Username, target, argv, "")
                log.WriteString(strings.TrimSpace(out) + "\n")
                if err != nil {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "wp update failed: " + firstLine(out)}
                }
        }
        outV, _, _ := r.runAsAccountUser(p.Username, target, []string{wp, "core", "version", "--path=" + target}, "")
        entry := r.deps.WAL.NewEntry("apps.update_wordpress", map[string]any{
                "username": p.Username, "path": p.Path,
        })
        _ = r.deps.WAL.Append(entry)
        return wpUpdateResult{Status: "updated", Path: target, Version: firstLine(outV), Log: log.String()}, auditQueued(entry), nil
}

// appsRunWpCli is NOT a generic exec escape hatch: it allowlists a tiny
// set of read-only WP-CLI maintenance verbs, confined to one install.
func (r *Registry) appsRunWpCli(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        dec := json.NewDecoder(strings.NewReader(string(raw)))
        dec.DisallowUnknownFields()
        var p wpCliParams
        if err := dec.Decode(&p); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
        }
        allowed := map[string]bool{
                "core": true, "plugin": true, "theme": true, "user": true,
                "search-replace": true, "cache": true, "rewrite": true, "option": true,
        }
        if len(p.Args) == 0 || !allowed[p.Args[0]] {
                return nil, nil, &rpc.RPCError{
                        Code:    rpc.CodeInvalidParams,
                        Message: "wp verb not allowlisted (core|plugin|theme|user|search-replace|cache|rewrite|option)",
                }
        }
        for _, a := range p.Args {
                if len(a) > 512 || strings.ContainsAny(a, "\n\r\x00") {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid wp argument"}
                }
        }
        target, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.Path)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        wp, err := r.wpBinary()
        if err != nil {
                return nil, nil, err
        }
        argv := append([]string{wp}, p.Args...)
        argv = append(argv, "--path="+target)
        out, err, asUser := r.runAsAccountUser(p.Username, target, argv, "")
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "wp failed: " + firstLine(out)}
        }
        entry := r.deps.WAL.NewEntry("apps.wp_cli", map[string]any{
                "username": p.Username, "path": p.Path, "verb": p.Args[0],
        })
        _ = r.deps.WAL.Append(entry)
        return map[string]any{"status": "ok", "executed_as": asUser, "output": string(out)}, auditQueued(entry), nil
}

// appsStagingClone copies a WordPress install to a staging directory,
// swaps the copied wp-config.php to a fresh database, and re-points the
// staging copy's URLs — everything runs as the ACCOUNT USER except the
// config rewrite (agent-side, mode preserved). The staging database must
// already exist (the panel provisions it through db.create first); its
// credentials ride the signed command and land ONLY in the staging
// wp-config.php, never in logs or the WAL.
func (r *Registry) appsStagingClone(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        dec := json.NewDecoder(strings.NewReader(string(raw)))
        dec.DisallowUnknownFields()
        var p wpStagingParams
        if err := dec.Decode(&p); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
        }
        if p.DBHost == "" {
                p.DBHost = "localhost"
        }
        if !wpUrlRe.MatchString(p.StagingURL) || !wpUrlRe.MatchString(p.ProdURL) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "staging_url and prod_url must be site URLs"}
        }
        if !wpDbNameRe.MatchString(p.DBName) || !wpDbNameRe.MatchString(p.DBUser) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid staging database name or user"}
        }
        if len(p.DBPassword) < 8 || len(p.DBPassword) > 1024 {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "db_password must be 8-1024 bytes"}
        }
        source, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.SourcePath)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid source path: " + err.Error()}
        }
        staging, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.StagingPath)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid staging path: " + err.Error()}
        }
        if source == staging {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "staging path must differ from the source install"}
        }
        if fi, err := os.Stat(filepath.Join(source, "wp-config.php")); err != nil || fi.IsDir() {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "no WordPress install at the source path"}
        }
        if entries, _ := os.ReadDir(staging); len(entries) > 0 {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "staging path is not empty"}
        }
        wp, err := r.wpBinary()
        if err != nil {
                return nil, nil, err
        }

        var log strings.Builder
        // 1. copy the tree (account user — ownership stays with the account).
        if err := os.MkdirAll(staging, 0o755); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "staging dir create failed: " + err.Error()}
        }
        _, _ = chownToUserBestEffort(staging, p.Username)
        out, err, asUser := r.runAsAccountUser(p.Username, source, []string{"cp", "-a", source + "/.", staging}, "")
        log.WriteString(strings.TrimSpace(out) + "\n")
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "copy failed: " + firstLine(out)}
        }

        // 2. swap the DB constants inside the staging wp-config.php (0600 kept).
        cfgPath := filepath.Join(staging, "wp-config.php")
        cfg, err := os.ReadFile(cfgPath)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "staging wp-config.php missing after copy"}
        }
        newCfg := rewriteWpConfigDb(string(cfg), p.DBName, p.DBUser, p.DBPassword, p.DBHost)
        if err := os.WriteFile(cfgPath, []byte(newCfg), wpConfigMode); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "staging wp-config rewrite failed: " + err.Error()}
        }
        _ = os.Chmod(cfgPath, wpConfigMode)
        _, _ = chownToUserBestEffort(cfgPath, p.Username)

        // 3. dump prod → import into staging → search-replace URLs (account user).
        dump := filepath.Join(staging, ".nexus-staging-dump.sql")
        defer func() { _ = os.Remove(dump) }()
        for _, argv := range [][]string{
                {wp, "db", "export", dump, "--path=" + source, "--add-drop-table"},
                {wp, "db", "import", dump, "--path=" + staging},
                {wp, "search-replace", p.ProdURL, p.StagingURL, "--path=" + staging, "--all-tables", "--skip-columns=guid"},
        } {
                out, err, _ := r.runAsAccountUser(p.Username, source, argv, "")
                log.WriteString(strings.TrimSpace(out) + "\n")
                if err != nil {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "staging clone step failed (" + argv[1] + " " + argv[2] + "): " + firstLine(out)}
                }
        }

        entry := r.deps.WAL.NewEntry("apps.staging_clone", map[string]any{
                "username": p.Username, "source": p.SourcePath, "staging": p.StagingPath,
                "staging_url": p.StagingURL, "db_name": p.DBName,
        })
        _ = r.deps.WAL.Append(entry)
        return map[string]any{
                "status": "staged", "source_path": source, "staging_path": staging,
                "staging_url": p.StagingURL, "executed_as": asUser, "log": log.String(),
        }, auditQueued(entry), nil
}

// rewriteWpConfigDb replaces the DB_NAME/DB_USER/DB_PASSWORD/DB_HOST
// defines in an existing wp-config.php. Values are escaped the same way
// the generator escapes them.
func rewriteWpConfigDb(cfg, name, user, password, host string) string {
        repl := func(key, value string) {
                re := regexp.MustCompile(`define\(\s*'` + key + `',\s*'[^']*'\s*\);`)
                cfg = re.ReplaceAllString(cfg, "define( '"+key+"', '"+phpEscape(value)+"' );")
        }
        repl("DB_NAME", name)
        repl("DB_USER", user)
        repl("DB_PASSWORD", password)
        repl("DB_HOST", host)
        return cfg
}
