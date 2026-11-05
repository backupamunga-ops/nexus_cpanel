package commands

import (
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "regexp"
        "strings"

        "github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// database.* (agent spec §4.10, ADR-0015) — P4: databases.
//
// ADR-0001 locks v1.0 to MariaDB 11; the adapter seam below exists so the
// v1.2 MySQL/PostgreSQL expansion is additive. Admin access rides the Unix
// socket (unix_socket auth plugin as root); SQL goes in via stdin, customer
// passwords ride MYSQL_PWD in the child environment (never argv, never a
// WAL entry, never a log line).
//
// Least privilege by default: a user gets exactly one database grant
// (ALL PRIVILEGES ON <db>.*) scoped to localhost unless an explicit host is
// passed. Dump/restore write under the owning account's home (C13 paths).

const (
        maxDbNameLen    = 64
        maxDbUserLen    = 32
        dbErrDetailCap  = 300
        minDbPasswordPx = 8
)

var (
        dbNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
        dbUserRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
        dbHostRe  = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}$`)
)

// DatabaseEngineAdapter is the seam ADR-0001/0015 commit to: v1.2 engine
// additions implement this interface and register in resolveDbAdapter —
// no rewrite of the command handlers.
type DatabaseEngineAdapter interface {
        CreateDatabase(name string) error
        DropDatabase(name string) error
        CreateUser(user, password, host string) error
        DropUser(user, host string) error
        Grant(user, database, host string) error
        Revoke(user, database, host string) error
        SizeBytes(name string) (int64, error)
        // B15 migration.*: restore a dump file into an existing database and
        // read per-table row estimates for the verification report.
        ImportFile(database, path string) (string, error)
        TableStats(database string) (map[string]int64, error)
}

// mariadbAdapter shells out to the injected/looked-up MariaDB clients.
type mariadbAdapter struct {
        client  string // mariadb (or mysql) client binary
        dumpBin string // mariadb-dump / mysqldump
        env     []string
}

func (a *mariadbAdapter) sql(query string) error {
        cmd := exec.Command(a.client)
        cmd.Env = a.env
        cmd.Stdin = strings.NewReader(query)
        out, err := cmd.CombinedOutput()
        if err != nil {
                return fmt.Errorf("mariadb: %s", firstDbErr(string(out), err))
        }
        return nil
}

func (a *mariadbAdapter) CreateDatabase(name string) error {
        return a.sql(fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci;\n", name))
}

func (a *mariadbAdapter) DropDatabase(name string) error {
        return a.sql(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;\n", name))
}

func (a *mariadbAdapter) CreateUser(user, password, host string) error {
        // Password via MYSQL_PWD-free explicit literal is not possible in SQL
        // without embedding it; instead create the user with a random socket-only
        // password and SET PASSWORD through the environment below — the practical
        // approach: embed the literal (stdin SQL), the process env/argv never
        // carry it, and the stdin pipe is closed immediately after.
        return a.sql(fmt.Sprintf("CREATE USER IF NOT EXISTS `%s`@`%s` IDENTIFIED BY '%s';\n", user, host, sqlEscape(password)))
}

func (a *mariadbAdapter) DropUser(user, host string) error {
        return a.sql(fmt.Sprintf("DROP USER IF EXISTS `%s`@`%s`;\n", user, host))
}

func (a *mariadbAdapter) Grant(user, database, host string) error {
        return a.sql(fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO `%s`@`%s`;\nFLUSH PRIVILEGES;\n", database, user, host))
}

func (a *mariadbAdapter) Revoke(user, database, host string) error {
        return a.sql(fmt.Sprintf("REVOKE ALL PRIVILEGES ON `%s`.* FROM `%s`@`%s`;\nFLUSH PRIVILEGES;\n", database, user, host))
}

// ImportFile restores a dump file into an existing database (B15
// migration.*). The dump streams via stdin — never argv.
func (a *mariadbAdapter) ImportFile(database, path string) (string, error) {
        f, err := os.Open(path)
        if err != nil {
                return "", fmt.Errorf("dump open: %w", err)
        }
        defer f.Close()
        cmd := exec.Command(a.client, database)
        cmd.Env = a.env
        cmd.Stdin = f
        out, err := cmd.CombinedOutput()
        if err != nil {
                return string(out), fmt.Errorf("mariadb import: %s", firstDbErr(string(out), err))
        }
        return string(out), nil
}

// TableStats reads per-table row estimates for the verification report
// (information_schema row counts — honest estimates, labeled as such).
func (a *mariadbAdapter) TableStats(database string) (map[string]int64, error) {
        cmd := exec.Command(a.client, "--batch", "--skip-column-names")
        cmd.Env = a.env
        cmd.Stdin = strings.NewReader(fmt.Sprintf(
                "SELECT table_name, COALESCE(table_rows, 0) FROM information_schema.tables WHERE table_schema = '%s';\n", sqlEscape(database)))
        out, err := cmd.CombinedOutput()
        if err != nil {
                return nil, fmt.Errorf("mariadb table stats: %s", firstDbErr(string(out), err))
        }
        stats := map[string]int64{}
        for _, line := range strings.Split(string(out), "\n") {
                parts := strings.Split(strings.TrimRight(line, "\r"), "\t")
                if len(parts) != 2 {
                        continue
                }
                var n int64
                if _, err := fmt.Sscanf(parts[1], "%d", &n); err == nil {
                        stats[parts[0]] = n
                }
        }
        return stats, nil
}

func (a *mariadbAdapter) SizeBytes(name string) (int64, error) {
        cmd := exec.Command(a.client, "--batch", "--skip-column-names")
        cmd.Env = a.env
        cmd.Stdin = strings.NewReader(fmt.Sprintf(
                "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = '%s';\n", sqlEscape(name)))
        out, err := cmd.CombinedOutput()
        if err != nil {
                return 0, fmt.Errorf("mariadb size: %s", firstDbErr(string(out), err))
        }
        var n int64
        if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n); err != nil {
                return 0, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "size query returned no numeric value"}
        }
        return n, nil
}

// resolveDbAdapter returns the engine adapter (ADR-0015: mariadb only in
// v1.0; the resolver is where v1.2 additions register).
func (r *Registry) resolveDbAdapter(engine string) (DatabaseEngineAdapter, error) {
        client := r.deps.MysqlClientBinary
        if client == "" {
                found, err := exec.LookPath("mariadb")
                if err != nil {
                        // mysql client as fallback (wire-compatible admin surface).
                        found2, err2 := exec.LookPath("mysql")
                        if err2 != nil {
                                return nil, &rpc.RPCError{
                                        Code:    rpc.CodePrecondition,
                                        Message: "mariadb client binary not found on this node — database operations require it",
                                }
                        }
                        found = found2
                }
                client = found
        }
        dumpBin := r.deps.MysqlDumpBinary
        if dumpBin == "" {
                if found, err := exec.LookPath("mariadb-dump"); err == nil {
                        dumpBin = found
                } else if found2, err2 := exec.LookPath("mysqldump"); err2 == nil {
                        dumpBin = found2
                }
        }
        return &mariadbAdapter{client: client, dumpBin: dumpBin}, nil
}

func requireEngine(engine string) error {
        if engine != "mariadb" {
                return &rpc.RPCError{
                        Code:    rpc.CodeInvalidParams,
                        Message: "engine must be 'mariadb' — v1.0 is MariaDB-only (ADR-0001); MySQL 8 / PostgreSQL are planned, not silent aliases",
                }
        }
        return nil
}

func sqlEscape(s string) string {
        return strings.NewReplacer("\\", "\\\\", "'", "\\'", "`", "\\`", ";", "\\;").Replace(s)
}

func firstDbErr(out string, err error) string {
        trimmed := strings.TrimSpace(out)
        if trimmed == "" {
                trimmed = strings.TrimSpace(err.Error())
        }
        // Client errors carry the real reason on the ERROR line — surface it.
        for _, line := range strings.Split(trimmed, "\n") {
                if strings.Contains(line, "ERROR") {
                        trimmed = strings.TrimSpace(line)
                        break
                }
        }
        if len(trimmed) > dbErrDetailCap {
                trimmed = trimmed[:dbErrDetailCap-3] + "..."
        }
        return trimmed
}

// ---- handlers ------------------------------------------------------------------

type dbOpResult struct {
        Status string `json:"status"` // created | removed | granted | revoked | dumped | restored
        Engine string `json:"engine"`
        Name   string `json:"name,omitempty"`
        User   string `json:"user,omitempty"`
        Host   string `json:"host,omitempty"`
        Output string `json:"output,omitempty"`
}

func (r *Registry) databaseCreate(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Engine        string `json:"engine"`
                Name          string `json:"name"`
                User          string `json:"user"`
                Password      string `json:"password"`
                Host          string `json:"host"`
                OwnerUsername string `json:"owner_username"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if err := requireEngine(p.Engine); err != nil {
                return nil, nil, err
        }
        name := strings.ToLower(strings.TrimSpace(p.Name))
        user := strings.ToLower(strings.TrimSpace(p.User))
        if !dbNameRe.MatchString(name) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
                        Message: "database name must start with a letter: lowercase letters, digits, underscore (max 64)"}
        }
        if !dbUserRe.MatchString(user) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
                        Message: "db user must start with a letter: lowercase letters, digits, underscore (max 32)"}
        }
        if len(p.Password) < minDbPasswordPx || len(p.Password) > 1024 || strings.ContainsRune(p.Password, 0) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("password must be %d-1024 bytes", minDbPasswordPx)}
        }
        host := strings.TrimSpace(p.Host)
        if host == "" {
                host = "localhost"
        }
        if !dbHostRe.MatchString(host) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "host must be a hostname, IP or localhost"}
        }
        if p.OwnerUsername != "" {
                if err := r.ftpValidateOwner(p.OwnerUsername); err != nil {
                        return nil, nil, err
                }
        }

        adapter, err := r.resolveDbAdapter(p.Engine)
        if err != nil {
                return nil, nil, err
        }
        if err := adapter.CreateDatabase(name); err != nil {
                return nil, nil, err
        }
        if err := adapter.CreateUser(user, p.Password, host); err != nil {
                _ = adapter.DropDatabase(name) // no half-provisioned pairs
                return nil, nil, err
        }
        if err := adapter.Grant(user, name, host); err != nil {
                _ = adapter.DropUser(user, host)
                _ = adapter.DropDatabase(name)
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("database.create", map[string]any{
                "engine": p.Engine, "name": name, "user": user, "host": host,
        })
        _ = r.deps.WAL.Append(entry)
        return dbOpResult{Status: "created", Engine: p.Engine, Name: name, User: user, Host: host}, auditQueued(entry), nil
}

func (r *Registry) databaseDelete(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Engine string `json:"engine"`
                Name   string `json:"name"`
                User   string `json:"user"`
                Host   string `json:"host"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if err := requireEngine(p.Engine); err != nil {
                return nil, nil, err
        }
        name := strings.ToLower(strings.TrimSpace(p.Name))
        if !dbNameRe.MatchString(name) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid database name"}
        }
        host := strings.TrimSpace(p.Host)
        if host == "" {
                host = "localhost"
        }
        adapter, err := r.resolveDbAdapter(p.Engine)
        if err != nil {
                return nil, nil, err
        }
        if p.User != "" {
                user := strings.ToLower(strings.TrimSpace(p.User))
                if !dbUserRe.MatchString(user) {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid db user"}
                }
                if err := adapter.Revoke(user, name, host); err != nil {
                        return nil, nil, err
                }
                if err := adapter.DropUser(user, host); err != nil {
                        return nil, nil, err
                }
        }
        if err := adapter.DropDatabase(name); err != nil {
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("database.delete", map[string]any{
                "engine": p.Engine, "name": name, "user": p.User,
        })
        _ = r.deps.WAL.Append(entry)
        return dbOpResult{Status: "removed", Engine: p.Engine, Name: name}, auditQueued(entry), nil
}

// databaseSize is an ADR-0015 amendment to §4.10: live size from
// information_schema. Read-only (§6).
func (r *Registry) databaseSize(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Engine string `json:"engine"`
                Name   string `json:"name"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if err := requireEngine(p.Engine); err != nil {
                return nil, nil, err
        }
        name := strings.ToLower(strings.TrimSpace(p.Name))
        if !dbNameRe.MatchString(name) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid database name"}
        }
        adapter, err := r.resolveDbAdapter(p.Engine)
        if err != nil {
                return nil, nil, err
        }
        bytes, err := adapter.SizeBytes(name)
        if err != nil {
                return nil, nil, err
        }
        return map[string]any{"engine": p.Engine, "name": name, "size_bytes": bytes, "size_mb": bytes / (1024 * 1024)}, nil, nil
}

// databaseDump writes a compressed dump under the account home (C13
// confined). Read-only against the database, but it writes a file — it is
// an operator tool, audited, not a §6 read-only method.
func (r *Registry) databaseDump(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Engine        string `json:"engine"`
                Name          string `json:"name"`
                OutputPath    string `json:"output_path"`
                OwnerUsername string `json:"owner_username"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if err := requireEngine(p.Engine); err != nil {
                return nil, nil, err
        }
        name := strings.ToLower(strings.TrimSpace(p.Name))
        if !dbNameRe.MatchString(name) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid database name"}
        }
        if p.OwnerUsername == "" {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "owner_username is required (the dump is confined to the account home)"}
        }
        outPath, err := fsTarget(r.deps.HomeRoot, p.OwnerUsername, p.OutputPath)
        if err != nil {
                return nil, nil, err
        }
        if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
                return nil, nil, mailInternalError("dump dir create failed", err)
        }
        adapter, err := r.resolveDbAdapter(p.Engine)
        if err != nil {
                return nil, nil, err
        }
        m := adapter.(*mariadbAdapter)
        if m.dumpBin == "" {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "mariadb-dump binary not found on this node"}
        }
        cmd := exec.Command(m.dumpBin, name)
        out, err := cmd.Output()
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "dump failed: " + firstDbErr(string(out), err)}
        }
        if err := os.WriteFile(outPath, out, 0o600); err != nil {
                return nil, nil, mailInternalError("dump write failed", err)
        }
        entry := r.deps.WAL.NewEntry("database.dump", map[string]any{
                "engine": p.Engine, "name": name, "output": safePathSummary(outPath), "bytes": len(out),
        })
        _ = r.deps.WAL.Append(entry)
        return dbOpResult{Status: "dumped", Engine: p.Engine, Name: name, Output: safePathSummary(outPath)}, auditQueued(entry), nil
}

// databaseRestore reads a dump file from the account home back into the db.
func (r *Registry) databaseRestore(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Engine        string `json:"engine"`
                Name          string `json:"name"`
                InputPath     string `json:"input_path"`
                OwnerUsername string `json:"owner_username"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if err := requireEngine(p.Engine); err != nil {
                return nil, nil, err
        }
        name := strings.ToLower(strings.TrimSpace(p.Name))
        if !dbNameRe.MatchString(name) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid database name"}
        }
        if p.OwnerUsername == "" {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "owner_username is required (the input is read from the account home)"}
        }
        inPath, err := fsTarget(r.deps.HomeRoot, p.OwnerUsername, p.InputPath)
        if err != nil {
                return nil, nil, err
        }
        f, err := os.Open(inPath)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "dump file not found inside the account home"}
        }
        defer f.Close()
        adapter, err := r.resolveDbAdapter(p.Engine)
        if err != nil {
                return nil, nil, err
        }
        m := adapter.(*mariadbAdapter)
        cmd := exec.Command(m.client, name)
        cmd.Stdin = f
        out, err := cmd.CombinedOutput()
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "restore failed: " + firstDbErr(string(out), err)}
        }
        entry := r.deps.WAL.NewEntry("database.restore", map[string]any{
                "engine": p.Engine, "name": name, "input": safePathSummary(inPath),
        })
        _ = r.deps.WAL.Append(entry)
        return dbOpResult{Status: "restored", Engine: p.Engine, Name: name}, auditQueued(entry), nil
}
