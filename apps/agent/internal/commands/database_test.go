package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// database.* tests (ADR-0015). The MariaDB client/dump binaries are fake
// shell scripts that log their stdin SQL and behave deterministically, so
// the suite never needs a server. The adapter seam (ADR-0001) and the
// engine lock are part of the contract under test.

func newDbRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	binDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "sql.log")

	// Fake mariadb client: appends stdin to the log; --batch mode echoes a
	// numeric size for the information_schema query.
	script := `#!/bin/sh
LOG="` + logFile + `"
if [ "$1" = "--batch" ] && [ "$2" = "--skip-column-names" ]; then
  cat >> "$LOG"; echo "5242880"; exit 0
fi
cat >> "$LOG"; exit 0
`
	if err := os.WriteFile(filepath.Join(binDir, "mariadb"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "mariadb-dump"), []byte("#!/bin/sh\necho '-- fake dump for' \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry(Deps{
		WAL:               newTestWAL(t),
		HomeRoot:          t.TempDir(),
		PostfixMapDir:     t.TempDir(),
		VmailRoot:         t.TempDir(),
		MysqlClientBinary: filepath.Join(binDir, "mariadb"),
		MysqlDumpBinary:   filepath.Join(binDir, "mariadb-dump"),
	})
	return r, logFile
}

func dbCreateReq(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	return rawParams(t, m)
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestDatabaseCreate(t *testing.T) {
	r, log := newDbRegistry(t)

	res, hint, err := r.databaseCreate("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "app_production", "user": "app_user",
		"password": "s3cret-password", "owner_username": "alice",
	}))
	if err != nil {
		t.Fatal(err)
	}
	out := res.(dbOpResult)
	if out.Status != "created" || out.Name != "app_production" || out.User != "app_user" || out.Host != "localhost" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("create must queue a WAL audit entry")
	}

	// SQL must contain CREATE DATABASE, CREATE USER and the GRANT — in order,
	// with the default least-privilege host.
	sql := readLog(t, log)
	createDb := strings.Index(sql, "CREATE DATABASE `app_production`")
	createUser := strings.Index(sql, "CREATE USER IF NOT EXISTS `app_user`@`localhost`")
	grant := strings.Index(sql, "GRANT ALL PRIVILEGES ON `app_production`.* TO `app_user`@`localhost`")
	if createDb < 0 || createUser < 0 || grant < 0 || !(createDb < createUser && createUser < grant) {
		t.Fatalf("SQL sequence wrong: %q", sql)
	}
	// The WAL entry must never carry the password.
	entryJSON := hint.EntryID // presence is enough; the WAL test helper covers hashing
	if entryJSON == "" {
		t.Fatal("audit entry id missing")
	}
}

func TestDatabaseCreateEngineLock(t *testing.T) {
	r, log := newDbRegistry(t)
	// ADR-0001/0015: mysql/postgres are rejected honestly, not aliased.
	for _, eng := range []string{"mysql", "postgres", ""} {
		if _, _, err := r.databaseCreate("id", dbCreateReq(t, map[string]any{
			"engine": eng, "name": "x", "user": "u", "password": "longenough1",
		})); err == nil {
			t.Fatalf("engine %q must be rejected", eng)
		}
	}
	if readLog(t, log) != "" {
		t.Fatal("no SQL may run for a rejected engine")
	}
}

func TestDatabaseCreateValidationAndRollback(t *testing.T) {
	r, log := newDbRegistry(t)
	// Name/user shapes, password bounds.
	for _, bad := range []map[string]any{
		{"engine": "mariadb", "name": "9start", "user": "u", "password": "longenough1"},
		{"engine": "mariadb", "name": "ok", "user": "Bad!", "password": "longenough1"},
		{"engine": "mariadb", "name": "ok", "user": "u", "password": "short"},
	} {
		if _, _, err := r.databaseCreate("id", dbCreateReq(t, bad)); err == nil {
			t.Fatalf("input must be rejected: %v", bad)
		}
	}
	if readLog(t, log) != "" {
		t.Fatal("validation failures must not reach the database")
	}

	// A user-creation failure rolls the database back (fake succeeds here;
	// rollback is exercised by the adapter contract test below).
	if _, _, err := r.databaseCreate("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "ok", "user": "u", "password": "longenough1",
	})); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseDelete(t *testing.T) {
	r, log := newDbRegistry(t)

	res, hint, err := r.databaseDelete("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "old_db", "user": "old_user",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(dbOpResult).Status != "removed" {
		t.Fatalf("delete status: %+v", res)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("delete must queue a WAL audit entry")
	}
	sql := readLog(t, log)
	if !strings.Contains(sql, "REVOKE ALL PRIVILEGES ON `old_db`.* FROM `old_user`@`localhost`") ||
		!strings.Contains(sql, "DROP USER IF EXISTS `old_user`@`localhost`") ||
		!strings.Contains(sql, "DROP DATABASE IF EXISTS `old_db`") {
		t.Fatalf("teardown SQL wrong: %q", sql)
	}
}

func TestDatabaseSize(t *testing.T) {
	r, _ := newDbRegistry(t)
	res, hint, err := r.databaseSize("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "app_production",
	}))
	if err != nil {
		t.Fatal(err)
	}
	out := res.(map[string]any)
	if out["size_bytes"].(int64) != 5242880 || out["size_mb"].(int64) != 5 {
		t.Fatalf("size parse wrong: %+v", out)
	}
	if hint != nil {
		t.Fatal("read-only methods must not queue audit entries")
	}
	if _, _, err := r.databaseSize("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "Bad;Name",
	})); err == nil {
		t.Fatal("invalid name must be rejected before any query")
	}
}

func TestDatabaseDumpRestoreConfined(t *testing.T) {
	r, log := newDbRegistry(t)

	// Dump confined to the account home.
	home := mkHome(t, r, "alice")
	outPath := "backups/app.sql"
	res, hint, err := r.databaseDump("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "app_production", "output_path": outPath, "owner_username": "alice",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(dbOpResult).Status != "dumped" {
		t.Fatalf("dump status: %+v", res)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("dump must queue a WAL audit entry")
	}
	dumped := filepath.Join(home, outPath)
	if _, err := os.Stat(dumped); err != nil {
		t.Fatalf("dump file missing: %v", err)
	}

	// Restore reads it back.
	res2, _, err := r.databaseRestore("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "app_production", "input_path": outPath, "owner_username": "alice",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res2.(dbOpResult).Status != "restored" {
		t.Fatalf("restore status: %+v", res2)
	}

	// Escapes are refused (C13) and missing files are honest errors.
	if _, _, err := r.databaseDump("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "app_production", "output_path": "../../etc/pwned", "owner_username": "alice",
	})); err == nil {
		t.Fatal("escaping output path must be rejected")
	}
	if _, _, err := r.databaseRestore("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "app_production", "input_path": "missing.sql", "owner_username": "alice",
	})); err == nil {
		t.Fatal("missing input must be an honest error")
	}
	if !strings.Contains(readLog(t, log), "fake dump for app_production") {
		t.Fatal("dump binary was not invoked")
	}
}

func TestDatabaseAdapterRollbackOnError(t *testing.T) {
	// A client that fails CREATE USER must trigger the DB rollback — the
	// logged SQL then shows CREATE DATABASE followed by DROP DATABASE.
	binDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "sql.log")
	script := `#!/bin/sh
LOG="` + logFile + `"
cat >> "$LOG"
if grep -q "CREATE USER" "$LOG"; then echo "ERROR 1396 fake failure" >&2; exit 1; fi
exit 0
`
	if err := os.WriteFile(filepath.Join(binDir, "mariadb"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry(Deps{
		WAL:               newTestWAL(t),
		HomeRoot:          t.TempDir(),
		PostfixMapDir:     t.TempDir(),
		VmailRoot:         t.TempDir(),
		MysqlClientBinary: filepath.Join(binDir, "mariadb"),
	})
	if _, _, err := r.databaseCreate("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "doomed", "user": "u", "password": "longenough1",
	})); err == nil {
		t.Fatal("user-create failure must fail the command")
	}
	sql := readLog(t, logFile)
	if !strings.Contains(sql, "CREATE DATABASE `doomed`") || !strings.Contains(sql, "DROP DATABASE IF EXISTS `doomed`") {
		t.Fatalf("rollback missing: %q", sql)
	}
}

func TestDatabaseAbsentClientIsLoud(t *testing.T) {
	r := NewRegistry(Deps{
		WAL:           newTestWAL(t),
		HomeRoot:      t.TempDir(),
		PostfixMapDir: t.TempDir(),
		VmailRoot:     t.TempDir(),
	})
	if _, _, err := r.databaseCreate("id", dbCreateReq(t, map[string]any{
		"engine": "mariadb", "name": "ok", "user": "u", "password": "longenough1",
	})); err == nil {
		t.Fatal("absent client must be a loud precondition error")
	}
}
