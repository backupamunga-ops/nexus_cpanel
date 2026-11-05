package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// nginx.* handler tests run fully in-process: the health gate is a fake
// "nginx" script (Deps.NginxBinary), the vhost root a temp dir, the WAL a
// temp queue. No NSS users are involved.

func fakeNginx(t *testing.T, exitCode int, output string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "nginx")
	script := "#!/bin/sh\necho " + output + "\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func newNginxRegistry(t *testing.T, bin string) *Registry {
	t.Helper()
	return NewRegistry(Deps{
		WAL:         newTestWAL(t),
		HomeRoot:    t.TempDir(),
		VhostRoot:   t.TempDir(),
		CertRoot:    t.TempDir(),
		NginxBinary: bin,
	})
}

func rawParams(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestApplyVhostWritesAndHealthChecks(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "syntax is ok"))
	res, _, err := r.nginxApplyVhost("id", rawParams(t, applyVhostParams{
		Domain:  "example.com",
		Content: "server { listen 80; server_name example.com; }",
	}))
	if err != nil {
		t.Fatal(err)
	}
	op := res.(vhostOpResult)
	if op.Status != "applied" || op.HealthCheck != "passed" || op.PreviousExisted {
		t.Fatalf("unexpected result: %+v", op)
	}
	got, err := os.ReadFile(filepath.Join(r.deps.VhostRoot, "example.com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "server_name example.com") {
		t.Fatalf("vhost content wrong: %q", got)
	}
}

func TestApplyVhostRollsBackOnFailedHealth(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 1, "emerg: broken directive"))
	original := "server { listen 80; }"
	final := filepath.Join(r.deps.VhostRoot, "example.com.conf")
	if err := os.WriteFile(final, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := r.nginxApplyVhost("id", rawParams(t, applyVhostParams{
		Domain:  "example.com",
		Content: "server { this is not nginx; }",
	}))
	if err == nil {
		t.Fatal("failed health check must reject the apply")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("error must report the rollback: %v", err)
	}
	got, readErr := os.ReadFile(final)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != original {
		t.Fatalf("previous vhost not restored: got %q want %q", got, original)
	}
}

func TestApplyVhostValidatesDomainAndContent(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "ok"))
	cases := []struct {
		name    string
		domain  string
		content string
	}{
		{"traversal domain", "../etc/passwd", "server {}"},
		{"uppercase domain", "Example.COM", "server {}"},
		{"no tld", "localhost", "server {}"},
		{"empty content", "example.com", "   "},
		{"nul content", "example.com", "server {\x00}"},
		{"oversized content", "example.com", strings.Repeat("a", maxVhostBytes+1)},
	}
	for _, tc := range cases {
		if _, _, err := r.nginxApplyVhost("id", rawParams(t, applyVhostParams{Domain: tc.domain, Content: tc.content})); err == nil {
			t.Fatalf("%s: must be rejected", tc.name)
		}
	}
}

func TestRemoveVhostIdempotentAndRollback(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "ok"))

	// Absent → {status:"absent"}, no error.
	res, _, err := r.nginxRemoveVhost("id", rawParams(t, applyVhostParams{Domain: "gone.example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(vhostOpResult).Status != "absent" {
		t.Fatalf("want absent, got %+v", res)
	}

	// Present + failing health → restored byte-for-byte, error returned.
	r2 := newNginxRegistry(t, fakeNginx(t, 1, "emerg: fail"))
	original := "server { listen 8080; }"
	final := filepath.Join(r2.deps.VhostRoot, "example.com.conf")
	if err := os.WriteFile(final, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r2.nginxRemoveVhost("id", rawParams(t, applyVhostParams{Domain: "example.com"})); err == nil {
		t.Fatal("failing health must reject removal")
	}
	got, _ := os.ReadFile(final)
	if string(got) != original {
		t.Fatalf("vhost not restored after failed removal health check: %q", got)
	}

	// Present + passing health → removed.
	r3 := newNginxRegistry(t, fakeNginx(t, 0, "ok"))
	final3 := filepath.Join(r3.deps.VhostRoot, "example.com.conf")
	if err := os.WriteFile(final3, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	res3, _, err := r3.nginxRemoveVhost("id", rawParams(t, applyVhostParams{Domain: "example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if res3.(vhostOpResult).Status != "removed" {
		t.Fatalf("want removed, got %+v", res3)
	}
	if _, err := os.Stat(final3); !os.IsNotExist(err) {
		t.Fatal("vhost file must be gone after removal")
	}
}

func TestHealthCheckSkippedWithoutBinary(t *testing.T) {
	t.Setenv("PATH", "")
	r := newNginxRegistry(t, "")
	res, _, err := r.nginxApplyVhost("id", rawParams(t, applyVhostParams{
		Domain: "example.com", Content: "server {}",
	}))
	if err != nil {
		t.Fatal(err)
	}
	op := res.(vhostOpResult)
	if op.HealthCheck != "skipped" || op.HealthDetail == "" {
		t.Fatalf("health check must be skipped with a reason: %+v", op)
	}
	if _, err := os.Stat(filepath.Join(r.deps.VhostRoot, "example.com.conf")); err != nil {
		t.Fatal("vhost must still be written when the health gate is skipped")
	}
}

func TestNginxTestAndReload(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "ok"))
	res, _, err := r.nginxTest("id", nil)
	if err != nil || res.(simpleStatus).Status != "passed" {
		t.Fatalf("test: %v %+v", err, res)
	}
	res, _, err = r.nginxReload("id", nil)
	if err != nil || res.(simpleStatus).Status != "reloaded" {
		t.Fatalf("reload: %v %+v", err, res)
	}

	rFail := newNginxRegistry(t, fakeNginx(t, 1, "emerg"))
	if _, _, err := rFail.nginxTest("id", nil); err == nil {
		t.Fatal("failing test must error")
	}

	t.Setenv("PATH", "")
	rSkip := newNginxRegistry(t, "")
	if res, _, err := rSkip.nginxReload("id", nil); err != nil || res.(simpleStatus).Status != "skipped" {
		t.Fatalf("reload must be skipped without a binary: %v %+v", err, res)
	}
}
