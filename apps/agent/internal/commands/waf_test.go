package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// waf.* / malware.* tests: fake nginx binary for the health gate (the
// established pattern), a temp vhost root, a fake clamscan emitting canned
// ClamAV output, and a temp quarantine root.

func newWafRegistry(t *testing.T, nginxExit int) *Registry {
	t.Helper()
	return NewRegistry(Deps{
		WAL:         newTestWAL(t),
		HomeRoot:    t.TempDir(),
		VhostRoot:   t.TempDir(),
		NginxBinary: fakeNginx(t, nginxExit, "syntax is ok"),
	})
}

func TestWafApplyBlockWritesInclude(t *testing.T) {
	r := newWafRegistry(t, 0)
	res, hint, err := r.wafApplyPolicy("id", rawParams(t, wafPolicyParams{
		Domain: "example.com", Mode: "block", ParanoiaLevel: 2,
		Exclusions: []string{"942100", "949110"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	op := res.(wafPolicyResult)
	if op.Status != "applied" || op.Mode != "block" || op.HealthCheck != "passed" {
		t.Fatalf("unexpected result: %+v", op)
	}
	if hint == nil {
		t.Fatal("expected audit hint")
	}
	got, err := os.ReadFile(filepath.Join(r.deps.VhostRoot, "example.com"+wafExt))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SecRuleEngine On", // block mode
		"# mode: block",
		"# paranoia_level: 2",
		"SecRuleRemoveById 942100",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("include missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "949110") && !strings.Contains(string(got), "SecRuleRemoveById 949110") {
		t.Fatalf("exclusion rendering broken:\n%s", got)
	}
}

func TestWafDetectUsesDetectionOnly(t *testing.T) {
	r := newWafRegistry(t, 0)
	res, _, err := r.wafApplyPolicy("id", rawParams(t, wafPolicyParams{
		Domain: "example.com", Mode: "detect", ParanoiaLevel: 1,
	}))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(res.(wafPolicyResult).ConfPath)
	if !strings.Contains(string(got), "SecRuleEngine DetectionOnly") {
		t.Fatalf("detect mode must be DetectionOnly:\n%s", got)
	}
}

func TestWafOffRemovesInclude(t *testing.T) {
	r := newWafRegistry(t, 0)
	conf := filepath.Join(r.deps.VhostRoot, "example.com"+wafExt)
	if _, _, err := r.wafApplyPolicy("id", rawParams(t, wafPolicyParams{
		Domain: "example.com", Mode: "block", ParanoiaLevel: 1,
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(conf); err != nil {
		t.Fatal("include should exist after apply")
	}
	if _, _, err := r.wafApplyPolicy("id", rawParams(t, wafPolicyParams{
		Domain: "example.com", Mode: "off",
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatal("mode=off must remove the include")
	}
}

func TestWafFailedHealthRollsBack(t *testing.T) {
	r := newWafRegistry(t, 1) // nginx -t fails
	conf := filepath.Join(r.deps.VhostRoot, "example.com"+wafExt)
	if _, _, err := r.wafApplyPolicy("id", rawParams(t, wafPolicyParams{
		Domain: "example.com", Mode: "block", ParanoiaLevel: 1,
	})); err == nil {
		t.Fatal("expected health check failure")
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatal("failed health check must roll the include back")
	}
}

func TestWafValidationWhitelist(t *testing.T) {
	r := newWafRegistry(t, 0)
	bad := []wafPolicyParams{
		{Domain: "not a domain", Mode: "block", ParanoiaLevel: 1},
		{Domain: "example.com", Mode: "paranoid", ParanoiaLevel: 1},
		{Domain: "example.com", Mode: "block", ParanoiaLevel: 3},
		{Domain: "example.com", Mode: "block", ParanoiaLevel: 1, Exclusions: []string{"drop tables"}},
		{Domain: "example.com", Mode: "block", ParanoiaLevel: 1, Exclusions: []string{"1", "1"}},
	}
	for i, p := range bad {
		if _, _, err := r.wafApplyPolicy("id", rawParams(t, p)); err == nil {
			t.Fatalf("case %d: invalid policy accepted", i)
		}
	}
	// Unknown fields rejected.
	if _, _, err := r.wafApplyPolicy("id", []byte(`{"domain":"example.com","mode":"block","paranoia_level":1,"cmd":"/bin/sh"}`)); err == nil {
		t.Fatal("unknown field accepted — whitelist hole")
	}
}

// ---- malware ----------------------------------------------------------------

func fakeClamscan(t *testing.T, output string, exitCode int) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "clamscan")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' " + shQuote(output) + "\n" +
		"exit " + fmt.Sprint(exitCode) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// fakeClamscanDynamic emits two FOUND lines for the directory it was asked
// to scan (its last argv element), so quarantine tests can stage real files
// at exactly those paths.
func fakeClamscanDynamic(t *testing.T, exitCode int) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "clamscan")
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do last=\"$a\"; done\n" +
		"printf '%s: (Php.Trojan.Shell) FOUND\\n' \"$last/shell.php\"\n" +
		"printf '%s: (JS.Obfus.1) FOUND\\n' \"$last/evil.js\"\n" +
		"exit " + fmt.Sprint(exitCode) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func newMalwareRegistry(t *testing.T, clamBin string) *Registry {
	t.Helper()
	return NewRegistry(Deps{
		WAL:            newTestWAL(t),
		HomeRoot:       t.TempDir(),
		ClamscanBinary: clamBin,
		QuarantineRoot: t.TempDir(),
	})
}

func TestMalwareScanParsesAndQuarantines(t *testing.T) {
	r := newMalwareRegistry(t, "")

	// Stage an infected file so quarantine has something to move; the fake
	// clamscan emits findings for exactly this path.
	uploadDir := filepath.Join(r.deps.HomeRoot, "alpha", "uploads")
	src := filepath.Join(uploadDir, "shell.php")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("<?php evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The fake also reports evil.js — stage it so quarantine can move both.
	if err := os.WriteFile(filepath.Join(uploadDir, "evil.js"), []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.deps.ClamscanBinary = fakeClamscanDynamic(t, 1)

	res, hint, err := r.malwareScan("id", rawParams(t, malwareScanParams{
		Scope: "account", Path: uploadDir, MoveInfected: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := res.(malwareScanResult)
	if m.Status != "success" || m.InfectedCount != 2 || len(m.Findings) != 2 {
		t.Fatalf("bad parse: %+v", m)
	}
	if m.Findings[0].Signature != "Php.Trojan.Shell" || m.Findings[0].QuarantinePath == "" {
		t.Fatalf("finding not quarantined: %+v", m.Findings[0])
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("infected file must be MOVED out of place")
	}
	if _, err := os.Stat(m.Findings[0].QuarantinePath); err != nil {
		t.Fatalf("quarantine copy missing: %v", err)
	}
	if hint == nil {
		t.Fatal("expected audit hint")
	}

	// Without move_infected: findings reported honestly in place.
	res2, _, err := r.malwareScan("id", rawParams(t, malwareScanParams{
		Scope: "site", Path: uploadDir,
	}))
	if err != nil {
		t.Fatal(err)
	}
	m2 := res2.(malwareScanResult)
	if m2.Findings[0].QuarantinePath != "" {
		t.Fatalf("no move requested but quarantine path set: %+v", m2.Findings[0])
	}
}

func TestMalwareQuarantineDeleteRestore(t *testing.T) {
	clam := fakeClamscan(t, "", 0)
	r := newMalwareRegistry(t, clam)

	// Seed a quarantined artifact manually.
	qpath := filepath.Join(r.deps.QuarantineRoot, "home/alpha/uploads/shell.php.quarantined")
	if err := os.MkdirAll(filepath.Dir(qpath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qpath, []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}

	// List sees it.
	lres, _, err := r.malwareQuarantineList("id", nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := lres.(map[string]any)["entries"].([]malwareQuarantineEntry)
	if len(entries) != 1 || entries[0].Path != qpath {
		t.Fatalf("list wrong: %+v", entries)
	}

	// Delete is confined to the quarantine root.
	if _, _, err := r.malwareQuarantineDelete("id", rawParams(t, map[string]string{
		"path": filepath.Join(r.deps.QuarantineRoot, "../../etc/passwd"),
	})); err == nil {
		t.Fatal("escape path accepted")
	}
	if _, _, err := r.malwareQuarantineDelete("id", rawParams(t, map[string]string{"path": qpath})); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(qpath); !os.IsNotExist(err) {
		t.Fatal("artifact not deleted")
	}

	// Restore path: seed again, restore into an account home.
	if err := os.WriteFile(qpath, []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.malwareQuarantineRestore("id", rawParams(t, map[string]string{
		"path":     qpath,
		"username": "alpha",
		"rel_path": "uploads/restored.php",
	})); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(r.deps.HomeRoot, "alpha", "uploads", "restored.php")
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("restore destination missing: %v", err)
	}
	if _, err := os.Stat(qpath); !os.IsNotExist(err) {
		t.Fatal("artifact must move out of quarantine on restore")
	}
}

func TestMalwareScanPathValidation(t *testing.T) {
	clam := fakeClamscan(t, "", 0)
	r := newMalwareRegistry(t, clam)
	if _, _, err := r.malwareScan("id", rawParams(t, malwareScanParams{Scope: "weird", Path: "/tmp"})); err == nil {
		t.Fatal("bad scope accepted")
	}
	if _, _, err := r.malwareScan("id", rawParams(t, malwareScanParams{Scope: "account", Path: "relative/path"})); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, _, err := r.malwareScan("id", rawParams(t, malwareScanParams{Scope: "account", Path: "/nonexistent-dir-xyz"})); err == nil {
		t.Fatal("missing path accepted")
	}
}
