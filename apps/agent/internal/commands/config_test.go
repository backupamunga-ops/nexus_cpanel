package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "ok"))

	good := "# managed\nserver {\n\tlisten 80;\n}\n"
	res, _, err := r.configValidate("id", rawParams(t, configValidateParams{TargetType: "nginx_vhost", Content: good}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.(configValidateResult).Valid {
		t.Fatal("balanced config must validate")
	}

	bad := "server {\n\tlisten 80;\n"
	res, _, err = r.configValidate("id", rawParams(t, configValidateParams{TargetType: "nginx_vhost", Content: bad}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(configValidateResult).Valid {
		t.Fatal("unbalanced config must not validate")
	}

	pool := "; pool\n[example.com]\nuser = alice\npm = dynamic\n"
	res, _, err = r.configValidate("id", rawParams(t, configValidateParams{TargetType: "php_pool", Content: pool}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.(configValidateResult).Valid {
		t.Fatal("pool config must validate")
	}

	twoSections := "[a.com]\nx = 1\n[b.com]\ny = 2\n"
	res, _, err = r.configValidate("id", rawParams(t, configValidateParams{TargetType: "php_pool", Content: twoSections}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(configValidateResult).Valid {
		t.Fatal("two sections must not validate")
	}

	if _, _, err := r.configValidate("id", rawParams(t, configValidateParams{TargetType: "postfix_main", Content: "x"})); err == nil {
		t.Fatal("unknown target type must be rejected")
	}
}

func TestConfigDriftCheckAndListActive(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "ok"))
	content := "server {\n\tlisten 80;\n}\n"
	if err := os.WriteFile(filepath.Join(r.deps.VhostRoot, "example.com.conf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	params := driftCheckParams{TargetType: "nginx_vhost", TargetName: "example.com", ExpectedContent: content}
	res, _, err := r.configDriftCheck("id", rawParams(t, params))
	if err != nil {
		t.Fatal(err)
	}
	if !res.(driftCheckResult).Matches {
		t.Fatalf("identical content must match: %+v", res)
	}

	// Disk changes behind the panel's back → drift reported, never repaired.
	other := "server {\n\tlisten 8080;\n}\n"
	if err := os.WriteFile(filepath.Join(r.deps.VhostRoot, "example.com.conf"), []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _, _ = r.configDriftCheck("id", rawParams(t, params))
	d := res.(driftCheckResult)
	if d.Matches || !d.Exists || d.ActualHash == "" {
		t.Fatalf("drift must be reported: %+v", d)
	}

	// Missing file: exists=false, matches=false.
	res, _, _ = r.configDriftCheck("id", rawParams(t, driftCheckParams{
		TargetType: "nginx_vhost", TargetName: "gone.com", ExpectedContent: content,
	}))
	if res.(driftCheckResult).Exists {
		t.Fatal("missing file must report exists=false")
	}

	// list_active returns the disk truth.
	la, _, err := r.configListActive("id", rawParams(t, driftCheckParams{TargetType: "nginx_vhost", TargetName: "example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(la.(listActiveResult).Content, "8080") {
		t.Fatal("list_active must return disk content")
	}

	// Bad names rejected.
	if _, _, err := r.configDriftCheck("id", rawParams(t, driftCheckParams{
		TargetType: "nginx_vhost", TargetName: "../etc", ExpectedContent: "x",
	})); err == nil {
		t.Fatal("bad target name must be rejected")
	}
}
