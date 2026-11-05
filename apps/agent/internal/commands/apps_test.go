package commands

import (
        "os"
        "os/exec"
        "path/filepath"
        "strings"
        "testing"
)

// apps.*/git.* tests: a fake wp-cli that records argv AND stdin (the
// admin-password path), and a git shim that rewrites the repo URL to a
// real local bare repo so clone/checkout behave genuinely.

// fakeWp returns the fake binary path and the path its stdin is dumped
// to (read it AT ASSERTION TIME — a t.Cleanup copy would run only after
// the test body has already finished asserting).
func fakeWp(t *testing.T, output string) (binPath, stdinPath string) {
        t.Helper()
        bin := filepath.Join(t.TempDir(), "wp")
        script := "#!/bin/sh\n" +
                "for a in \"$@\"; do echo \"$a\" >> " + strconvQuote(bin+".argv") + "; done\n" +
                "if [ ! -t 0 ]; then echo '--- invocation' >> " + strconvQuote(bin+".stdin") + "; cat >> " + strconvQuote(bin+".stdin") + "; fi\n" +
                "printf '%s\\n' " + shQuote(output) + "\nexit 0\n"
        if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
                t.Fatal(err)
        }
        return bin, bin + ".stdin"
}

func newAppsRegistry(t *testing.T, wpBin string) *Registry {
        t.Helper()
        return NewRegistry(Deps{
                WAL:      newTestWAL(t),
                HomeRoot: t.TempDir(),
                WpBinary: wpBin,
        })
}

func TestWpInstallHappyPath(t *testing.T) {
        wpBin, stdinPath := fakeWp(t, "Success:")
        r := newAppsRegistry(t, wpBin)

        res, hint, err := r.appsInstallWordpress("id", rawParams(t, wpInstallParams{
                Username: "alpha", Path: "site", URL: "https://alpha.demo",
                Title: "Alpha", AdminUser: "admin", AdminEmail: "admin@alpha.demo",
                DBName: "alpha_wp", DBUser: "alpha_wp", DBPassword: "dbsecret-123",
        }))
        if err != nil {
                t.Fatal(err)
        }
        op := res.(wpInstallResult)
        if op.Status != "installed" || op.AdminUser != "admin" {
                t.Fatalf("unexpected result: %+v", op)
        }
        if len(op.AdminPassword) < 24 {
                t.Fatalf("generated admin password too weak: %q", op.AdminPassword)
        }
        if hint == nil {
                t.Fatal("expected audit hint")
        }

        // wp-config.php exists, carries the DB creds, and is 0600.
        cfgPath := filepath.Join(r.deps.HomeRoot, "alpha", "site", "wp-config.php")
        cfg, err := os.ReadFile(cfgPath)
        if err != nil {
                t.Fatal(err)
        }
        for _, want := range []string{"alpha_wp", "dbsecret-123", "AUTH_KEY"} {
                if !strings.Contains(string(cfg), want) {
                        t.Fatalf("wp-config missing %q", want)
                }
        }
        fi, _ := os.Stat(cfgPath)
        if fi.Mode().Perm() != 0o600 {
                t.Fatalf("wp-config mode: %v", fi.Mode().Perm())
        }

        // The admin password went to wp-cli via STDIN, never argv — the fake
        // wp dumps its stdin next to itself; read it now, mid-test.
        stdinSeen, err := os.ReadFile(stdinPath)
        if err != nil {
                t.Fatalf("fake wp stdin log missing: %v", err)
        }
        if !strings.Contains(string(stdinSeen), op.AdminPassword) {
                t.Fatalf("admin password not fed via stdin: %q / %q", string(stdinSeen), op.AdminPassword)
        }
}

func TestWpInstallRefusals(t *testing.T) {
        wpBin, _ := fakeWp(t, "ok")
        r := newAppsRegistry(t, wpBin)

        // Non-empty target dir refused.
        target := filepath.Join(r.deps.HomeRoot, "alpha", "busy")
        if err := os.MkdirAll(target, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(target, "x.txt"), []byte("x"), 0o644); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.appsInstallWordpress("id", rawParams(t, wpInstallParams{
                Username: "alpha", Path: "busy", URL: "https://a.b", Title: "t",
                AdminUser: "admin", AdminEmail: "a@b.c", DBName: "db", DBUser: "db",
                DBPassword: "longenough1",
        })); err == nil {
                t.Fatal("non-empty target accepted")
        }

        // Path escape refused.
        if _, _, err := r.appsInstallWordpress("id", rawParams(t, wpInstallParams{
                Username: "alpha", Path: "../escape", URL: "https://a.b", Title: "t",
                AdminUser: "admin", AdminEmail: "a@b.c", DBName: "db", DBUser: "db",
                DBPassword: "longenough1",
        })); err == nil {
                t.Fatal("path escape accepted")
        }

        // Weak db password refused.
        if _, _, err := r.appsInstallWordpress("id", rawParams(t, wpInstallParams{
                Username: "alpha", Path: "site", URL: "https://a.b", Title: "t",
                AdminUser: "admin", AdminEmail: "a@b.c", DBName: "db", DBUser: "db",
                DBPassword: "short",
        })); err == nil {
                t.Fatal("weak db password accepted")
        }
}

func TestWpUpdateRequiresInstall(t *testing.T) {
        wpBin, _ := fakeWp(t, "ok")
        r := newAppsRegistry(t, wpBin)
        if _, _, err := r.appsUpdateWordpress("id", rawParams(t, wpUpdateParams{
                Username: "alpha", Path: "nothing-here",
        })); err == nil {
                t.Fatal("update without install accepted")
        }
}

func TestWpCliVerbAllowlist(t *testing.T) {
        wpBin, _ := fakeWp(t, "ok")
        r := newAppsRegistry(t, wpBin)
        // Disallowed verb.
        if _, _, err := r.appsRunWpCli("id", rawParams(t, wpCliParams{
                Username: "alpha", Path: "p", Args: []string{"eval", "phpinfo();"},
        })); err == nil {
                t.Fatal("eval verb accepted — that is an exec escape hatch")
        }
        // Allowed verb passes with the path pinned (create the install dir).
        if err := os.MkdirAll(filepath.Join(r.deps.HomeRoot, "alpha", "p"), 0o755); err != nil {
                t.Fatal(err)
        }
        res, _, err := r.appsRunWpCli("id", rawParams(t, wpCliParams{
                Username: "alpha", Path: "p", Args: []string{"cache", "flush"},
        }))
        if err != nil {
                t.Fatal(err)
        }
        if res.(map[string]any)["status"] != "ok" {
                t.Fatalf("unexpected: %+v", res)
        }
}

// ---- staging clone -----------------------------------------------------------

func TestStagingCloneRewritesConfigAndRunsSteps(t *testing.T) {
        wpBin, _ := fakeWp(t, "ok")
        r := newAppsRegistry(t, wpBin)

        // A "prod" install: wp-config.php (rendered the way install renders it).
        prod := filepath.Join(r.deps.HomeRoot, "alpha", "public_html")
        if err := os.MkdirAll(prod, 0o755); err != nil {
                t.Fatal(err)
        }
        cfg := renderWpConfig(wpInstallParams{
                DBName: "alpha_wp", DBUser: "alpha_wp", DBPassword: "prod-db-pass", DBHost: "localhost",
        }, make([]string, 8))
        if err := os.WriteFile(filepath.Join(prod, "wp-config.php"), []byte(cfg), 0o600); err != nil {
                t.Fatal(err)
        }

        res, hint, err := r.appsStagingClone("id", rawParams(t, wpStagingParams{
                Username: "alpha", SourcePath: "public_html", StagingPath: "staging-wp",
                StagingURL: "https://staging.alpha.demo", ProdURL: "https://alpha.demo",
                DBName: "alpha_wpstg", DBUser: "alpha_wpstg", DBPassword: "staging-db-pass",
        }))
        if err != nil {
                t.Fatal(err)
        }
        if res.(map[string]any)["status"] != "staged" || hint == nil {
                t.Fatalf("unexpected: %+v", res)
        }

        // The staging config points at the staging DB; prod config untouched.
        stgCfg, err := os.ReadFile(filepath.Join(r.deps.HomeRoot, "alpha", "staging-wp", "wp-config.php"))
        if err != nil {
                t.Fatal(err)
        }
        for _, want := range []string{"alpha_wpstg", "staging-db-pass"} {
                if !strings.Contains(string(stgCfg), want) {
                        t.Fatalf("staging wp-config missing %q", want)
                }
        }
        if strings.Contains(string(stgCfg), "prod-db-pass") {
                t.Fatal("staging wp-config still carries prod credentials")
        }
        prodCfg, _ := os.ReadFile(filepath.Join(prod, "wp-config.php"))
        if !strings.Contains(string(prodCfg), "prod-db-pass") || strings.Contains(string(prodCfg), "staging-db-pass") {
                t.Fatal("prod wp-config was modified by the staging clone")
        }
        fi, _ := os.Stat(filepath.Join(r.deps.HomeRoot, "alpha", "staging-wp", "wp-config.php"))
        if fi.Mode().Perm() != 0o600 {
                t.Fatalf("staging wp-config mode: %v", fi.Mode().Perm())
        }

        // The dump file was cleaned up.
        if _, err := os.Stat(filepath.Join(r.deps.HomeRoot, "alpha", "staging-wp", ".nexus-staging-dump.sql")); !os.IsNotExist(err) {
                t.Fatal("staging dump file left behind")
        }
}

func TestStagingCloneRefusals(t *testing.T) {
        wpBin, _ := fakeWp(t, "ok")
        r := newAppsRegistry(t, wpBin)
        prod := filepath.Join(r.deps.HomeRoot, "alpha", "public_html")
        if err := os.MkdirAll(prod, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(prod, "wp-config.php"), []byte("<?php\n"), 0o600); err != nil {
                t.Fatal(err)
        }
        // Same source and staging path.
        if _, _, err := r.appsStagingClone("id", rawParams(t, wpStagingParams{
                Username: "alpha", SourcePath: "public_html", StagingPath: "public_html",
                StagingURL: "https://s.a", ProdURL: "https://p.a",
                DBName: "db", DBUser: "db", DBPassword: "longenough1",
        })); err == nil {
                t.Fatal("identical staging path accepted")
        }
        // Populated staging dir.
        busy := filepath.Join(r.deps.HomeRoot, "alpha", "busy")
        if err := os.MkdirAll(busy, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(busy, "x"), []byte("x"), 0o644); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.appsStagingClone("id", rawParams(t, wpStagingParams{
                Username: "alpha", SourcePath: "public_html", StagingPath: "busy",
                StagingURL: "https://s.a", ProdURL: "https://p.a",
                DBName: "db", DBUser: "db", DBPassword: "longenough1",
        })); err == nil {
                t.Fatal("non-empty staging path accepted")
        }
}

// ---- git.* ------------------------------------------------------------------

// gitShim wraps the real git binary, rewriting the CLONE URL to a local
// bare repo (env TEST_REPO) — so our release/symlink logic runs against
// genuine git behavior without needing network URLs.
var gitRealPath = func() string {
        p, err := exec.LookPath("git")
        if err != nil {
                return "/usr/bin/git"
        }
        return p
}()

func gitShim(t *testing.T) (shim string, repoURL string) {
        t.Helper()
        bare := filepath.Join(t.TempDir(), "origin.git")
        seed := filepath.Join(t.TempDir(), "seed")
        if err := os.MkdirAll(seed, 0o755); err != nil {
                t.Fatal(err)
        }
        for _, cmd := range [][]string{
                {"git", "init", "-q", "-b", "main", seed},
                {"git", "-C", seed, "config", "user.email", "t@t"},
                {"git", "-C", seed, "config", "user.name", "t"},
                {"git", "-C", seed, "commit", "-q", "--allow-empty", "-m", "one"},
                {"git", "clone", "-q", "--bare", seed, bare},
                {"git", "-C", bare, "config", "user.email", "t@t"},
        } {
                c := exec.Command(cmd[0], cmd[1:]...)
                if out, err := c.CombinedOutput(); err != nil {
                        t.Fatalf("git setup: %v: %s", err, out)
                }
        }
        bin := filepath.Join(t.TempDir(), "git")
        script := "#!/bin/bash\n" +
                "if [ \"$1\" = \"clone\" ]; then\n" +
                "  args=(\"$@\"); args[3]=\"$NEXUS_TEST_REPO\"\n" +
                "  exec " + gitRealPath + " \"${args[@]}\"\n" +
                "fi\n" +
                "exec " + gitRealPath + " \"$@\"\n"
        if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
                t.Fatal(err)
        }
        t.Setenv("NEXUS_TEST_REPO", bare)
        return bin, bare
}

func newGitRegistry(t *testing.T, gitBin string) *Registry {
        t.Helper()
        return NewRegistry(Deps{
                WAL:       newTestWAL(t),
                HomeRoot:  t.TempDir(),
                GitBinary: gitBin,
        })
}

func TestGitDeployHistoryRollback(t *testing.T) {
        shim, _ := gitShim(t)
        r := newGitRegistry(t, shim)

        // First deploy creates the release + swaps the symlink in.
        res, hint, err := r.gitDeploy("id", rawParams(t, gitDeployParams{
                Username: "alpha", Domain: "alpha.demo", RepoURL: "https://github.com/x/y.git",
                Branch: "main", DeployPath: "public_html",
        }))
        if err != nil {
                t.Fatal(err)
        }
        d1 := res.(gitDeployResult)
        if d1.Status != "deployed" || d1.ReleaseID == "" {
                t.Fatalf("unexpected: %+v", d1)
        }
        if hint == nil {
                t.Fatal("expected audit hint")
        }
        link, err := os.Readlink(filepath.Join(r.deps.HomeRoot, "alpha", "public_html"))
        if err != nil || filepath.Base(link) != d1.ReleaseID {
                t.Fatalf("symlink not at release: %v → %s", err, link)
        }

        // Second deploy adds a release.
        res2, _, err := r.gitDeploy("id", rawParams(t, gitDeployParams{
                Username: "alpha", Domain: "alpha.demo", RepoURL: "https://github.com/x/y.git",
                Branch: "main", DeployPath: "public_html",
        }))
        if err != nil {
                t.Fatal(err)
        }
        d2 := res2.(gitDeployResult)
        if d2.ReleaseID == d1.ReleaseID {
                t.Fatal("release ids must be unique per deploy")
        }

        // History: 2 releases, current = latest.
        hres, _, err := r.gitDeployHistory("id", rawParams(t, map[string]string{
                "username": "alpha", "domain": "alpha.demo", "deploy_path": "public_html",
        }))
        if err != nil {
                t.Fatal(err)
        }
        h := hres.(gitHistoryResult)
        if len(h.Releases) != 2 || !h.Releases[0].Active {
                t.Fatalf("history wrong: %+v", h.Releases)
        }

        // Rollback to release 1 (audited) and the symlink follows.
        if _, _, err := r.gitRollback("id", rawParams(t, map[string]string{
                "username": "alpha", "domain": "alpha.demo",
                "deploy_path": "public_html", "release_id": d1.ReleaseID,
        })); err != nil {
                t.Fatal(err)
        }
        link2, _ := os.Readlink(filepath.Join(r.deps.HomeRoot, "alpha", "public_html"))
        if filepath.Base(link2) != d1.ReleaseID {
                t.Fatalf("rollback did not repoint: %s", link2)
        }
        hres2, _, _ := r.gitDeployHistory("id", rawParams(t, map[string]string{
                "username": "alpha", "domain": "alpha.demo", "deploy_path": "public_html",
        }))
        h2 := hres2.(gitHistoryResult)
        if !h2.Releases[1].Active {
                t.Fatalf("active flag wrong after rollback: %+v", h2.Releases)
        }
}

func TestGitDeployRefusals(t *testing.T) {
        shim, _ := gitShim(t)
        r := newGitRegistry(t, shim)

        // A real (non-symlink) deploy dir is never silently replaced.
        realDir := filepath.Join(r.deps.HomeRoot, "alpha", "public_html")
        if err := os.MkdirAll(realDir, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(realDir, "index.html"), []byte("hi"), 0o644); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.gitDeploy("id", rawParams(t, gitDeployParams{
                Username: "alpha", Domain: "alpha.demo", RepoURL: "https://github.com/x/y.git",
                Branch: "main", DeployPath: "public_html",
        })); err == nil {
                t.Fatal("real directory deploy accepted")
        }

        // Bad repo URL / branch / release id.
        if _, _, err := r.gitDeploy("id", rawParams(t, gitDeployParams{
                Username: "alpha", Domain: "alpha.demo", RepoURL: "file:///etc",
                Branch: "main", DeployPath: "p",
        })); err == nil {
                t.Fatal("file:// repo accepted")
        }
        if _, _, err := r.gitRollback("id", rawParams(t, map[string]string{
                "username": "alpha", "domain": "alpha.demo",
                "deploy_path": "p", "release_id": "../../etc",
        })); err == nil {
                t.Fatal("traversal release id accepted")
        }
}
