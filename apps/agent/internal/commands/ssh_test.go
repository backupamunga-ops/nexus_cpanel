package commands

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

// ssh.* tests (ADR-0010). No NSS users in tests: chownToUserBestEffort
// reports the skip honestly and the file/mode contracts are asserted
// around it, exactly like the filesystem content-op tests.

const testEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9exampleexampleexampleexampleexampleexam alice@laptop"

func newSshRegistry(t *testing.T) *Registry {
        t.Helper()
        return NewRegistry(Deps{WAL: newTestWAL(t), HomeRoot: t.TempDir(), VhostRoot: t.TempDir()})
}

func sshDeployReq(t *testing.T, username string, keys map[string]string) json.RawMessage {
        t.Helper()
        list := []map[string]string{}
        for fp, pk := range keys {
                list = append(list, map[string]string{"fingerprint": fp, "public_key": pk})
        }
        return rawParams(t, map[string]any{"username": username, "keys": list})
}

func akPath(t *testing.T, r *Registry, username string) string {
        t.Helper()
        return filepath.Join(r.deps.HomeRoot, username, ".ssh", "authorized_keys")
}

func TestSshDeployCreatesAuthorizedKeys(t *testing.T) {
        r := newSshRegistry(t)
        home := mkHome(t, r, "alice")
        _ = home

        raw := sshDeployReq(t, "alice", map[string]string{
                "SHA256:bbb": testEd25519,
                "SHA256:aaa": testEd25519, // duplicate key body, distinct fingerprint: allowed
        })
        res, hint, err := r.sshDeployKeys("id", raw)
        if err != nil {
                t.Fatal(err)
        }
        out := res.(sshDeployResult)
        if out.ManagedCount != 2 || out.ForeignCount != 0 {
                t.Fatalf("want 2 managed / 0 foreign, got %+v", out)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("deploy must queue a WAL audit entry")
        }

        b, err := os.ReadFile(akPath(t, r, "alice"))
        if err != nil {
                t.Fatal(err)
        }
        lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
        if len(lines) != 2 {
                t.Fatalf("want 2 lines, got %q", lines)
        }
        if !strings.Contains(lines[0], "nexus-managed:SHA256:aaa") ||
                !strings.Contains(lines[1], "nexus-managed:SHA256:bbb") {
                t.Fatalf("managed lines must carry markers sorted by fingerprint: %q", lines)
        }
        if !strings.HasPrefix(lines[0], "ssh-ed25519 ") {
                t.Fatalf("managed line must stay a valid key entry: %q", lines[0])
        }

        fi, err := os.Stat(akPath(t, r, "alice"))
        if err != nil {
                t.Fatal(err)
        }
        if fi.Mode().Perm() != 0o600 {
                t.Fatalf("authorized_keys must be 0600, got %v", fi.Mode().Perm())
        }
        dirFi, _ := os.Stat(filepath.Dir(akPath(t, r, "alice")))
        if dirFi.Mode().Perm() != 0o700 {
                t.Fatalf(".ssh must be 0700, got %v", dirFi.Mode().Perm())
        }
}

func TestSshDeployPreservesForeignLinesAndReplacesManaged(t *testing.T) {
        r := newSshRegistry(t)
        mkHome(t, r, "bob")
        ak := akPath(t, r, "bob")
        if err := os.MkdirAll(filepath.Dir(ak), 0o700); err != nil {
                t.Fatal(err)
        }
        old := "ssh-rsa AAAAoldkey boss@old\n" +
                "ssh-ed25519 AAAAprevious nexus-managed:SHA256:stale\n"
        if err := os.WriteFile(ak, []byte(old), 0o600); err != nil {
                t.Fatal(err)
        }

        raw := sshDeployReq(t, "bob", map[string]string{"SHA256:new": testEd25519})
        res, _, err := r.sshDeployKeys("id", raw)
        if err != nil {
                t.Fatal(err)
        }
        out := res.(sshDeployResult)
        if out.ManagedCount != 1 || out.ForeignCount != 1 {
                t.Fatalf("want 1 managed / 1 foreign, got %+v", out)
        }

        b, _ := os.ReadFile(ak)
        s := string(b)
        if !strings.Contains(s, "ssh-rsa AAAAoldkey boss@old") {
                t.Fatalf("foreign line must be preserved verbatim: %q", s)
        }
        if strings.Contains(s, "SHA256:stale") {
                t.Fatalf("stale managed line must be replaced: %q", s)
        }
        if !strings.Contains(s, "nexus-managed:SHA256:new") {
                t.Fatalf("new managed line missing: %q", s)
        }
}

func TestSshDeployEmptySetRemovesOnlyManaged(t *testing.T) {
        r := newSshRegistry(t)
        mkHome(t, r, "carol")
        ak := akPath(t, r, "carol")
        if err := os.MkdirAll(filepath.Dir(ak), 0o700); err != nil {
                t.Fatal(err)
        }
        seed := "ssh-rsa AAAAhandadded user@node\n" +
                "ssh-ed25519 AAAAmine nexus-managed:SHA256:x\n"
        if err := os.WriteFile(ak, []byte(seed), 0o600); err != nil {
                t.Fatal(err)
        }

        raw := rawParams(t, map[string]any{"username": "carol", "keys": []any{}})
        if _, _, err := r.sshDeployKeys("id", raw); err != nil {
                t.Fatal(err)
        }
        b, _ := os.ReadFile(ak)
        s := string(b)
        if !strings.Contains(s, "AAAAhandadded") {
                t.Fatalf("foreign key must survive an empty deploy: %q", s)
        }
        if strings.Contains(s, "nexus-managed") {
                t.Fatalf("managed keys must be gone: %q", s)
        }
}

func TestSshDeployIsIdempotent(t *testing.T) {
        r := newSshRegistry(t)
        mkHome(t, r, "dave")
        req := sshDeployReq(t, "dave", map[string]string{"SHA256:k1": testEd25519})
        if _, _, err := r.sshDeployKeys("id", req); err != nil {
                t.Fatal(err)
        }
        first, err := os.ReadFile(akPath(t, r, "dave"))
        if err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.sshDeployKeys("id", req); err != nil {
                t.Fatal(err)
        }
        second, err := os.ReadFile(akPath(t, r, "dave"))
        if err != nil {
                t.Fatal(err)
        }
        if string(first) != string(second) {
                t.Fatalf("re-deploy must be byte-identical:\n%q\n%q", first, second)
        }
}

func TestSshDeployValidatesInput(t *testing.T) {
        r := newSshRegistry(t)
        mkHome(t, r, "eve")

        cases := []struct {
                name string
                raw  json.RawMessage
        }{
                {"bad key type", sshDeployReq(t, "eve", map[string]string{"SHA256:a": "ssh-dss AAAAbad"})},
                {"multiline key", sshDeployReq(t, "eve", map[string]string{"SHA256:a": testEd25519 + "\nrm -rf"})},
                {"empty fingerprint", rawParams(t, map[string]any{"username": "eve", "keys": []map[string]string{{"fingerprint": "", "public_key": testEd25519}}})},
                {"fingerprint with space", rawParams(t, map[string]any{"username": "eve", "keys": []map[string]string{{"fingerprint": "SHA256: x", "public_key": testEd25519}}})},
                {"duplicate fingerprints", sshDeployReq(t, "eve", map[string]string{"SHA256:a": testEd25519, "SHA256:a ": testEd25519})},
                {"invalid username", rawParams(t, map[string]any{"username": "not A user", "keys": []any{}})},
        }
        for _, c := range cases {
                if _, _, err := r.sshDeployKeys("id", c.raw); err == nil {
                        t.Fatalf("%s: must be rejected", c.name)
                }
        }

        tooMany := map[string]string{}
        for i := 0; i < 51; i++ {
                tooMany[fmt.Sprintf("SHA256:%03d", i)] = testEd25519
        }
        if _, _, err := r.sshDeployKeys("id", sshDeployReq(t, "eve", tooMany)); err == nil {
                t.Fatal("more than 50 keys must be rejected")
        }
}

func TestSshListDeployed(t *testing.T) {
        r := newSshRegistry(t)
        mkHome(t, r, "frida")

        raw := rawParams(t, map[string]any{"username": "frida"})
        res, _, err := r.sshListDeployed("id", raw)
        if err != nil {
                t.Fatal(err)
        }
        if res.(sshListResult).Exists {
                t.Fatal("fresh account has no authorized_keys")
        }

        if _, _, err := r.sshDeployKeys("id", sshDeployReq(t, "frida", map[string]string{
                "SHA256:k1": testEd25519,
        })); err != nil {
                t.Fatal(err)
        }
        ak := akPath(t, r, "frida")
        if err := os.WriteFile(ak, append([]byte("ssh-rsa AAAAforeign x@y\n"), mustRead(t, ak)...), 0o600); err != nil {
                t.Fatal(err)
        }

        res, _, err = r.sshListDeployed("id", raw)
        if err != nil {
                t.Fatal(err)
        }
        out := res.(sshListResult)
        if !out.Exists || len(out.Managed) != 1 || out.ForeignCount != 1 {
                t.Fatalf("want exists with 1 managed / 1 foreign, got %+v", out)
        }
        if out.Managed[0].Fingerprint != "SHA256:k1" {
                t.Fatalf("fingerprint parse wrong: %+v", out.Managed)
        }
        if !strings.HasPrefix(out.Managed[0].PublicKey, "ssh-ed25519 ") {
                t.Fatalf("public key must be reported without the marker: %+v", out.Managed[0])
        }
}

func mustRead(t *testing.T, path string) []byte {
        t.Helper()
        b, err := os.ReadFile(path)
        if err != nil {
                t.Fatal(err)
        }
        return b
}
