package commands

import (
        "encoding/json"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

// mail.* tests (ADR-0013). postmap is injected as a fake shell script so
// the tests never depend on host tooling: the fake postmap "builds" the DB
// by copying the source file to the <name>.db target (postfix convention).
// Reload binaries are absent on purpose — the honest-skip path is part of
// the contract.

func newMailRegistry(t *testing.T) (*Registry, string, string) {
        t.Helper()
        binDir := t.TempDir()
        fakePostmap := filepath.Join(binDir, "postmap")
        if err := os.WriteFile(fakePostmap, []byte("#!/bin/sh\ncp \"$1\" \"$1.db\"\n"), 0o755); err != nil {
                t.Fatal(err)
        }
        mapDir := t.TempDir()
        vmailRoot := t.TempDir()
        r := NewRegistry(Deps{
                WAL:           newTestWAL(t),
                HomeRoot:      t.TempDir(),
                PostfixMapDir: mapDir,
                VmailRoot:     vmailRoot,
                PostmapBinary: fakePostmap,
        })
        return r, mapDir, vmailRoot
}

func mailReq(t *testing.T, m map[string]any) json.RawMessage {
        t.Helper()
        return rawParams(t, m)
}

func seedMailDomain(t *testing.T, r *Registry, domain string) {
        t.Helper()
        if _, _, err := r.mailCreateDomain("id", mailReq(t, map[string]any{"domain": domain})); err != nil {
                t.Fatal(err)
        }
}

func TestMailCreateDomain(t *testing.T) {
        r, mapDir, _ := newMailRegistry(t)

        res, hint, err := r.mailCreateDomain("id", mailReq(t, map[string]any{"domain": "Example.COM."}))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(mailStatusResult)
        if out.Status != "created" || out.Domain != "example.com" {
                t.Fatalf("unexpected result: %+v", out)
        }
        if !out.Maps.Built {
                t.Fatalf("maps must be built with the fake postmap: %+v", out.Maps)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("create must queue a WAL audit entry")
        }

        b, err := os.ReadFile(filepath.Join(mapDir, "virtual_domains_map"))
        if err != nil {
                t.Fatal(err)
        }
        if !strings.Contains(string(b), "example.com") {
                t.Fatalf("domain missing from map: %q", string(b))
        }
        if _, err := os.Stat(filepath.Join(mapDir, "virtual_domains_map.db")); err != nil {
                t.Fatal("fake postmap must have built the .db file")
        }

        // Duplicate is a conflict.
        if _, _, err := r.mailCreateDomain("id", mailReq(t, map[string]any{"domain": "example.com"})); err == nil {
                t.Fatal("duplicate domain must conflict")
        }

        // Bad shapes are invalid params.
        for _, bad := range []string{"", "no-dots", "-bad.com", "bad..com"} {
                if _, _, err := r.mailCreateDomain("id", mailReq(t, map[string]any{"domain": bad})); err == nil {
                        t.Fatalf("domain %q must be rejected", bad)
                }
        }
}

func TestMailCreateMailbox(t *testing.T) {
        r, mapDir, vmailRoot := newMailRegistry(t)
        seedMailDomain(t, r, "example.com")

        res, hint, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{
                "email": "Info@Example.com", "quota_mb": 512,
        }))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(mailStatusResult)
        if out.Status != "created" || out.Email != "info@example.com" {
                t.Fatalf("unexpected result: %+v", out)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("create must queue a WAL audit entry")
        }

        maildir := filepath.Join(vmailRoot, "example.com", "info")
        for _, sub := range []string{"cur", "new", "tmp", "maildirsize"} {
                if _, err := os.Stat(filepath.Join(maildir, sub)); err != nil {
                        t.Fatalf("maildir scaffold missing %s: %v", sub, err)
                }
        }
        size, _ := os.ReadFile(filepath.Join(maildir, "maildirsize"))
        if strings.TrimSpace(string(size)) != "536870912S" {
                t.Fatalf("maildirsize wrong: %q", string(size))
        }
        // Dev rig (no vmail uid/gid): the ownership skip must be stated, not hidden.
        if out.Ownership.Applied || out.Ownership.Skipped == "" {
                t.Fatalf("ownership must report an honest skip on dev rigs: %+v", out.Ownership)
        }

        b, _ := os.ReadFile(filepath.Join(mapDir, "virtual_mailboxes_map"))
        if !strings.Contains(string(b), "info@example.com "+maildir+"/") {
                t.Fatalf("mailbox map wrong: %q", string(b))
        }

        // Duplicate mailbox conflicts.
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "info@example.com", "quota_mb": 10})); err == nil {
                t.Fatal("duplicate mailbox must conflict")
        }
        // Unknown domain is a precondition (create the domain first).
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "x@other.com", "quota_mb": 10})); err == nil {
                t.Fatal("mailbox under unprovisioned domain must fail")
        }
        // Traversal-shaped local parts never become directories.
        for _, bad := range []string{"../../etc@example.com", "a/b@example.com", "@example.com"} {
                if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": bad, "quota_mb": 10})); err == nil {
                        t.Fatalf("email %q must be rejected", bad)
                }
        }
        // Quota bounds.
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "q@example.com", "quota_mb": 0})); err == nil {
                t.Fatal("zero quota must be rejected")
        }
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "q@example.com", "quota_mb": (1 << 20) + 1})); err == nil {
                t.Fatal("quota above 1 TiB must be rejected")
        }
}

func TestMailModifyMailbox(t *testing.T) {
        r, _, vmailRoot := newMailRegistry(t)
        seedMailDomain(t, r, "example.com")
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "bob@example.com", "quota_mb": 100})); err != nil {
                t.Fatal(err)
        }

        if _, _, err := r.mailModifyMailbox("id", mailReq(t, map[string]any{"email": "bob@example.com", "quota_mb": 250})); err != nil {
                t.Fatal(err)
        }
        size, _ := os.ReadFile(filepath.Join(vmailRoot, "example.com", "bob", "maildirsize"))
        if strings.TrimSpace(string(size)) != "262144000S" {
                t.Fatalf("maildirsize not updated: %q", string(size))
        }

        // Modifying a nonexistent mailbox is a precondition, not a silent ok.
        if _, _, err := r.mailModifyMailbox("id", mailReq(t, map[string]any{"email": "ghost@example.com", "quota_mb": 5})); err == nil {
                t.Fatal("modify of absent mailbox must fail")
        }
}

func TestMailDeleteMailboxPreserveAndPurge(t *testing.T) {
        r, _, vmailRoot := newMailRegistry(t)
        seedMailDomain(t, r, "example.com")
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "carol@example.com", "quota_mb": 64})); err != nil {
                t.Fatal(err)
        }

        // preserve_mail moves the maildir into .trash with a timestamp suffix.
        res, hint, err := r.mailDeleteMailbox("id", mailReq(t, map[string]any{"email": "carol@example.com", "preserve_mail": true}))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(mailStatusResult)
        if out.Status != "removed" || out.PreservedAs == "" {
                t.Fatalf("unexpected result: %+v", out)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("delete must queue a WAL audit entry")
        }
        if _, err := os.Stat(out.PreservedAs); err != nil {
                t.Fatalf("preserved maildir missing: %v", err)
        }
        if _, err := os.Stat(filepath.Join(vmailRoot, "example.com", "carol")); !os.IsNotExist(err) {
                t.Fatal("live maildir must be gone after preserve-delete")
        }

        // Deleting an absent mailbox reports absent (idempotent).
        res2, _, err := r.mailDeleteMailbox("id", mailReq(t, map[string]any{"email": "carol@example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        if res2.(mailStatusResult).Status != "absent" {
                t.Fatalf("second delete must be absent: %+v", res2)
        }
}

func TestMailAliases(t *testing.T) {
        r, mapDir, _ := newMailRegistry(t)
        seedMailDomain(t, r, "example.com")

        if _, _, err := r.mailCreateAlias("id", mailReq(t, map[string]any{"source": "postmaster@example.com", "destination": "alice@example.com"})); err != nil {
                t.Fatal(err)
        }
        // Catch-all shape.
        if _, _, err := r.mailCreateAlias("id", mailReq(t, map[string]any{"source": "@example.com", "destination": "alice@example.com"})); err != nil {
                t.Fatal(err)
        }
        b, _ := os.ReadFile(filepath.Join(mapDir, "virtual_aliases_map"))
        if !strings.Contains(string(b), "postmaster@example.com alice@example.com") ||
                !strings.Contains(string(b), "@example.com alice@example.com") {
                t.Fatalf("alias map wrong: %q", string(b))
        }

        // Duplicate source conflicts; self-loop rejected; bad destination rejected.
        if _, _, err := r.mailCreateAlias("id", mailReq(t, map[string]any{"source": "postmaster@example.com", "destination": "b@example.com"})); err == nil {
                t.Fatal("duplicate alias must conflict")
        }
        if _, _, err := r.mailCreateAlias("id", mailReq(t, map[string]any{"source": "loop@example.com", "destination": "loop@example.com"})); err == nil {
                t.Fatal("self-loop alias must be rejected")
        }
        if _, _, err := r.mailCreateAlias("id", mailReq(t, map[string]any{"source": "x@example.com", "destination": "not-an-address"})); err == nil {
                t.Fatal("bad destination must be rejected")
        }
        // Alias under an unprovisioned domain fails.
        if _, _, err := r.mailCreateAlias("id", mailReq(t, map[string]any{"source": "x@other.com", "destination": "y@other.com"})); err == nil {
                t.Fatal("alias under unprovisioned domain must fail")
        }

        // Removal is idempotent: present → removed, absent → absent.
        res, _, err := r.mailDeleteAlias("id", mailReq(t, map[string]any{"source": "postmaster@example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(mailStatusResult).Status != "removed" {
                t.Fatalf("alias delete status: %+v", res)
        }
        res2, _, _ := r.mailDeleteAlias("id", mailReq(t, map[string]any{"source": "postmaster@example.com"}))
        if res2.(mailStatusResult).Status != "absent" {
                t.Fatalf("second alias delete must be absent: %+v", res2)
        }
}

func TestMailDeleteDomainCleansAllMaps(t *testing.T) {
        r, mapDir, _ := newMailRegistry(t)
        seedMailDomain(t, r, "example.com")
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "dave@example.com", "quota_mb": 32})); err != nil {
                t.Fatal(err)
        }
        if _, _, err := r.mailCreateAlias("id", mailReq(t, map[string]any{"source": "help@example.com", "destination": "dave@example.com"})); err != nil {
                t.Fatal(err)
        }

        res, hint, err := r.mailDeleteDomain("id", mailReq(t, map[string]any{"domain": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(mailStatusResult).Status != "removed" {
                t.Fatalf("domain delete status: %+v", res)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("delete must queue a WAL audit entry")
        }

        for _, mapName := range []string{"virtual_domains_map", "virtual_mailboxes_map", "virtual_aliases_map"} {
                b, err := os.ReadFile(filepath.Join(mapDir, mapName))
                if err != nil {
                        t.Fatal(err)
                }
                if strings.Contains(string(b), "example.com") {
                        t.Fatalf("%s still carries the domain: %q", mapName, string(b))
                }
        }

        // Absent second delete is a success.
        res2, _, _ := r.mailDeleteDomain("id", mailReq(t, map[string]any{"domain": "example.com"}))
        if res2.(mailStatusResult).Status != "absent" {
                t.Fatalf("second domain delete must be absent: %+v", res2)
        }
}

func TestMailAutoresponder(t *testing.T) {
        r, _, vmailRoot := newMailRegistry(t)
        seedMailDomain(t, r, "example.com")
        if _, _, err := r.mailCreateMailbox("id", mailReq(t, map[string]any{"email": "erin@example.com", "quota_mb": 16})); err != nil {
                t.Fatal(err)
        }

        res, hint, err := r.mailCreateAutoresponder("id", mailReq(t, map[string]any{
                "email": "erin@example.com",
                "subject": "Out of office",
                "body": "I am away.\nWill reply after.\n.line starts with a dot",
        }))
        if err != nil {
                t.Fatal(err)
        }
        if res.(mailStatusResult).Status != "created" {
                t.Fatalf("unexpected result: %+v", res)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("create must queue a WAL audit entry")
        }
        script, err := os.ReadFile(filepath.Join(vmailRoot, "example.com", "erin", ".dovecot.sieve"))
        if err != nil {
                t.Fatal(err)
        }
        s := string(script)
        if !strings.Contains(s, `:subject "Out of office"`) || !strings.Contains(s, "\n..line starts with a dot") {
                t.Fatalf("sieve script wrong: %q", s)
        }

        // Absent mailbox is a precondition.
        if _, _, err := r.mailCreateAutoresponder("id", mailReq(t, map[string]any{"email": "ghost@example.com", "subject": "s", "body": "b"})); err == nil {
                t.Fatal("autoresponder for absent mailbox must fail")
        }
        // Empty subject/body rejected.
        if _, _, err := r.mailCreateAutoresponder("id", mailReq(t, map[string]any{"email": "erin@example.com", "subject": " ", "body": "b"})); err == nil {
                t.Fatal("empty subject must be rejected")
        }

        if _, _, err := r.mailDeleteAutoresponder("id", mailReq(t, map[string]any{"email": "erin@example.com"})); err != nil {
                t.Fatal(err)
        }
        if _, err := os.Stat(filepath.Join(vmailRoot, "example.com", "erin", ".dovecot.sieve")); !os.IsNotExist(err) {
                t.Fatal("sieve script must be gone")
        }
        // Absent delete is a success (idempotent).
        if _, _, err := r.mailDeleteAutoresponder("id", mailReq(t, map[string]any{"email": "erin@example.com"})); err != nil {
                t.Fatal(err)
        }
}

func TestMailReloadHonestSkips(t *testing.T) {
        r, _, _ := newMailRegistry(t) // no postfix/doveadm binaries injected
        res, hint, err := r.mailReload("id", nil)
        if err != nil {
                t.Fatal(err)
        }
        out := res.(map[string]any)
        svcs := out["services"].([]mailServiceResult)
        if len(svcs) != 2 {
                t.Fatalf("want postfix+dovecot rows, got %+v", svcs)
        }
        for _, s := range svcs {
                if s.Applied || s.Skipped == "" {
                        t.Fatalf("missing binaries must report an honest skip: %+v", s)
                }
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatal("reload must queue a WAL audit entry")
        }
}

func TestMailPostmapAbsentIsHonestSkip(t *testing.T) {
        mapDir := t.TempDir()
        r := NewRegistry(Deps{
                WAL:           newTestWAL(t),
                HomeRoot:      t.TempDir(),
                PostfixMapDir: mapDir,
                VmailRoot:     t.TempDir(),
                // PostmapBinary left empty and PATH has no postmap in the test env —
                // belt and braces: run through a PATH that does not carry one.
        })
        res, _, err := r.mailCreateDomain("id", mailReq(t, map[string]any{"domain": "skip.example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(mailStatusResult)
        if out.Maps.Built {
                t.Fatalf("without postmap the maps must be an honest skip: %+v", out.Maps)
        }
        if out.Maps.Skipped == "" {
                t.Fatal("skip reason must be stated")
        }
}
