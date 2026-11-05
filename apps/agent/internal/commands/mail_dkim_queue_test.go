package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B08 tests (ADR-0014): DKIM key storage + DNS TXT derivation with an
// injected key root, queue parsing against a captured postqueue sample,
// and honest precondition errors when the queue binaries are absent.

func rsaPem(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func TestMailApplyDkim(t *testing.T) {
	r, _, _ := newMailRegistry(t)
	keyRoot := t.TempDir()
	tableDir := t.TempDir()
	r.deps.OpendkimKeyRoot = keyRoot
	r.deps.OpendkimTableDir = tableDir

	res, hint, err := r.mailApplyDkim("id", mailReq(t, map[string]any{
		"domain": "example.com", "selector": "default", "private_key_pem": rsaPem(t, 2048),
	}))
	if err != nil {
		t.Fatal(err)
	}
	out := res.(mailDkimResult)
	if out.Status != "created" || out.Selector != "default" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !strings.HasPrefix(out.DnsTxt, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("dns txt wrong: %q", out.DnsTxt)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("apply must queue a WAL audit entry")
	}

	keyBytes, err := os.ReadFile(filepath.Join(keyRoot, "example.com", "default.private"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keyBytes), "BEGIN RSA PRIVATE KEY") {
		t.Fatal("key file must hold the PEM")
	}
	kt, _ := os.ReadFile(filepath.Join(tableDir, "KeyTable"))
	if !strings.Contains(string(kt), "default._domainkey.example.com example.com:default:") {
		t.Fatalf("KeyTable wrong: %q", string(kt))
	}
	st, _ := os.ReadFile(filepath.Join(tableDir, "SigningTable"))
	if !strings.Contains(string(st), "@example.com default._domainkey.example.com") {
		t.Fatalf("SigningTable wrong: %q", string(st))
	}

	// Rejections: bad selector, non-RSA/invalid PEM, undersized key.
	if _, _, err := r.mailApplyDkim("id", mailReq(t, map[string]any{
		"domain": "example.com", "selector": "bad selector", "private_key_pem": rsaPem(t, 2048),
	})); err == nil {
		t.Fatal("bad selector must be rejected")
	}
	if _, _, err := r.mailApplyDkim("id", mailReq(t, map[string]any{
		"domain": "example.com", "selector": "s", "private_key_pem": "not pem",
	})); err == nil {
		t.Fatal("invalid pem must be rejected")
	}
	if _, _, err := r.mailApplyDkim("id", mailReq(t, map[string]any{
		"domain": "example.com", "selector": "small", "private_key_pem": rsaPem(t, 512),
	})); err == nil {
		t.Fatal("undersized key must be rejected")
	}
}

func TestMailQueueListParsing(t *testing.T) {
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "postqueue")
	sample := `-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
AB12CD34EF     512 Tue Nov  4 09:15:22  bounce@example.com
(connect to mx.example.net[203.0.113.9]:25: Connection refused)
                                         rcpt@example.net
FF98GG77HH     100 Tue Nov  4 10:00:01  news@example.org
(timeout)
                                         other@example.net

-- 2 Kbytes in 2 Requests.`
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ncat <<'EOF'\n"+sample+"\nEOF\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry(Deps{
		WAL:             newTestWAL(t),
		HomeRoot:        t.TempDir(),
		PostfixMapDir:   t.TempDir(),
		VmailRoot:       t.TempDir(),
		PostqueueBinary: fake,
	})
	res, hint, err := r.mailQueueList("id", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.(mailQueueListResult)
	if out.Total != 2 {
		t.Fatalf("want 2 entries, got %+v", out)
	}
	if hint != nil {
		t.Fatal("read-only methods must not queue audit entries")
	}
	first := out.Queue[0]
	if first.QueueID != "AB12CD34EF" || first.Sender != "bounce@example.com" || first.Recipient != "rcpt@example.net" {
		t.Fatalf("first entry wrong: %+v", first)
	}
	if !strings.Contains(first.Reason, "Connection refused") {
		t.Fatalf("reason not attached: %+v", first)
	}
	if out.Queue[1].QueueID != "FF98GG77HH" {
		t.Fatalf("second entry wrong: %+v", out.Queue[1])
	}

	// Empty queue sample.
	empty := filepath.Join(binDir, "postqueue-empty")
	if err := os.WriteFile(empty, []byte("#!/bin/sh\necho 'Mail queue is empty'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.deps.PostqueueBinary = empty
	res2, _, err := r.mailQueueList("id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.(mailQueueListResult).Total != 0 {
		t.Fatalf("empty queue must parse to zero entries: %+v", res2)
	}
}

func TestMailQueueAbsentBinaryIsLoud(t *testing.T) {
	r := NewRegistry(Deps{
		WAL:           newTestWAL(t),
		HomeRoot:      t.TempDir(),
		PostfixMapDir: t.TempDir(),
		VmailRoot:     t.TempDir(),
	})
	if _, _, err := r.mailQueueList("id", nil); err == nil {
		t.Fatal("missing postqueue must be a loud precondition error, not an empty queue")
	}
	if _, _, err := r.mailQueueFlush("id", mailReq(t, map[string]any{})); err == nil {
		t.Fatal("missing postqueue must be loud on flush")
	}
	if _, _, err := r.mailQueueRetry("id", mailReq(t, map[string]any{"message_id": "AB12CD34EF"})); err == nil {
		t.Fatal("missing postsuper must be loud on retry")
	}
}

func TestMailQueueFlushAndRetryShapes(t *testing.T) {
	binDir := t.TempDir()
	pq := filepath.Join(binDir, "postqueue")
	if err := os.WriteFile(pq, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(binDir, "postsuper")
	if err := os.WriteFile(ps, []byte("#!/bin/sh\necho 'AB12CD34EF: requeued'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry(Deps{
		WAL:             newTestWAL(t),
		HomeRoot:        t.TempDir(),
		PostfixMapDir:   t.TempDir(),
		VmailRoot:       t.TempDir(),
		PostqueueBinary: pq,
		PostsuperBinary: ps,
	})

	res, hint, err := r.mailQueueFlush("id", mailReq(t, map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["status"] != "flushed" {
		t.Fatalf("flush result: %+v", res)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatal("flush must queue a WAL audit entry")
	}

	if _, _, err := r.mailQueueFlush("id", mailReq(t, map[string]any{"queue_id": "bad id!"})); err == nil {
		t.Fatal("invalid queue_id must be rejected")
	}

	res2, hint2, err := r.mailQueueRetry("id", mailReq(t, map[string]any{"message_id": "AB12CD34EF"}))
	if err != nil {
		t.Fatal(err)
	}
	if res2.(map[string]any)["status"] != "requeued" {
		t.Fatalf("retry result: %+v", res2)
	}
	if hint2 == nil || hint2.EntryID == "" {
		t.Fatal("retry must queue a WAL audit entry")
	}
	if _, _, err := r.mailQueueRetry("id", mailReq(t, map[string]any{"message_id": "no"})); err == nil {
		t.Fatal("invalid message_id must be rejected")
	}
}
