package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func signMeta(priv ed25519.PrivateKey, m EnvelopeMeta) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m.SignatureInput()))
}

func TestVerifyHappyPath(t *testing.T) {
	pub, priv := testKey(t)
	v := &Verifier{key: pub}
	now := time.Now().UTC()
	m := EnvelopeMeta{
		Method:    "account.create",
		RawParams: []byte(`{"username":"alice"}`),
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339),
	}
	if err := v.Verify(m, signMeta(priv, m), now); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyTamperedParams(t *testing.T) {
	pub, priv := testKey(t)
	v := &Verifier{key: pub}
	now := time.Now().UTC()
	m := EnvelopeMeta{
		Method:    "account.create",
		RawParams: []byte(`{"username":"alice"}`),
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339),
	}
	sig := signMeta(priv, m)
	m.RawParams = []byte(`{"username":"root"}`) // attacker swaps params after signing
	if err := v.Verify(m, sig, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	pub, priv := testKey(t)
	v := &Verifier{key: pub}
	now := time.Now().UTC()
	m := EnvelopeMeta{
		Method:    "system.health",
		IssuedAt:  now.Add(-2 * time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(-1 * time.Minute).Format(time.RFC3339),
	}
	if err := v.Verify(m, signMeta(priv, m), now); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyWindowTooLong(t *testing.T) {
	pub, priv := testKey(t)
	v := &Verifier{key: pub}
	now := time.Now().UTC()
	m := EnvelopeMeta{
		Method:    "system.health",
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(61 * time.Second).Format(time.RFC3339), // > 60s max
	}
	if err := v.Verify(m, signMeta(priv, m), now); !errors.Is(err, ErrWindowTooLong) {
		t.Fatalf("want ErrWindowTooLong, got %v", err)
	}
}

func TestVerifyIssuedInFuture(t *testing.T) {
	pub, priv := testKey(t)
	v := &Verifier{key: pub}
	now := time.Now().UTC()
	m := EnvelopeMeta{
		Method:    "system.health",
		IssuedAt:  now.Add(10 * time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(11 * time.Minute).Format(time.RFC3339),
	}
	if err := v.Verify(m, signMeta(priv, m), now); !errors.Is(err, ErrIssuedInFuture) {
		t.Fatalf("want ErrIssuedInFuture, got %v", err)
	}
}

func TestVerifyUnsignedStrictMode(t *testing.T) {
	pub, _ := testKey(t)
	v := &Verifier{key: pub}
	now := time.Now().UTC()
	m := EnvelopeMeta{
		Method:    "system.health",
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339),
	}
	if err := v.Verify(m, "", now); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("want ErrUnsigned, got %v", err)
	}
}

func TestVerifyDevModeAllowsUnsigned(t *testing.T) {
	v := &Verifier{devMode: true}
	now := time.Now().UTC()
	m := EnvelopeMeta{
		Method:    "system.health",
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339),
	}
	if err := v.Verify(m, "", now); err != nil {
		t.Fatalf("dev mode should accept unsigned, got %v", err)
	}
}

func TestParsePublicKeyRawBase64(t *testing.T) {
	pub, _ := testKey(t)
	got, err := ParsePublicKey([]byte(base64.StdEncoding.EncodeToString(pub)))
	if err != nil {
		t.Fatalf("parse raw: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("roundtrip mismatch")
	}
}
