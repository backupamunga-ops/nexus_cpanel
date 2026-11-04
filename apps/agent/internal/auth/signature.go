// Package auth verifies control-plane command signatures (spec §3, §5).
//
// Every command envelope carries:
//
//	issued_at, expires_at (RFC3339 UTC; expires_at at most 60s after issued_at)
//	signature = base64(ed25519_sign(method || raw_params || issued_at || expires_at))
//
// The signature input is the concatenation of UTF-8 byte strings: the method name,
// the RAW params JSON bytes exactly as received (no canonicalization — the control
// plane signs the bytes it serialized), and the two timestamp strings.
package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// MaxValidityWindow is the maximum allowed distance between issued_at and expires_at.
const MaxValidityWindow = 60 * time.Second

// MaxClockSkew tolerates minor clock differences for issued_at in the past.
const MaxClockSkew = 5 * time.Second

var (
	ErrUnsigned       = errors.New("command is not signed")
	ErrBadSignature   = errors.New("command signature verification failed")
	ErrExpired        = errors.New("command validity window expired")
	ErrWindowTooLong  = errors.New("command validity window exceeds maximum")
	ErrIssuedInFuture = errors.New("command issued_at is in the future")
	ErrNoKeyLoaded    = errors.New("no signing key loaded and dev mode disabled")
)

// Verifier validates envelopes. In dev mode (no key file), unsigned commands are
// accepted with a loud warning — this must NEVER be enabled on a real node.
type Verifier struct {
	key     ed25519.PublicKey
	devMode bool
}

// NewVerifier loads the control-plane public key. In dev mode the key file may be
// absent; the returned verifier accepts unsigned commands and PrintDevWarning
// advertises the fact.
func NewVerifier(keyPath string, devMode bool) (*Verifier, error) {
	v := &Verifier{devMode: devMode}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		if devMode {
			PrintDevWarning()
			return v, nil
		}
		return nil, fmt.Errorf("read signing key %s: %w", keyPath, err)
	}
	key, err := ParsePublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	v.key = key
	return v, nil
}

// ParsePublicKey accepts either raw base64 (32 bytes) or PEM ED25519 PUBLIC KEY.
func ParsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(string(raw))
	if block, _ := pem.Decode(raw); block != nil && block.Type == "ED25519 PUBLIC KEY" {
		s = strings.TrimSpace(string(block.Bytes))
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if len(s) == ed25519.PublicKeySize {
		return ed25519.PublicKey(s), nil
	}
	return nil, fmt.Errorf("not a valid ed25519 public key (%d bytes)", len(s))
}

// EnvelopeMeta carries the fields participating in the signature.
type EnvelopeMeta struct {
	Method    string
	RawParams []byte // raw JSON bytes as received
	IssuedAt  string
	ExpiresAt string
}

// SignatureInput reconstructs the exact signed byte string.
func (m EnvelopeMeta) SignatureInput() []byte {
	b := make([]byte, 0, len(m.Method)+len(m.RawParams)+len(m.IssuedAt)+len(m.ExpiresAt))
	b = append(b, m.Method...)
	b = append(b, m.RawParams...)
	b = append(b, m.IssuedAt...)
	b = append(b, m.ExpiresAt...)
	return b
}

// Verify checks the validity window and the Ed25519 signature over the envelope.
// A nil signature is only acceptable in dev mode.
func (v *Verifier) Verify(m EnvelopeMeta, signatureB64 string, now time.Time) error {
	if v.key == nil {
		if v.devMode && signatureB64 == "" {
			return nil // dev mode: accepted, warned at startup
		}
		return ErrNoKeyLoaded
	}
	if signatureB64 == "" {
		return ErrUnsigned
	}
	issued, err := time.Parse(time.RFC3339, m.IssuedAt)
	if err != nil {
		return fmt.Errorf("issued_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return fmt.Errorf("expires_at: %w", err)
	}
	if window := expires.Sub(issued); window > MaxValidityWindow || window < 0 {
		return ErrWindowTooLong
	}
	if issued.After(now.Add(MaxClockSkew)) {
		return ErrIssuedInFuture
	}
	if now.After(expires) {
		return ErrExpired
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return ErrBadSignature
	}
	if !ed25519.Verify(v.key, m.SignatureInput(), sig) {
		return ErrBadSignature
	}
	return nil
}

// PrintDevWarning is emitted when the agent accepts unsigned commands.
func PrintDevWarning() {
	fmt.Fprint(os.Stderr, `
======================================================================
 DEV MODE: UNSIGNED COMMANDS ARE ACCEPTED. NEVER RUN ON A REAL NODE.
======================================================================
`)
}
