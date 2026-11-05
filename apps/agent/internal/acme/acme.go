// Package acme implements the minimal ACME v2 (RFC 8555) client the agent
// needs for http-01 issuance: directory discovery, ES256 JWS with nonce
// management, newAccount, newOrder, authorization polling, challenge
// readiness, finalize with a CSR, and certificate-chain fetch.
//
// Scope discipline: exactly what issuance requires, nothing else — no
// renewal logic (the control plane re-issues), no dns-01 (no DNS write
// path yet), no key rollover. The client is stdlib-only; the HTTP client
// is injectable so tests run against a fake CA.
package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Directory is the CA's endpoint map (RFC 8555 §7.1.1).
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type Order struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
	Location       string   `json:"-"`
}

type Authz struct {
	Status     string      `json:"status"`
	Challenges []Challenge `json:"challenges"`
}

type Challenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

// Account is the created/retrieved ACME account (its URL is the kid).
type Account struct {
	URL string
}

type Client struct {
	DirectoryURL string
	Key          *ecdsa.PrivateKey
	HTTP         *http.Client

	dir        Directory
	accountURL string
}

// New creates a client; the HTTP client defaults to a 30 s timeout one.
func New(directoryURL string, key *ecdsa.PrivateKey, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{DirectoryURL: directoryURL, Key: key, HTTP: hc}
}

// GenerateKey creates a P-256 account key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EnsureDirectory fetches and caches the directory document.
func (c *Client) EnsureDirectory() error {
	if c.dir.NewOrder != "" {
		return nil
	}
	resp, err := c.HTTP.Get(c.DirectoryURL)
	if err != nil {
		return fmt.Errorf("acme directory: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme directory: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&c.dir); err != nil {
		return fmt.Errorf("acme directory decode: %w", err)
	}
	return nil
}

// fetchNonce pulls a fresh anti-replay nonce (RFC 8555 §7.2).
func (c *Client) fetchNonce() (string, error) {
	req, err := http.NewRequest(http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("acme nonce: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", errors.New("acme nonce: empty Replay-Nonce")
	}
	return n, nil
}

// b64 is the RFC 7515 base64url encoding without padding.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// thumbprint is the RFC 7638 JWK thumbprint of the account key.
func (c *Client) thumbprint() (string, error) {
	pub := c.Key.Public().(*ecdsa.PublicKey)
	jwk := map[string]string{"crv": "P-256", "kty": "EC", "x": b64(pub.X.FillBytes(make([]byte, 32))), "y": b64(pub.Y.FillBytes(make([]byte, 32)))}
	canonical, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return b64(sum[:]), nil
}

// jwsRequest performs one authenticated POST (JWS with ES256). When kid is
// empty the JWK is embedded (newAccount); otherwise kid is used.
func (c *Client) jwsRequest(url string, payload any, kid string) (*http.Response, []byte, error) {
	if err := c.EnsureDirectory(); err != nil {
		return nil, nil, err
	}
	nonce, err := c.fetchNonce()
	if err != nil {
		return nil, nil, err
	}

	var payloadB64 string
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		payloadB64 = b64(raw)
	} else {
		payloadB64 = "" // empty-payload POSTs for challenge readiness
	}

	protected := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if kid == "" {
		pub := c.Key.Public().(*ecdsa.PublicKey)
		protected["jwk"] = map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": b64(pub.X.FillBytes(make([]byte, 32))),
			"y": b64(pub.Y.FillBytes(make([]byte, 32))),
		}
	} else {
		protected["kid"] = kid
	}
	protJSON, err := json.Marshal(protected)
	if err != nil {
		return nil, nil, err
	}
	protB64 := b64(protJSON)

	signing := []byte(protB64 + "." + payloadB64)
	digest := sha256.Sum256(signing)
	r, s, err := ecdsa.Sign(rand.Reader, c.Key, digest[:])
	if err != nil {
		return nil, nil, err
	}
	sig := make([]byte, 64)
	copy(sig[:32], r.FillBytes(make([]byte, 32)))
	copy(sig[32:], s.FillBytes(make([]byte, 32)))

	body := map[string]string{
		"protected": protB64,
		"payload":   payloadB64,
		"signature": b64(sig),
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	defer func() { _ = resp.Body.Close() }()
	if c2 := resp.Header.Get("Replay-Nonce"); c2 != "" {
		// keep for potential retry logic later; ignored in this minimal client
		_ = c2
	}
	return resp, raw, nil
}

// NewAccount creates (or retrieves) the account and caches its kid URL.
func (c *Client) NewAccount(email string, tosAccepted bool) (*Account, error) {
	if err := c.EnsureDirectory(); err != nil {
		return nil, err
	}
	payload := map[string]any{"onlyReturnExisting": false}
	if tosAccepted {
		payload["termsOfServiceAgreed"] = true
	}
	if email != "" {
		payload["contact"] = []string{"mailto:" + email}
	}
	resp, raw, err := c.jwsRequest(c.dir.NewAccount, payload, "")
	if err != nil {
		return nil, err
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, fmt.Errorf("acme newAccount: no Location header (status %d): %s", resp.StatusCode, truncate(raw))
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme newAccount: status %d: %s", resp.StatusCode, truncate(raw))
	}
	c.accountURL = loc
	return &Account{URL: loc}, nil
}

// NewOrder requests a certificate order for the given DNS identifiers.
func (c *Client) NewOrder(domains []string) (*Order, error) {
	if c.accountURL == "" {
		return nil, errors.New("acme newOrder: no account (NewAccount first)")
	}
	ids := make([]map[string]string, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	resp, raw, err := c.jwsRequest(c.dir.NewOrder, map[string]any{"identifiers": ids}, c.accountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("acme newOrder: status %d: %s", resp.StatusCode, truncate(raw))
	}
	var o Order
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("acme newOrder decode: %w", err)
	}
	o.Location = resp.Header.Get("Location")
	return &o, nil
}

// GetAuthz fetches one authorization object.
func (c *Client) GetAuthz(url string) (*Authz, error) {
	resp, raw, err := c.jwsRequest(url, nil, c.accountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme authz: status %d: %s", resp.StatusCode, truncate(raw))
	}
	var a Authz
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("acme authz decode: %w", err)
	}
	return &a, nil
}

// ReadyChallenge answers a challenge (empty-payload POST). The caller must
// have made the challenge response servable BEFORE calling this.
func (c *Client) ReadyChallenge(url string) error {
	resp, raw, err := c.jwsRequest(url, nil, c.accountURL)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("acme challenge: status %d: %s", resp.StatusCode, truncate(raw))
	}
	return nil
}

// WaitAuthzValid polls an authorization until valid or invalid (deadline).
func (c *Client) WaitAuthzValid(url string, deadline time.Time) error {
	for {
		a, err := c.GetAuthz(url)
		if err != nil {
			return err
		}
		switch a.Status {
		case "valid":
			return nil
		case "invalid", "revoked", "expired":
			return fmt.Errorf("acme authz %s: %s", url, a.Status)
		}
		if time.Now().After(deadline) {
			return errors.New("acme authz: timeout waiting for validation")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// WaitOrderReady polls the order until ready to finalize.
func (c *Client) WaitOrderReady(orderURL string, deadline time.Time) (*Order, error) {
	for {
		o, err := c.GetOrder(orderURL)
		if err != nil {
			return nil, err
		}
		switch o.Status {
		case "ready":
			return o, nil
		case "valid":
			return o, nil
		case "invalid":
			return nil, errors.New("acme order: invalid")
		}
		if time.Now().After(deadline) {
			return nil, errors.New("acme order: timeout waiting for ready")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// GetOrder fetches the order by URL.
func (c *Client) GetOrder(url string) (*Order, error) {
	resp, raw, err := c.jwsRequest(url, nil, c.accountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme order: status %d: %s", resp.StatusCode, truncate(raw))
	}
	var o Order
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("acme order decode: %w", err)
	}
	return &o, nil
}

// Finalize submits the CSR and returns the (possibly still processing) order.
func (c *Client) Finalize(order *Order, csrDER []byte) (*Order, error) {
	resp, raw, err := c.jwsRequest(order.Finalize, map[string]any{"csr": b64(csrDER)}, c.accountURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("acme finalize: status %d: %s", resp.StatusCode, truncate(raw))
	}
	var o Order
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("acme finalize decode: %w", err)
	}
	return &o, nil
}

// FetchCertificate downloads the PEM certificate chain.
func (c *Client) FetchCertificate(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/pem-certificate-chain")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme cert fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("acme cert fetch: status %d: %s", resp.StatusCode, truncate(raw))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// DNS01Record returns the TXT record value for a dns-01 challenge token —
// included for completeness of the challenge math; dns-01 issuance itself
// is out of scope until the DNS write path exists.
func DNS01Record(token, keyAuthorization string) string {
	sum := sha256.Sum256([]byte(keyAuthorization))
	return b64(sum[:])
}

// KeyAuthorization builds the challenge response string.
func KeyAuthorization(token string, c *Client) (string, error) {
	tp, err := c.thumbprint()
	if err != nil {
		return "", err
	}
	return token + "." + tp, nil
}

// MakeCSR builds a CSR for the given domains with a fresh P-256 key. The
// returned PEM is the private key material for the leaf (caller stores it),
// the DER the CSR to finalize with.
func MakeCSR(domains []string) (leafKeyPEM []byte, csrDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return keyPEM, der, nil
}

// ParseCertChainPEM extracts the leaf certificate for metadata (expiry,
// SANs, issuer) from a PEM chain.
func ParseCertChainPEM(pemBytes []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no certificate in PEM chain")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return cert, nil
			}
		}
		pemBytes = rest
	}
}

func truncate(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}
