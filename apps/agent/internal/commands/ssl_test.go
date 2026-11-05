package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/acme/testca"
)

// makeSelfSigned builds a matched cert/key PEM pair for a domain.
func makeSelfSigned(t *testing.T, domain string) (certPem, keyPem string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain, Organization: []string{"NexusPanel Test"}},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestSslInstallValidatesPair(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "ok"))
	cert, key := makeSelfSigned(t, "example.com")

	res, _, err := r.sslInstallCert("id", rawParams(t, installCertParams{Domain: "example.com", CertPem: cert, KeyPem: key}))
	if err != nil {
		t.Fatal(err)
	}
	got := res.(installCertResult)
	if got.Issuer != "NexusPanel Test" || !strings.HasSuffix(got.ExpiresAt, "Z") {
		t.Fatalf("cert info: %+v", got.certInfo)
	}
	if _, err := os.Stat(filepath.Join(r.deps.CertRoot, "example.com.crt")); err != nil {
		t.Fatal("cert file must exist")
	}
	ki, err := os.Stat(filepath.Join(r.deps.CertRoot, "example.com.key"))
	if err != nil {
		t.Fatal("key file must exist")
	}
	if ki.Mode().Perm() != 0o600 {
		t.Fatalf("key mode must be 0600, got %v", ki.Mode().Perm())
	}

	// Mismatched pair rejected.
	cert2, _ := makeSelfSigned(t, "other.com")
	if _, _, err := r.sslInstallCert("id", rawParams(t, installCertParams{Domain: "example.com", CertPem: cert2, KeyPem: key})); err == nil {
		t.Fatal("mismatched cert/key must be rejected")
	}
	// Bad domain rejected.
	if _, _, err := r.sslInstallCert("id", rawParams(t, installCertParams{Domain: "../etc", CertPem: cert, KeyPem: key})); err == nil {
		t.Fatal("bad domain must be rejected")
	}
}

func TestSslRevokeIdempotentAndList(t *testing.T) {
	r := newNginxRegistry(t, fakeNginx(t, 0, "ok"))
	cert, key := makeSelfSigned(t, "example.com")
	if _, _, err := r.sslInstallCert("id", rawParams(t, installCertParams{Domain: "example.com", CertPem: cert, KeyPem: key})); err != nil {
		t.Fatal(err)
	}

	res, _, err := r.sslRevoke("id", rawParams(t, map[string]string{"domain": "example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.(struct {
		Status  string `json:"status"`
		Existed bool   `json:"existed"`
	}).Existed != true {
		t.Fatal("revoke must report existed:true")
	}
	if _, err := os.Stat(filepath.Join(r.deps.CertRoot, "example.com.crt")); !os.IsNotExist(err) {
		t.Fatal("cert file must be gone")
	}

	// Revoking again: idempotent.
	res2, _, err := r.sslRevoke("id", rawParams(t, map[string]string{"domain": "example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if res2.(struct {
		Status  string `json:"status"`
		Existed bool   `json:"existed"`
	}).Existed {
		t.Fatal("second revoke must report existed:false")
	}

	// List on an empty store is empty, not an error.
	lr, _, err := r.sslList("id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lr.(sslListResult).Certs) != 0 {
		t.Fatal("empty store must list empty")
	}
}

func TestSslIssueAcmeEndToEnd(t *testing.T) {
	ca := testca.New(t)
	r := NewRegistry(Deps{
		WAL:           newTestWAL(t),
		HomeRoot:      t.TempDir(),
		VhostRoot:     t.TempDir(),
		CertRoot:      t.TempDir(),
		NginxBinary:   fakeNginx(t, 0, "ok"),
		ACMEDirectory: ca.Srv.URL + "/directory",
		ACMEHTTP:      ca.Srv.Client(),
	})

	webroot := filepath.Join(r.deps.HomeRoot, "alice", "domains/example.com/public_html")
	if err := os.MkdirAll(webroot, 0o755); err != nil {
		t.Fatal(err)
	}

	res, _, err := r.sslIssueAcme("id", rawParams(t, issueAcmeParams{
		Domain:        "example.com",
		ChallengeType: "http01",
		Email:         "ops@example.com",
		Webroot:       webroot,
	}))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got := res.(issueAcmeResult)
	if !strings.Contains(got.CertPem, "BEGIN CERTIFICATE") || !strings.Contains(got.KeyPem, "PRIVATE KEY") {
		t.Fatal("issued material must include cert and key PEMs")
	}
	if got.Domain != "example.com" {
		t.Fatalf("cert info: %+v", got.certInfo)
	}
	// The pair must be installed on the node too.
	if _, err := os.Stat(filepath.Join(r.deps.CertRoot, "example.com.crt")); err != nil {
		t.Fatal("issued cert must be installed")
	}
	// Challenge files are cleaned up.
	challDir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if entries, err := os.ReadDir(challDir); err == nil && len(entries) != 0 {
		t.Fatalf("challenge files must be cleaned up, found %d", len(entries))
	}

	// dns-01 refuses honestly.
	if _, _, err := r.sslIssueAcme("id", rawParams(t, issueAcmeParams{
		Domain: "example.com", ChallengeType: "dns01", Email: "o@x.com", Webroot: webroot,
	})); err == nil || !strings.Contains(err.Error(), "dns-01") {
		t.Fatal("dns-01 must be a documented precondition")
	}

	// Webroot outside the home root is refused.
	if _, _, err := r.sslIssueAcme("id", rawParams(t, issueAcmeParams{
		Domain: "example.com", ChallengeType: "http01", Email: "o@x.com", Webroot: "/var/www",
	})); err == nil {
		t.Fatal("webroot outside home root must be refused")
	}

	// The account key persisted for reuse.
	if _, err := os.Stat(filepath.Join(r.deps.CertRoot, "acme-account.key")); err != nil {
		t.Fatal("acme account key must persist")
	}
}
