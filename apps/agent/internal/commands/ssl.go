package commands

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/acme"
	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// ssl.* (agent spec §4.11) — certificate lifecycle on the node.
//
//   - ssl.install_cert validates that the cert and key PEMs parse AND match
//     each other (a mismatched pair is the classic outage), then stores
//     them under CertRoot and health-gates the change.
//   - ssl.issue_acme runs the full RFC 8555 http-01 flow (internal/acme),
//     serving challenge tokens from the site's webroot, and returns the
//     issued PEM material to the control plane (which stores it encrypted —
//     ADR-0009). dns-01 is a documented precondition: no DNS write path yet.
//   - ssl.revoke removes the node files (idempotent).
//   - ssl.list reports installed certs with parsed expiry.
//
// ACME account keys persist at CertRoot/acme-account.key so re-issuance
// reuses the same ACME account (rate-limit friendly).

const (
	certExt = ".crt"
	keyExt  = ".key"
)

type installCertParams struct {
	Domain  string `json:"domain"`
	CertPem string `json:"cert_pem"`
	KeyPem  string `json:"key_pem"`
}

type certInfo struct {
	Domain    string   `json:"domain"`
	Issuer    string   `json:"issuer"`
	SanNames  []string `json:"san_names"`
	ExpiresAt string   `json:"expires_at"`
}

type installCertResult struct {
	certInfo
	HealthCheck  string `json:"health_check"`
	HealthDetail string `json:"health_detail,omitempty"`
}

// parseAndMatch validates the PEM pair: the leaf cert parses, the key
// parses, and their public keys are identical.
func parseAndMatch(certPem, keyPem string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPem))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "cert_pem is not a PEM CERTIFICATE block"}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "cert_pem does not parse: " + err.Error()}
	}

	keyBlock, _ := pem.Decode([]byte(keyPem))
	if keyBlock == nil {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "key_pem is not a PEM block"}
	}
	var key crypto.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "key_pem is not a supported private key PEM (" + keyBlock.Type + ")"}
	}
	if err != nil {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "key_pem does not parse"}
	}
	pubAny, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "key_pem is not an asymmetric private key"}
	}
	certPubDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "cert public key marshal failed"}
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(pubAny.Public())
	if err != nil {
		return nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "key public key marshal failed"}
	}
	if !bytes.Equal(certPubDER, keyPubDER) {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "cert_pem and key_pem do not match (different public keys)"}
	}
	return leaf, nil
}

func certInfoOf(domain string, leaf *x509.Certificate) certInfo {
	issuer := "(unknown)"
	if len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	} else if leaf.Issuer.CommonName != "" {
		issuer = leaf.Issuer.CommonName
	}
	return certInfo{
		Domain:    domain,
		Issuer:    issuer,
		SanNames:  append([]string{}, leaf.DNSNames...),
		ExpiresAt: leaf.NotAfter.UTC().Format(time.RFC3339),
	}
}

// writeCertPair stores the cert/key files atomically with a strict key mode.
func (r *Registry) writeCertPair(domain string, certPem, keyPem []byte) error {
	if err := os.MkdirAll(r.deps.CertRoot, 0o700); err != nil {
		return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("cert root mkdir failed: %v", err)}
	}
	crtPath := filepath.Join(r.deps.CertRoot, domain+certExt)
	keyPath := filepath.Join(r.deps.CertRoot, domain+keyExt)

	stagingCrt := crtPath + ".nexus-staging"
	if err := os.WriteFile(stagingCrt, certPem, 0o644); err != nil {
		return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("cert staging write failed: %v", err)}
	}
	stagingKey := keyPath + ".nexus-staging"
	if err := os.WriteFile(stagingKey, keyPem, 0o600); err != nil {
		_ = os.Remove(stagingCrt)
		return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("key staging write failed: %v", err)}
	}
	if err := os.Rename(stagingCrt, crtPath); err != nil {
		_ = os.Remove(stagingCrt)
		_ = os.Remove(stagingKey)
		return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("cert swap failed: %v", err)}
	}
	if err := os.Rename(stagingKey, keyPath); err != nil {
		_ = os.Remove(stagingKey)
		return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("key swap failed: %v", err)}
	}
	return nil
}

// sslInstallCert (agent spec §4.11) — store a provided cert/key pair.
func (r *Registry) sslInstallCert(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p installCertParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}
	leaf, err := parseAndMatch(p.CertPem, p.KeyPem)
	if err != nil {
		return nil, nil, err
	}
	if err := r.writeCertPair(p.Domain, []byte(p.CertPem), []byte(p.KeyPem)); err != nil {
		return nil, nil, err
	}

	status, detail, failed := r.healthCheck()
	if failed {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "health check failed after cert install: " + detail,
		}
	}

	info := certInfoOf(p.Domain, leaf)
	entry := r.deps.WAL.NewEntry("ssl.install_cert", map[string]any{
		"domain": p.Domain, "issuer": info.Issuer, "expires_at": info.ExpiresAt,
	})
	_ = r.deps.WAL.Append(entry)
	return installCertResult{certInfo: info, HealthCheck: status, HealthDetail: detail}, auditQueued(entry), nil
}

type issueAcmeParams struct {
	Domain        string   `json:"domain"`
	San           []string `json:"san"`
	ChallengeType string   `json:"challenge_type"`
	Email         string   `json:"email"`
	Webroot       string   `json:"webroot"`
}

type issueAcmeResult struct {
	certInfo
	CertPem string `json:"cert_pem"`
	KeyPem  string `json:"key_pem"`
}

// sslIssueAcme runs the complete http-01 issuance flow and returns the
// issued material. The challenge token files live in the site's webroot so
// the running webserver (which owns port 80) serves them — the agent never
// competes for the port.
func (r *Registry) sslIssueAcme(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p issueAcmeParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}
	for _, s := range p.San {
		if !fqdnRe.MatchString(s) || len(s) > 253 {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid SAN: " + safePathSummary(s)}
		}
	}
	if p.ChallengeType == "dns01" {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "dns-01 requires a DNS write path (not yet built); use http-01",
		}
	}
	if p.ChallengeType != "" && p.ChallengeType != "http01" {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "challenge_type must be http01 (dns01 not yet supported)"}
	}
	if p.Email == "" || !strings.Contains(p.Email, "@") {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "email is required for ACME registration"}
	}
	webroot, err := r.confineWebroot(p.Webroot)
	if err != nil {
		return nil, nil, err
	}

	// Account key: persist so re-issuance reuses the ACME account.
	if err := os.MkdirAll(r.deps.CertRoot, 0o700); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("cert root mkdir failed: %v", err)}
	}
	keyPath := filepath.Join(r.deps.CertRoot, "acme-account.key")
	var acctKey *ecdsa.PrivateKey
	if raw, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "acme account key is corrupt"}
		}
		acctKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "acme account key does not parse"}
		}
	} else {
		acctKey, err = acme.GenerateKey()
		if err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "acme keygen failed"}
		}
		der, err := x509.MarshalECPrivateKey(acctKey)
		if err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "acme key marshal failed"}
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("acme key persist failed: %v", err)}
		}
	}

	directory := r.deps.ACMEDirectory
	if directory == "" {
		directory = "https://acme-v02.api.letsencrypt.org/directory"
	}
	client := acme.New(directory, acctKey, r.deps.ACMEHTTP)

	if _, err := client.NewAccount(p.Email, true); err != nil {
		return nil, nil, err
	}
	domains := append([]string{p.Domain}, p.San...)
	order, err := client.NewOrder(domains)
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(3 * time.Minute)

	// http-01: serve token files from the webroot, then answer the challenge.
	challDir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challDir, 0o755); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("challenge dir mkdir failed: %v", err)}
	}
	written := []string{}
	defer func() {
		for _, f := range written {
			_ = os.Remove(filepath.Join(challDir, f))
		}
	}()

	for _, authzURL := range order.Authorizations {
		authz, err := client.GetAuthz(authzURL)
		if err != nil {
			return nil, nil, err
		}
		var chall *acme.Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == "http-01" {
				chall = &authz.Challenges[i]
				break
			}
		}
		if chall == nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "CA offered no http-01 challenge"}
		}
		keyAuth, err := acme.KeyAuthorization(chall.Token, client)
		if err != nil {
			return nil, nil, err
		}
		fname := fmt.Sprintf("%s.txt", chall.Token)
		if err := os.WriteFile(filepath.Join(challDir, fname), []byte(keyAuth), 0o644); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("challenge file write failed: %v", err)}
		}
		written = append(written, fname)

		if err := client.ReadyChallenge(chall.URL); err != nil {
			return nil, nil, err
		}
		if err := client.WaitAuthzValid(authzURL, deadline); err != nil {
			return nil, nil, err
		}
	}

	if _, err := client.WaitOrderReady(order.Location, deadline); err != nil {
		return nil, nil, err
	}
	leafKeyPem, csrDER, err := acme.MakeCSR(domains)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "CSR generation failed"}
	}
	finalized, err := client.Finalize(order, csrDER)
	if err != nil {
		return nil, nil, err
	}
	// Finalize may report processing; poll until the certificate URL exists.
	for finalized.Certificate == "" {
		if time.Now().After(deadline) {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeTimeout, Message: "acme finalize: timeout waiting for certificate"}
		}
		time.Sleep(500 * time.Millisecond)
		finalized, err = client.GetOrder(order.Location)
		if err != nil {
			return nil, nil, err
		}
	}
	chain, err := client.FetchCertificate(finalized.Certificate)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := acme.ParseCertChainPEM(chain)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "issued chain does not parse"}
	}

	if err := r.writeCertPair(p.Domain, chain, leafKeyPem); err != nil {
		return nil, nil, err
	}

	info := certInfoOf(p.Domain, leaf)
	entry := r.deps.WAL.NewEntry("ssl.issue_acme", map[string]any{
		"domain": p.Domain, "issuer": info.Issuer, "expires_at": info.ExpiresAt, "san": p.San,
	})
	_ = r.deps.WAL.Append(entry)
	return issueAcmeResult{
		certInfo: info,
		CertPem:  string(chain),
		KeyPem:   string(leafKeyPem),
	}, auditQueued(entry), nil
}

// confineWebroot validates an ACME webroot: it must be an absolute path
// inside the confined home root, with the existing prefix symlink-clean.
func (r *Registry) confineWebroot(webroot string) (string, error) {
	if webroot == "" {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "webroot is required for http-01"}
	}
	if strings.ContainsRune(webroot, 0) || strings.ContainsRune(webroot, '\\') {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "webroot contains forbidden characters"}
	}
	root := filepath.Clean(r.deps.HomeRoot)
	p := filepath.Clean(webroot)
	if !filepath.IsAbs(p) || (p != root && !strings.HasPrefix(p, root+string(filepath.Separator))) {
		return "", &rpc.RPCError{
			Code:    rpc.CodeInvalidParams,
			Message: "webroot must be inside the hosting home root",
			Data:    map[string]any{"requested": p, "confined_root": root},
		}
	}
	// Symlink-clean walk of the deepest existing ancestor.
	probe := p
	for {
		if _, err := os.Lstat(probe); err == nil {
			resolved, err := filepath.EvalSymlinks(probe)
			if err == nil {
				resolvedRoot, err2 := filepath.EvalSymlinks(root)
				if err2 != nil {
					resolvedRoot = root
				}
				if resolved != resolvedRoot && !strings.HasPrefix(resolved, resolvedRoot+string(filepath.Separator)) {
					return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "webroot resolves outside the hosting home root"}
				}
			}
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	return p, nil
}

// sslRevoke (agent spec §4.11) — removes the node cert files. Idempotent.
func (r *Registry) sslRevoke(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Domain string `json:"domain"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}
	crtPath := filepath.Join(r.deps.CertRoot, p.Domain+certExt)
	keyPath := filepath.Join(r.deps.CertRoot, p.Domain+keyExt)
	existed := false
	if _, err := os.Stat(crtPath); err == nil {
		existed = true
	}
	_ = os.Remove(crtPath)
	_ = os.Remove(keyPath)

	entry := r.deps.WAL.NewEntry("ssl.revoke", map[string]any{
		"domain": p.Domain, "existed": existed,
	})
	_ = r.deps.WAL.Append(entry)
	return struct {
		Status  string `json:"status"`
		Existed bool   `json:"existed"`
	}{Status: "revoked", Existed: existed}, auditQueued(entry), nil
}

type sslListResult struct {
	Certs []certInfo `json:"certs"`
}

// sslList (agent spec §4.11) — installed certs with parsed expiry.
func (r *Registry) sslList(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	out := []certInfo{}
	dirEntries, err := os.ReadDir(r.deps.CertRoot)
	if err == nil {
		for _, de := range dirEntries {
			if !strings.HasSuffix(de.Name(), certExt) || de.Name() == "acme-account.key" {
				continue
			}
			domain := strings.TrimSuffix(de.Name(), certExt)
			raw, err := os.ReadFile(filepath.Join(r.deps.CertRoot, de.Name()))
			if err != nil {
				continue
			}
			leaf, err := acme.ParseCertChainPEM(raw)
			if err != nil {
				continue
			}
			out = append(out, certInfoOf(domain, leaf))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return sslListResult{Certs: out}, nil, nil
}
