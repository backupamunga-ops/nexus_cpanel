// Package testca provides a functional in-memory ACME server for tests:
// it verifies newAccount JWS signatures against the embedded JWK (the
// crypto-critical path) and runs a scripted pending -> ready -> valid
// order lifecycle. Exported so the agent's ssl handlers can test the full
// issuance flow against the same fake CA the client itself is tested on.
package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type FakeCA struct {
	T  *testing.T
	mu sync.Mutex

	Srv           *httptest.Server
	orderStatus   string
	challAccepted bool
	CertPEM       []byte
}

func New(t *testing.T) *FakeCA {
	ca := &FakeCA{T: t, orderStatus: "pending"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   ca.Srv.URL + "/new-nonce",
			"newAccount": ca.Srv.URL + "/new-account",
			"newOrder":   ca.Srv.URL + "/new-order",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-"+time.Now().Format("150405.000000000"))
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-account", ca.handleNewAccount)
	mux.HandleFunc("/new-order", ca.handleNewOrder)
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, _ *http.Request) {
		ca.mu.Lock()
		status := "pending"
		if ca.challAccepted {
			status = "valid"
		}
		ca.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": status,
			"challenges": []map[string]string{{
				"type": "http-01", "url": ca.Srv.URL + "/chall/1", "token": "tok-1",
			}},
		})
	})
	mux.HandleFunc("/chall/1", func(w http.ResponseWriter, _ *http.Request) {
		ca.mu.Lock()
		ca.challAccepted = true
		ca.mu.Unlock()
		w.Header().Set("Replay-Nonce", "n2")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, _ *http.Request) {
		ca.mu.Lock()
		st := ca.orderStatus
		if st == "pending" && ca.challAccepted {
			st = "ready"
		}
		ca.mu.Unlock()
		w.Header().Set("Replay-Nonce", "n3")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": st, "authorizations": []string{ca.Srv.URL + "/authz/1"},
			"finalize":    ca.Srv.URL + "/finalize",
			"certificate": map[bool]string{true: ca.Srv.URL + "/cert/1", false: ""}[st == "valid"],
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, _ *http.Request) {
		ca.mu.Lock()
		ca.orderStatus = "valid"
		ca.mu.Unlock()
		w.Header().Set("Replay-Nonce", "n4")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "valid", "certificate": ca.Srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(ca.CertPEM)
	})

	ca.Srv = httptest.NewServer(mux)
	t.Cleanup(ca.Srv.Close)
	return ca
}

func (ca *FakeCA) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		ca.T.Fatalf("fake CA: decode jws: %v", err)
	}
	protRaw, err := base64.RawURLEncoding.DecodeString(body.Protected)
	if err != nil {
		ca.T.Fatalf("fake CA: protected b64: %v", err)
	}
	var prot struct {
		Alg string `json:"alg"`
		Jwk struct {
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"jwk"`
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(protRaw, &prot); err != nil {
		ca.T.Fatalf("fake CA: protected json: %v", err)
	}
	if prot.Alg != "ES256" || prot.Jwk.Crv != "P-256" || prot.Nonce == "" {
		ca.T.Fatalf("bad protected header: %+v", prot)
	}
	x, err := base64.RawURLEncoding.DecodeString(prot.Jwk.X)
	if err != nil {
		ca.T.Fatal(err)
	}
	y, err := base64.RawURLEncoding.DecodeString(prot.Jwk.Y)
	if err != nil {
		ca.T.Fatal(err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	sig, err := base64.RawURLEncoding.DecodeString(body.Signature)
	if err != nil {
		ca.T.Fatalf("fake CA: sig b64: %v", err)
	}
	digest := sha256.Sum256([]byte(body.Protected + "." + body.Payload))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		ca.T.Fatal("fake CA: JWS signature verification FAILED")
	}
	w.Header().Set("Location", ca.Srv.URL+"/acct/1")
	w.Header().Set("Replay-Nonce", "n1")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"status":"valid"}`))
}

func (ca *FakeCA) handleNewOrder(w http.ResponseWriter, _ *http.Request) {
	ca.mu.Lock()
	ca.orderStatus = "pending"
	ca.mu.Unlock()
	w.Header().Set("Location", ca.Srv.URL+"/order/1")
	w.Header().Set("Replay-Nonce", "n2b")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"status":"pending","authorizations":["` + ca.Srv.URL + `/authz/1"],"finalize":"` + ca.Srv.URL + `/finalize"}`))
}
