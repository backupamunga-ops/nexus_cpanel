package acme

import (
	"strings"
	"testing"
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/acme/testca"
)

func TestFullIssuanceFlow(t *testing.T) {
	ca := testca.New(t)
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c := New(ca.Srv.URL+"/directory", key, ca.Srv.Client())

	acct, err := c.NewAccount("ops@example.com", true)
	if err != nil {
		t.Fatalf("newAccount: %v", err)
	}
	if !strings.HasSuffix(acct.URL, "/acct/1") {
		t.Fatalf("account url: %q", acct.URL)
	}

	order, err := c.NewOrder([]string{"example.com"})
	if err != nil {
		t.Fatalf("newOrder: %v", err)
	}
	if len(order.Authorizations) != 1 {
		t.Fatalf("authorizations: %+v", order)
	}

	authz, err := c.GetAuthz(order.Authorizations[0])
	if err != nil {
		t.Fatalf("getAuthz: %v", err)
	}
	var chall *Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "http-01" {
			chall = &authz.Challenges[i]
		}
	}
	if chall == nil {
		t.Fatalf("no http-01 challenge: %+v", authz)
	}

	ka, err := KeyAuthorization(chall.Token, c)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := c.thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if ka != chall.Token+"."+tp {
		t.Fatalf("key authorization mismatch: %q", ka)
	}

	if err := c.ReadyChallenge(chall.URL); err != nil {
		t.Fatalf("readyChallenge: %v", err)
	}
	if err := c.WaitAuthzValid(order.Authorizations[0], time.Now().Add(3*time.Second)); err != nil {
		t.Fatalf("waitAuthz: %v", err)
	}
	if _, err := c.WaitOrderReady(order.Location, time.Now().Add(3*time.Second)); err != nil {
		t.Fatalf("waitOrderReady: %v", err)
	}

	leafKeyPEM, csrDER, err := MakeCSR([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(leafKeyPEM), "PRIVATE KEY") {
		t.Fatal("leaf key PEM malformed")
	}
	finalized, err := c.Finalize(order, csrDER)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if finalized.Status != "valid" {
		t.Fatalf("order status after finalize: %s", finalized.Status)
	}

	chain, err := c.FetchCertificate(finalized.Certificate)
	if err != nil {
		t.Fatalf("fetchCert: %v", err)
	}
	leaf, err := ParseCertChainPEM(chain)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.DNSNames[0] != "example.com" {
		t.Fatalf("leaf SANs: %v", leaf.DNSNames)
	}
	if !strings.Contains(string(chain), "BEGIN CERTIFICATE") {
		t.Fatal("chain must be PEM")
	}
}
