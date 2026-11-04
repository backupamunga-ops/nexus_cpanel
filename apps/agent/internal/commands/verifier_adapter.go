package commands

import (
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/auth"
)

// verifierAdapter adapts auth.Verifier (explicit clock) to the rpc.SignatureChecker
// interface (server supplies no clock; wall time is used at the boundary).
type verifierAdapter struct {
	v *auth.Verifier
}

// Verify checks the envelope at wall-clock time.
func (a verifierAdapter) Verify(meta auth.EnvelopeMeta, signatureB64 string) error {
	return a.v.Verify(meta, signatureB64, time.Now())
}

// RPCVerifier exposes the adapter for the RPC server wiring.
func (d Deps) RPCVerifier() verifierAdapter { return verifierAdapter{v: d.Verifier} }
