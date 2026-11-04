package commands

import (
	"os"
	"testing"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/wal"
)

func newTestWAL(t *testing.T) *wal.Queue {
	t.Helper()
	q, err := wal.Open(t.TempDir(), 100)
	if err != nil {
		t.Fatalf("wal open: %v", err)
	}
	return q
}

var _ = os.Getenv // keep os linked for tests that may use it
