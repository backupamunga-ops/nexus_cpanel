// Command nexuspanel-agent is the single privileged process on a NexusPanel node.
//
// It exposes a typed JSON-RPC 2.0 command allowlist over a Unix socket. There is
// no exec() primitive: every mutation is a named method with typed parameters,
// signed by the control plane's Ed25519 key. See specs/nexuspanel-agent-spec-v1.0.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // registered on the metrics mux in P1; harmless placeholder
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/auth"
	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/commands"
	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/wal"
)

func main() {
	var (
		socketPath  = flag.String("socket", "/run/nexuspanel/agent.sock", "Unix socket path")
		signingKey  = flag.String("signing-pubkey", "/etc/nexuspanel/keys/control-plane-signing.pub", "Control-plane Ed25519 public key (base64 raw or PEM)")
		walDir      = flag.String("wal-dir", "/var/lib/nexuspanel-agent/wal", "WAL directory for offline audit entries")
		cgroupRoot  = flag.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 root (overridable for tests)")
		metricsAddr = flag.String("metrics-addr", "127.0.0.1:9101", "Prometheus metrics bind (localhost only)")
		devMode     = flag.Bool("dev", false, "DEV MODE: accept unsigned commands. Refuses to start as root unless NEXUSAGENT_DEV_MODE_ROOT_OK=1 is also set.")
		socketMode  = flag.String("socket-mode", "0600", "Socket file mode")
	)
	flag.Parse()

	log.SetPrefix("nexuspanel-agent: ")
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Printf("starting nexuspanel-agent (dev=%v)", *devMode)
	if *devMode && os.Geteuid() == 0 && os.Getenv("NEXUSAGENT_DEV_MODE_ROOT_OK") != "1" {
		log.Fatal("dev mode refuses to run as root; set NEXUSAGENT_DEV_MODE_ROOT_OK=1 to override")
	}

	verifier, err := auth.NewVerifier(*signingKey, *devMode)
	if err != nil {
		log.Fatalf("signature verifier: %v", err)
	}

	queue, err := wal.Open(*walDir, 100_000)
	if err != nil {
		log.Fatalf("wal: %v", err)
	}
	defer queue.Close()

	deps := commands.Deps{
		Verifier:   verifier,
		WAL:        queue,
		CgroupRoot: *cgroupRoot,
	}
	registry := commands.NewRegistry(deps)

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o755); err != nil {
		log.Fatalf("socket dir: %v", err)
	}
	_ = os.Remove(*socketPath)
	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if mode, perr := parseMode(*socketMode); perr == nil {
		_ = os.Chmod(*socketPath, mode)
	}
	log.Printf("listening on %s (metrics on %s)", *socketPath, *metricsAddr)
	go serveMetrics(*metricsAddr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := rpc.NewServer(registry, deps.RPCVerifier())
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")
	_ = ln.Close()
}

func parseMode(s string) (os.FileMode, error) {
	var m uint32
	if _, err := fmt.Sscanf(s, "%o", &m); err != nil {
		return 0, err
	}
	return os.FileMode(m), nil
}

// serveMetrics exposes a trivial textformat endpoint on localhost.
// Real metric families (command latency, WAL depth, drift status) land in P1.
func serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "# HELP nexuspanel_agent_up Agent process liveness.")
		fmt.Fprintln(w, "# TYPE nexuspanel_agent_up gauge")
		fmt.Fprintln(w, "nexuspanel_agent_up 1")
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("metrics: %v", err)
	}
}
