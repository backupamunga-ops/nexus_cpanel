package term

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/wal"
)

// Session bounds (ADR-0023). The terminal is an inherently privileged
// capability, so the agent itself — not the caller — owns the limits: a node
// can never accumulate unbounded shells no matter what the control plane asks.
const (
	defaultMaxSessions = 3
	defaultIdleTimeout = 15 * time.Minute
	defaultMaxLifetime = 8 * time.Hour
	reapInterval       = 30 * time.Second

	defaultCols = 80
	defaultRows = 24
	maxCols     = 500
	maxRows     = 300
	minCols     = 2
	minRows     = 2

	// outputChunk caps one pty read before it becomes an output frame.
	outputChunk = 32 << 10

	openMethod  = "terminal.open"
	closeMethod = "terminal.close"
)

var usernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// openParams mirrors the signed `terminal.open` params exactly; the signature
// covers the raw bytes, so any surprise field fails verification upstream.
type openParams struct {
	Username string `json:"username"`
	Cols     uint16 `json:"cols"`
	Rows     uint16 `json:"rows"`
}

// Config bounds the terminal subsystem; zero fields take the defaults.
type Config struct {
	MaxSessions int
	IdleTimeout time.Duration
	MaxLifetime time.Duration
	// AllowRoot admits uid-0 shells; OFF by default because a root terminal
	// in a browser tab is an accident (and a screen-share) away from a
	// destroyed node. Enabled explicitly via NEXUSAGENT_ALLOW_ROOT_TERMINAL=1.
	AllowRoot bool
}

func (c Config) withDefaults() Config {
	if c.MaxSessions <= 0 {
		c.MaxSessions = defaultMaxSessions
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	if c.MaxLifetime <= 0 {
		c.MaxLifetime = defaultMaxLifetime
	}
	return c
}

// Manager owns every live terminal session on the node.
type Manager struct {
	cfg Config
	wal *wal.Queue

	mu       sync.Mutex
	sessions map[string]*session
}

// NewManager builds the session manager and starts its reaper.
func NewManager(cfg Config, audit *wal.Queue) *Manager {
	m := &Manager{cfg: cfg.withDefaults(), wal: audit, sessions: map[string]*session{}}
	go m.reapLoop()
	return m
}

// Prepared is a spawned session awaiting its client stream. Prepare runs
// BEFORE the connection is hijacked so every rejection keeps clean JSON-RPC
// error semantics; Attach is the point of no return.
type Prepared struct {
	ID       string
	Username string
	UID      int

	s *session
}

// Attach hands the (already hijacked) byte stream to the session and blocks
// until the session ends.
func (p *Prepared) Attach(conn io.ReadWriteCloser) {
	p.s.attach(conn)
}

// Prepare validates a signed terminal.open envelope and spawns the shell.
// Errors are *rpc.RPCError and surface as JSON-RPC rejections (-32602 params,
// -32000 policy, -32001 preconditions) before any stream is established.
func (m *Manager) Prepare(id string, rawParams json.RawMessage) (rpc.TerminalSession, error) {
	if len(rawParams) == 0 {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "missing params"}
	}
	var p openParams
	if err := json.Unmarshal(rawParams, &p); err != nil {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	if !usernameRE.MatchString(p.Username) {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams,
			Message: "username must be lowercase (a-z, 0-9, _ -), max 32 chars — per the accounts service"}
	}
	cols := clampDim(p.Cols, minCols, maxCols, defaultCols)
	rows := clampDim(p.Rows, minRows, maxRows, defaultRows)

	m.mu.Lock()
	if len(m.sessions) >= m.cfg.MaxSessions {
		m.mu.Unlock()
		return nil, &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: fmt.Sprintf("terminal session limit reached (%d active) — close a session and retry", m.cfg.MaxSessions)}
	}
	m.mu.Unlock()

	uid, gid, home, shell, ok := passwdEntry(p.Username)
	if !ok {
		return nil, &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: fmt.Sprintf("user %q not found on this node — create the hosting account first", p.Username)}
	}
	if uid == 0 && !m.cfg.AllowRoot {
		return nil, &rpc.RPCError{Code: rpc.CodePermission,
			Message: "root shell refused — enable NEXUSAGENT_ALLOW_ROOT_TERMINAL=1 on the agent if you really mean it"}
	}
	if os.Geteuid() != 0 && uid != os.Geteuid() {
		return nil, &rpc.RPCError{Code: rpc.CodePermission,
			Message: "agent is not running as root — cannot open a shell for another user"}
	}
	if base := baseName(shell); base == "nologin" || base == "false" {
		return nil, &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: fmt.Sprintf("account %s has login shell %s — terminal is disabled for this account", p.Username, shell)}
	}
	if st, err := os.Stat(home); err != nil || !st.IsDir() {
		return nil, &rpc.RPCError{Code: rpc.CodePrecondition,
			Message: fmt.Sprintf("home directory %s is missing — account not fully provisioned", home)}
	}

	s := &session{
		id:       id,
		username: p.Username,
		uid:      uid,
		gid:      gid,
		started:  time.Now(),
		mgr:      m,
		wal:      m.wal,
	}
	s.lastActivity.Store(time.Now().Unix())

	master, cmd, err := startShell(shell, p.Username, home, uid, gid, cols, rows)
	if err != nil {
		return nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: err.Error()}
	}
	s.master, s.cmd = master, cmd

	entry := m.wal.NewEntry(openMethod, map[string]any{
		"username": p.Username, "uid": uid, "session_id": id, "cols": cols, "rows": rows,
	})
	_ = m.wal.Append(entry)

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return &Prepared{ID: id, Username: p.Username, UID: uid, s: s}, nil
}

func (m *Manager) remove(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// reapLoop enforces the idle and lifetime bounds. Killing the process group
// (not just the shell) prevents `sleep 9999 &` children from outliving the
// policy; closing the master unblocks the output loop so the exit frame flows.
func (m *Manager) reapLoop() {
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		victims := []*session{}
		m.mu.Lock()
		for _, s := range m.sessions {
			idleFor := time.Duration(now.Unix()-s.lastActivity.Load()) * time.Second
			switch {
			case idleFor > m.cfg.IdleTimeout:
				s.closeReason.Store("idle_timeout")
				victims = append(victims, s)
			case now.Sub(s.started) > m.cfg.MaxLifetime:
				s.closeReason.Store("max_lifetime")
				victims = append(victims, s)
			}
		}
		m.mu.Unlock()
		for _, s := range victims {
			killShell(s.cmd)
			_ = s.master.Close()
		}
	}
}

// session is one live pty. All frame writes to the client are serialized
// (the output loop and the exit path race by design); reads are single-owner.
type session struct {
	id       string
	username string
	uid, gid int
	started  time.Time

	lastActivity atomic.Int64
	closeReason  atomic.Value // string; set by the reaper before it kills

	mgr    *Manager
	wal    *wal.Queue
	cmd    *exec.Cmd
	master *os.File

	wmu  sync.Mutex
	conn io.ReadWriteCloser
}

func (s *session) touch() { s.lastActivity.Store(time.Now().Unix()) }

func (s *session) writeFrame(t Frame, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.conn == nil {
		return fmt.Errorf("session not attached")
	}
	return WriteFrame(s.conn, t, payload)
}

// attach relays pty ↔ client until the shell exits, the client disconnects,
// or the reaper kills the session — whichever comes first. Exactly one
// cleanup runs (sync.Once), and it audits terminal.close.
func (s *session) attach(conn io.ReadWriteCloser) {
	s.conn = conn
	var once sync.Once
	cleanup := func(clientGone bool) {
		once.Do(func() {
			reason, _ := s.closeReason.Load().(string)
			if reason == "" && clientGone {
				reason = "client_disconnected"
			}
			killShell(s.cmd)
			waitErr := s.cmd.Wait()
			_ = s.master.Close()

			exitStatus := exitCode(waitErr)
			if reason != "" {
				exitStatus = 0 // policy kill (idle/lifetime/client), not a shell failure
			}

			s.mgr.remove(s.id)
			if e := s.wal.NewEntry(closeMethod, map[string]any{
				"username": s.username, "session_id": s.id,
				"duration_sec": int(time.Since(s.started).Seconds()),
				"exit_status":  exitStatus, "reason": reason,
			}); e != nil {
				_ = s.wal.Append(e)
			}

			s.wmu.Lock()
			s.conn = nil
			s.wmu.Unlock()
			payload, _ := json.Marshal(map[string]any{"status": exitStatus, "reason": reason})
			_ = WriteFrame(conn, FrameExit, payload) // best effort; then the stream dies
			_ = conn.Close()
		})
	}

	// pty → client
	go func() {
		buf := make([]byte, outputChunk)
		for {
			n, err := s.master.Read(buf)
			if n > 0 {
				s.touch()
				if werr := s.writeFrame(FrameOutput, buf[:n]); werr != nil {
					cleanup(true)
					return
				}
			}
			if err != nil {
				cleanup(false) // EIO here is the normal end-of-session signal
				return
			}
		}
	}()

	// client → pty
	for {
		t, payload, err := ReadFrame(conn)
		if err != nil {
			cleanup(true)
			return
		}
		switch t {
		case FrameInput:
			s.touch()
			if len(payload) > 0 {
				if _, err := s.master.Write(payload); err != nil {
					cleanup(false)
					return
				}
			}
		case FrameResize:
			s.touch()
			if len(payload) == 4 {
				cols := uint16(payload[0])<<8 | uint16(payload[1])
				rows := uint16(payload[2])<<8 | uint16(payload[3])
				_ = setWinsize(s.master.Fd(),
					clampDim(cols, minCols, maxCols, defaultCols),
					clampDim(rows, minRows, maxRows, defaultRows))
			}
		case FramePing:
			s.touch()
		default:
			msg, _ := json.Marshal(map[string]any{
				"message": fmt.Sprintf("unexpected frame type 0x%02x — session closed (fail-closed)", byte(t)),
			})
			_ = s.writeFrame(FrameError, msg)
			cleanup(true)
			return
		}
	}
}

// ---- helpers ----------------------------------------------------------------

func clampDim(v, min, max, def uint16) uint16 {
	if v == 0 {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// exitCode maps a cmd.Wait error onto a shell-style exit status.
func exitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	if ee, ok := waitErr.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 127 // could not wait at all — report a command-style failure
}

// passwdEntry parses /etc/passwd directly (NSS-file scope is sufficient for
// hosting accounts, which are local users by construction). Returns
// uid, gid, home, login shell.
func passwdEntry(username string) (int, int, string, string, bool) {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, 0, "", "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] != username {
			continue
		}
		uid, e1 := strconv.Atoi(f[2])
		gid, e2 := strconv.Atoi(f[3])
		if e1 != nil || e2 != nil {
			return 0, 0, "", "", false
		}
		shell := f[6]
		if shell == "" {
			shell = "/bin/bash"
		}
		return uid, gid, f[5], shell, true
	}
	return 0, 0, "", "", false
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
