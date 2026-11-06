// Package rpc implements the JSON-RPC 2.0 framing and Unix-socket server
// (agent spec §3: message format and error codes).
//
// Transport framing: HTTP/1.1 POST over the Unix socket — one JSON-RPC
// request body in, one JSON-RPC response body out. HTTP gives keep-alive,
// standard tooling (curl), and a clean TLS termination story for the
// production mTLS deployment without changing the JSON-RPC envelope.
package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/auth"
)

// JSON-RPC 2.0 error codes (agent spec §3) plus NexusPanel-reserved -32000..-32005.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodePermission     = -32000
	CodePrecondition   = -32001
	CodeConflict       = -32002
	CodeTimeout        = -32003
	CodeQuota          = -32004
	CodeCPUnreachable  = -32005
)

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// RPCError lets handlers return coded errors.
type RPCError struct {
	Code    int
	Message string
	Data    any
}

func (e *RPCError) Error() string { return e.Message }

func (e *RPCError) rpcError() *Error {
	d, _ := json.Marshal(e.Data)
	return &Error{Code: e.Code, Message: e.Message, Data: d}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	// NexusPanel envelope extensions (agent spec §3):
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Signature string `json:"signature"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *Error          `json:"error"`
	// Audit chaining hint returned with every executed mutation (agent spec §3):
	Audit *AuditHint `json:"audit,omitempty"`
}

// AuditHint mirrors the audit-chain position the control plane should verify.
type AuditHint struct {
	EntryID   string `json:"entry_id,omitempty"`
	PriorHash string `json:"prior_hash,omitempty"`
	ThisHash  string `json:"this_hash,omitempty"`
}

// Handler executes an allowlisted method. It receives the RAW params bytes so
// signatures can be verified over exactly what the control plane serialized.
type Handler func(id string, rawParams json.RawMessage) (result any, audit *AuditHint, err error)

// TerminalSession is one prepared terminal stream (ADR-0023).
type TerminalSession interface {
	Attach(conn io.ReadWriteCloser)
}

// TerminalStream prepares and serves web-terminal sessions (ADR-0023) on
// POST /terminal. Prepare validates the signed `terminal.open` envelope and
// spawns the shell BEFORE the connection is hijacked, so every rejection is a
// normal JSON-RPC response; Attach then streams until the session ends. A nil
// Terminal disables the subsystem: /terminal answers method-not-found. The
// allowlist doctrine (§4 preamble) still holds — terminal.open is a NAMED,
// signature-gated capability wired in at launch, not a generic exec primitive.
type TerminalStream interface {
	Prepare(id string, rawParams json.RawMessage) (TerminalSession, error)
}

const terminalOpenMethod = "terminal.open"

// HandlerRegistry resolves method names to handlers. Unknown methods are
// "method not found"; the allowlist IS the registry map (spec §4).
type HandlerRegistry interface {
	Lookup(method string) (Handler, bool)
	IsReadOnly(method string) bool
}

// SignatureChecker verifies an envelope. The agent spec requires that after
// five consecutive failures on one connection the socket is closed.
type SignatureChecker interface {
	Verify(meta auth.EnvelopeMeta, signatureB64 string) error
}

// Server serves JSON-RPC over a Unix listener.
type Server struct {
	Registry HandlerRegistry
	Auth     SignatureChecker
	Terminal TerminalStream // optional; nil disables the /terminal route
}

// NewServer wires a registry and signature verifier.
func NewServer(reg HandlerRegistry, authCheck SignatureChecker) *Server {
	return &Server{Registry: reg, Auth: authCheck}
}

// Serve accepts connections until the listener closes (HTTP framing).
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler: s.HTTPHandler(),
		// Per-connection state for the 5-consecutive-signature-failure
		// rule (spec §5): each connection gets its own counter.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			n := 0
			return context.WithValue(ctx, sigFailKey{}, &n)
		},
	}
	return srv.Serve(ln)
}

type sigFailKey struct{}

// HTTPHandler returns the JSON-RPC HTTP handler (POST / — one envelope per
// request body; POST /terminal — one signed terminal.open upgrade, ADR-0023).
// Exported for tests.
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/terminal" {
			s.serveTerminal(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(response{JSONRPC: "2.0", Error: &Error{
				Code: CodeInvalidRequest, Message: "POST required",
			}})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
		if err != nil {
			_ = json.NewEncoder(w).Encode(response{JSONRPC: "2.0", Error: &Error{
				Code: CodeParseError, Message: "read error",
			}})
			return
		}
		var req request
		if err := json.Unmarshal(body, &req); err != nil {
			_ = json.NewEncoder(w).Encode(response{JSONRPC: "2.0", Error: &Error{
				Code: CodeParseError, Message: "parse error",
			}})
			return
		}

		resp := s.dispatch(&req)

		// Spec §5: five consecutive signature failures close the connection.
		if counter, ok := r.Context().Value(sigFailKey{}).(*int); ok {
			if resp.Error != nil && resp.Error.Code == CodePermission {
				*counter++
				if *counter >= 5 {
					w.Header().Set("Connection", "close")
				}
			} else if resp.Error == nil || resp.Error.Code != CodePermission {
				*counter = 0
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// serveTerminal implements the one-request upgrade: verify the signed
// terminal.open envelope exactly like dispatch() does, run Prepare (still a
// plain HTTP request — failures are JSON-RPC errors), then hijack the
// connection, answer 101 Switching Protocols and hand the raw stream to the
// session. After Hijack() the net/http machinery is out of the loop; closing
// the connection is the session's job.
func (s *Server) serveTerminal(w http.ResponseWriter, r *http.Request) {
	if s.Terminal == nil {
		s.writeRPCError(w, &Error{Code: CodeMethodNotFound, Message: "terminal subsystem is not enabled on this agent"})
		return
	}
	if r.Method != http.MethodPost {
		s.writeRPCError(w, &Error{Code: CodeInvalidRequest, Message: "POST required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.writeRPCError(w, &Error{Code: CodeParseError, Message: "read error"})
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeRPCError(w, &Error{Code: CodeParseError, Message: "parse error"})
		return
	}
	meta := auth.EnvelopeMeta{
		Method:    req.Method,
		RawParams: req.Params,
		IssuedAt:  req.IssuedAt,
		ExpiresAt: req.ExpiresAt,
	}
	if err := s.Auth.Verify(meta, req.Signature); err != nil {
		s.writeRPCError(w, authError(err))
		return
	}
	if req.Method != terminalOpenMethod {
		s.writeRPCError(w, &Error{Code: CodeMethodNotFound, Message: "method not found: " + req.Method})
		return
	}
	sess, err := s.Terminal.Prepare(req.ID, req.Params)
	if err != nil {
		s.writeRPCError(w, handlerError(err))
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		s.writeRPCError(w, &Error{Code: CodeInternalError, Message: "terminal streaming unsupported on this listener"})
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		s.writeRPCError(w, &Error{Code: CodeInternalError, Message: "hijack failed: " + err.Error()})
		return
	}
	defer conn.Close()
	// A session spawned but never hijacked (error above) is reaped by the
	// manager's idle bound — it never runs with a client attached.
	if _, err := buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: nexus-terminal\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}
	sess.Attach(conn)
}

// writeRPCError answers with a single JSON-RPC error body (non-hijack paths).
func (s *Server) writeRPCError(w http.ResponseWriter, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{JSONRPC: "2.0", Error: e})
}

func (s *Server) dispatch(req *request) *response {
	r := &response{JSONRPC: "2.0", ID: req.ID}
	if req.JSONRPC != "2.0" || req.Method == "" {
		r.Error = &Error{Code: CodeInvalidRequest, Message: "invalid request"}
		return r
	}
	meta := auth.EnvelopeMeta{
		Method:    req.Method,
		RawParams: req.Params,
		IssuedAt:  req.IssuedAt,
		ExpiresAt: req.ExpiresAt,
	}
	if err := s.Auth.Verify(meta, req.Signature); err != nil {
		r.Error = authError(err)
		return r
	}
	handler, ok := s.Registry.Lookup(req.Method)
	if !ok {
		r.Error = &Error{Code: CodeMethodNotFound, Message: "method not found: " + req.Method}
		return r
	}
	result, audit, err := handler(req.ID, req.Params)
	if err != nil {
		r.Error = handlerError(err)
		return r
	}
	raw, merr := json.Marshal(result)
	if merr != nil {
		r.Error = &Error{Code: CodeInternalError, Message: "result marshal: " + merr.Error()}
		return r
	}
	r.Result = raw
	r.Audit = audit
	return r
}

// authError maps signature/validity failures to the wire error codes.
func authError(err error) *Error {
	code := CodePermission // signature failures: -32000, close-after-5 policy applies
	switch {
	case errors.Is(err, auth.ErrExpired), errors.Is(err, auth.ErrWindowTooLong), errors.Is(err, auth.ErrIssuedInFuture):
		code = CodeTimeout // validity-window failures are timed rejections (-32003)
	}
	return &Error{Code: code, Message: err.Error()}
}

// handlerError maps typed handler failures onto the reserved error range.
func handlerError(err error) *Error {
	if re, ok := err.(*RPCError); ok {
		return re.rpcError()
	}
	return &Error{Code: CodeInternalError, Message: err.Error()}
}
