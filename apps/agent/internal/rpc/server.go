// Package rpc implements the JSON-RPC 2.0 framing and Unix-socket server
// (agent spec §3: message format and error codes).
package rpc

import (
	"encoding/json"
	"errors"
	"io"
	"net"

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
}

// NewServer wires a registry and signature verifier.
func NewServer(reg HandlerRegistry, authCheck SignatureChecker) *Server {
	return &Server{Registry: reg, Auth: authCheck}
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	dec := json.NewDecoder(c)
	enc := json.NewEncoder(c)
	sigFailures := 0
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if err != io.EOF {
				_ = enc.Encode(response{JSONRPC: "2.0", Error: &Error{
					Code: CodeParseError, Message: "parse error",
				}})
			}
			return
		}
		resp := s.dispatch(&req)
		if resp.Error != nil && resp.Error.Code == CodePermission {
			sigFailures++
			// Spec §5: five consecutive signature failures close the socket.
			if sigFailures >= 5 {
				_ = enc.Encode(resp)
				return
			}
		} else if resp.Error == nil || resp.Error.Code != CodePermission {
			sigFailures = 0
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
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
