# ADR-0023 — Web terminal: a named, signed `terminal.open` stream instead of a hole in the no-exec doctrine

**Status:** Accepted (live-VM operations batch)
**Implements:** agent spec §4 preamble (amendment), security model §11.3 (C6 permission), §4 (C11 audit)
**Builds on:** ADR-0010 (ssh authorized_keys), ADR-0019 (apps/git releases), the agent's Ed25519 envelope (agent spec §3)

## Context

Operators of a hosting panel will shell into the node — with the panel open or
without it. Today the only paths are raw SSH (outside the panel, unaudited by
it) or nothing. A layman-friendly panel that hides "open a terminal behind the
panel" will keep pushing users to paste root passwords into raw SSH sessions,
which is strictly worse for the security posture the panel is trying to raise.

The agent doctrine is "no exec() primitive": every mutation is a named, signed
method with typed parameters (agent spec §4 preamble), and the registry IS the
allowlist. A terminal cannot be expressed as a request/response method — it is
a long-lived bidirectional byte stream.

## Decision

1. **One named capability, same trust path.** The agent gains `POST /terminal`
   on its existing Unix socket: one signed `terminal.open` envelope per
   session, verified by the same `auth.Verifier` and error codes as every
   other method (-32000 policy, -32001 precondition, -32602 params). On
   success the agent answers `101 Switching Protocols` and hijacks the
   connection; from then on it carries length-prefixed frames
   (`apps/agent/internal/term/frame.go`): input/resize/ping toward the pty,
   output/exit/error back. The doctrine holds because `terminal.open` is a
   *named* capability wired in at launch (`rpc.Server.Terminal`), not a
   generic exec channel — and the registry/allowlist stays untouched.

2. **The agent owns the limits, not the caller.** Per node: max 3 concurrent
   sessions, 15-minute idle timeout, 8-hour hard lifetime (reaper kills the
   whole process group — Setsid makes pgid == pid). Root shells are refused
   unless the operator sets `NEXUSAGENT_ALLOW_ROOT_TERMINAL=1` on the agent
   unit. Accounts whose login shell is `nologin`/`false` are refused with a
   clear error. The control plane cannot override any of these.

3. **The control plane is a permission-checking relay, nothing more.**
   `TerminalGateway` (path `/api/v1/terminal`, JWT handshake like `/events`)
   resolves the hosting account by username, enforces C7 visibility
   (invisible accounts answer `not_found`), requires `terminal:use` (granted
   to account owner/admin roles; server admins pass; members/readonly never),
   refuses suspended accounts, and audits `terminal.open` (success *and*
   failures) plus `terminal.close` with duration into the hash chain. It
   never inspects or stores terminal content.

4. **Shell surface.** The agent spawns the account's login shell (from
   `/etc/passwd`) on a stdlib PTY (`/dev/ptmx` + TIOCGPTN/TIOCSPTLCK — go.mod
   stays dependency-free), cwd = homedir, minimal env (`TERM=xterm-256color`,
   HOME/USER/LOGNAME/SHELL, nothing inherited). The browser gets xterm.js
   (`@xterm/xterm`) with a fit addon; resizes travel as frames to
   `TIOCSWINSZ`.

5. **No REST surface, no tokens.** The capability is only reachable through
   the browser WebSocket path; it is deliberately absent from the REST API
   and from API-token scoping (a stolen automation token must not be able to
   hold a shell). If token-scoped terminal access is ever needed, that is a
   new ADR.

## Consequences

- Agent spec §4 preamble is amended: `terminal.open` is allowlisted as a
  stream capability outside the request/response registry; `IsReadOnly`
  semantics do not apply.
- The agent's attack surface grows by one pre-conditioned, signature-gated,
  audited, hard-capped path — measured against the alternative (operators in
  raw SSH with no audit), this is the smaller hole.
- Session content is NOT recorded in v1. Open/close/duration is in the audit
  chain; content recording (optional, encrypted) is deferred with its own
  ADR if ever requested.
- `@xterm/xterm` + `@xterm/addon-fit` are the only new browser dependencies;
  the agent gains none.
