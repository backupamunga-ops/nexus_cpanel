# M0 Scope — "Hello, privileged agent" (v1.0)

> Status: NORMATIVE for milestone P1. Derived from the specification set's
> recommendation (see provenance-spec-set-complete.md) and approved at kickoff.

## 1. Purpose

M0 is the smallest vertical slice that validates the entire architecture — one thread
through every layer. If the schema, the agent protocol, or the security model has a
flaw, M0 finds it in week 2, before 50 features are built on top of it.

## 2. The thread

1. User logs into the panel (email + password, Argon2id, JWT + rotating refresh).
2. User clicks "create test account" with a username.
3. Control plane validates permission (`account:create`), persists the hosting account
   row, and sends `account.create` + `isolation.provision` as signed JSON-RPC over the
   agent Unix socket.
4. Agent verifies the Ed25519 signature and validity window, creates the Linux user
   (typed `execve`, no shell) and a cgroup v2 slice.
5. Agent returns `{uid, gid, homedir}`; control plane stores them.
6. An audit entry is written and **hash-chained**; `POST /audit/verify` validates the chain.
7. Frontend shows the account with **live usage** from `account.usage` (WebSocket).

## 3. In scope

- Login (Argon2id; TOTP enrollment lands in P2 but the schema columns exist).
- Hosting account create/suspend/delete (minimal) + list + usage.
- Agent methods: `account.create|suspend|resume|delete|usage|list`, `isolation.provision`,
  `system.health`.
- Audit chain writer + verify endpoint (C11 exact hash construction).
- Agent WAL read-only mode when the control plane is unreachable (mutations → `-32005`).
- Dev-mode key provisioning script (generates Ed25519 keypair; production installer
  owns real key ceremony later).

## 4. Explicitly out of scope

Sites, mail, DNS, databases, SSL, backups, apps, resellers, extensions, drift
detection loop, multi-node — these begin in P2+.

## 5. Acceptance criteria

| # | Criterion |
|---|---|
| A1 | M0 flow completes on a fresh VM via documented steps |
| A2 | Tampered command signature is rejected (`-32000`) and logged as a security event |
| A3 | Command with expired `expires_at` is rejected (`-32003`) |
| A4 | With control plane down, agent serves reads, rejects writes with `-32005`, drains WAL on reconnect |
| A5 | Modifying any mid-chain audit entry causes `POST /audit/verify` to fail at that entry |
| A6 | `account.usage` returns real cgroup usage for the created account |
| A7 | CI green: control-plane (typecheck/test/build), agent (vet/test/build), web (build) |

## 6. Test map

| Layer | Tests |
|---|---|
| Agent | signature verify unit tests (tamper/expiry/wrong-key), username validation, JSON-RPC error codes, WAL append/drain, account.create against a fake root filesystem in CI |
| Control plane | audit-chain unit tests (hash construction, mid-chain tamper), agent-client envelope/signature tests against an in-process socket server, auth flow integration |
| E2E | M0 happy path scripted (Playwright) in P1 |
