# ADR-0021 — Extension SDK runtime: out-of-process, scope-reviewed, fail-closed

**Status:** Accepted (P7)
**Implements:** extension SDK spec v1.0 (§1–§12, normative), API spec §4.24 (pre-declared), BUILD_PLAN P7
**Builds on:** DDL `extensions` / `extension_registrations` (v2.0, pre-provisioned), ADR-0009 SecretBox, C6 permission guard, B13 audit-tail webhook dispatch (ADR-0018), D-11 honesty

## Context

P7 opens the extension surface. The SDK spec fixed the hard parts in
advance: extensions are **out-of-process services** speaking a versioned
protocol; they can never modify core source, run in the panel process, or
exceed their declared scopes. The remaining design work was the trust
ladder (who can grant what, and when), where the `/api/v1/ext/*`
enforcement lives, and how hooks reach extensions without a broker.

## Decision

### 1. Trust ladder: install → review → approve → operate (spec §3, fail-closed)

- **Install** (`POST /extensions` with `manifest_url`, or §5.1
  `POST /extensions/register` with an inline manifest): the panel fetches
  and validates the manifest (closed scope list, slug/semver/compat rules,
  endpoint path shapes). The row lands **`disabled` with ZERO granted
  scopes** — an installed-but-unreviewed extension is inert by construction.
- **Approve** (`PATCH /extensions/{id}` action `approve`): grants exactly
  the requested scopes, sets `enabled`, and returns the §5.1 credentials —
  shared secret + derived token — **exactly once**. The secret lives only
  in a SecretBox envelope (ADR-0009); no endpoint ever returns it again.
  Rotation = uninstall + install (spec §9's v1.0 update path).
- **Reject** removes the row; **disable** freezes it (token refuses with
  `extension_disabled`); **uninstall** deletes it (registration cascades).

### 2. `/api/v1/ext/*` is a closed route table, not a proxy (spec §5.3)

`EXT_PROXY_ROUTES` binds every permitted (method, path) to exactly one
scope. Enforcement order per call: bearer → active registration (token =
HMAC of the SecretBoxed secret, recomputed per request, never stored) →
`enabled` → route table → granted scope → rate limit (60/min per extension,
spec §5.3) → resolver → audit as `extension.<slug>.call` in the C11 chain.

Resolvers are **metadata-only by construction**: the prisma `select` lists
omit every secret-bearing column (mailbox password hashes, database
credentials, certificate/key PEM). There is no code path that can leak a
secret to an extension, which is stronger than filtering responses.

**Write scopes are declared but refused in v1.0.** The four write endpoints
(`site:write`, `mail:write`, `dns:write`, `backup:write`) exist in the
route table so a granted scope maps to a named endpoint, and `authorize()`
rejects them with `write_requires_confirmation` + an admin notification
(deduped 10 min). Spec §6 requires per-call admin confirmation for
extension writes; the confirmation queue is the v1.x trust-level work —
until it exists, failing closed is the only honest option. The
`notification:write` scope is NOT gated: creating in-panel notifications
mutates nothing outside the notification center.

### 3. Hook dispatch reuses the audit-tail architecture (ADR-0018)

`ExtDispatchService` tails `audit_entries` exactly like outbound webhooks —
no broker for v1.0 single-node. Deliveries are signed POSTs
(`X-Nexuspanel-Extension-Id` / `-Timestamp` / `-Signature` =
base64(HMAC(secret, method+path+body+timestamp))). Manifest hook keys are
SDK-canonical (`backup.completed`); `HOOK_EVENT_ALIASES` maps them to the
operations the audit chain actually emits (`backup.run.success`). No retry
queue for extension hooks in v1.0 — failure is recorded on the extension
(`last_error`) and the next matching event re-drives it; durable retries
remain the webhooks module's contract. Heartbeats (spec §5.2, every 60 s)
flip a silent extension to `errored`, suspend its token, and notify admins
once; recovery restores `enabled`.

### 4. Widgets are sandboxed iframes with postMessage theme context (spec §7)

The dashboard lists enabled widgets (`GET /extensions/widgets`, self
permission `extension:widgets`) and renders each entry URL in an iframe
with `sandbox="allow-scripts allow-same-origin"`, answering the widget's
`postMessage` handshake with the §7 theme tokens. Widgets get no panel CSS,
no cookies, no storage, no DOM.

### 5. `nexus-example-reporter` is the acceptance test (spec §11)

`examples/nexus-example-reporter/` (~300 lines, Node stdlib only) implements
the §11 contract: `backup.completed`/`backup.failed` hooks → webhook
summary, `last-backup` dashboard widget, strict §5.1 signature + 60 s
window verification on every panel call. It runs unmodified against a fresh
panel install; its verification logic is the reference for every future
extension receiver.

## Consequences

- Extension code can never crash, block, or leak into the panel process —
  the OS process boundary is the isolation (spec §1's cost: no in-process
  event interception; hooks only, via declared endpoints).
- The v1.0 API surface for extensions is read-mostly by design; the
  confirmation queue (v1.x) unlocks the write scopes without schema or
  protocol changes — the route table already binds them.
- Post-GA marketplace (spec §10) stays protocol-compatible: it indexes
  manifest URLs; nothing in this runtime changes.
- Storage (spec §8, `postgres_namespace`) is validated in the manifest but
  not yet provisioned by the runtime — the example extension needs none;
  provisioning lands with the live-VM acceptance run (AS-BUILT §3).

## Verification

- `extensions.service.spec.ts` — trust ladder: inert-until-approved,
  one-time credentials (SecretBox round-trip, deterministic derived token),
  duplicate-slug refusal, closed-scope manifest rejection, compat-window
  rejection, heartbeat failure/recovery + notify-once.
- `ext-proxy.service.spec.ts` — token resolution, disabled/errored refusal,
  anti-probing 404s, scope binding, write-scope fail-closed + deduped
  notification, 429 on call 61, BigInt-safe run sizes, audit attribution.
- Gates before push: jest · typecheck · permissions:check · prisma:check ·
  next build · go vet+test — then CI green on `origin/main`.
