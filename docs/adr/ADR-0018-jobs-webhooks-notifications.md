# ADR-0018 — Jobs, webhooks, notifications: in-process dispatch with queue-shaped registries

**Status:** Accepted (B13)
**Amends:** API spec §4.22 (webhooks live), §4.23 (notification permissions), §4.26 (job center)
**Builds on:** DDL `jobs_metadata` / `webhooks` / `webhook_deliveries` / `notifications` (v2.0), C11 audit chain, ADR-0009 SecretBox

## Context

B13 wires the panel's async surface together: a visible job center, signed
outbound webhooks, an in-app notification center, and the daily audit-chain
verification (C11). The original batch plan named BullMQ; the deployment
target for v1.0 is single-node without a broker dependency, and the panel
already has a perfectly good event source: the audit chain.

## Decision

### 1. Job center: DB registry, BullMQ-shaped, in-process executor

`jobs_metadata` is the visible state of long-running work — columns already
carry the BullMQ shape (`queue_name`, `job_type`,
waiting|active|completed|failed, `progress`, `attempts`, `bullmq_job_id`).
v1.0 executes in-process; `bullmq_job_id` stores an opaque executor id
(`inproc_*`, `run_*`, `scan_*`). A BullMQ deployment replaces ONLY the
executor — the registry, API and UI are unchanged. Retrigger is an explicit
per-type handler allowlist (`malware.scan`, `backup.run` at B13), audited,
starting a NEW row per attempt: history is never overwritten.

### 2. Webhooks: the audit chain is the event bus

Dispatch tails `audit_entries` (cursor = last seen id, in-process poller,
5 s). Subscriptions match exact names, family wildcards (`account.*`) or
`*`. Delivery contract (§9.4): JSON `{event, occurred_at, data}` with
`X-Nexus-Event`, `X-Nexus-Timestamp`, and
`X-Nexus-Signature: sha256=<HMAC-SHA256(secret, timestamp + '.' + body)>`
— GitHub-style signing so receivers verify authenticity and reject replays
by timestamp window. Secrets live as SecretBox envelopes (ADR-0009),
decrypted only at delivery time, never returned.

Failure handling is honest: exponential backoff (30 s · 2^(n−1), capped
1 h), five attempts, then the delivery is DEAD — with a notification to
server admins and a redrive endpoint to re-arm it. Each retry hand-off
nulls the old row's `next_retry_at` so no row is ever picked twice per
tick (the double-delivery bug the dead-letter test caught and pins).

### 3. Notifications: strictly own-feed producers

`notifications` rows are per-user; routes carry `notification:read` /
`notification:manage` permissions PLUS own-row scoping (both layers).
Producers at B13: the audit verify cron (failures → all super admins) and
webhook dead-letters. The producer API (`notify()`) is intentionally tiny
so P6 features (migrations) reuse it without a new mechanism.

### 4. Audit verification: cron with teeth (C11)

Runs at boot (+30 s) and every 24 h: walk the whole chain; on ANY break →
notify every super admin (severity error) AND append a `failure` audit
entry, so the evidence of tampering becomes part of the tamper-evident
record. Clean runs log, they don't spam. The batch-plan exit criterion —
a mid-chain tamper detected by the cron — is pinned by a unit test that
rewrites a mid-chain parameter and asserts `brokenAt`, the admin
notification, and the failure audit entry.

## Consequences

- New permission vocabulary: `webhook:*` (5), `job:list`/`job:manage`,
  `notification:read`/`notification:manage`; web mirror kept in sync.
- No new runtime dependencies (no redis/bullmq yet) — a deliberate v1.0
  single-node posture; the migration path is executor-only.
- The webhook poller is process-local: multi-node deployments will move it
  behind a lock or the BullMQ executor (noted in the module docs).
- Migration Center specification draft (G-17) delivered as
  `specs/nexuspanel-migration-spec-v1.0.md` for B15.
