# ADR-0002: Server-wide SMTP relay in v1.0; per-account override ships in schema first

- **Status:** Accepted (locked, Batch 1 Q2)
- **Phase:** P0

## Context

Outbound mail from customer applications needs a relay. Per-account provider
configuration (SES/Mailgun/Postmark/custom) is a requested capability, but its UI is
not required for GA.

## Decision

v1.0 ships a **server-wide SMTP relay** configuration. The per-account override table
`account_smtp_relay_config` (nullable, provider + age-encrypted credentials) is
created **now** in the DDL to avoid a migration later; its **UI ships in v1.2**.
Until then the table exists unused by the UI but is enforced by the same secret-encryption
CI rules (C9).

## Consequences

- No schema migration needed when the v1.2 UI lands.
- CI secret-column scan covers the table from P0 even before its UI exists.
