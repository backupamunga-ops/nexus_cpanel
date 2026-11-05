# ADR-0009: Secrets at rest use AES-256-GCM envelopes, not age — and the ACME issuance contract carries the PEM material

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P3 (sites, files, SSL, config engine)
- **Deciders:** Security review per BUILD_PLAN §2 WS7, Backend #1

## Context

Two P3 questions needed a ruling before code:

1. **The schema marks secret columns `*_enc bytea` as "age-encrypted"**
   (certificates, SMTP relay credentials, webhook secrets, backup
   destinations), but no encryption utility existed in the control plane.
   Age is a file-exchange tool: recipient identities, per-file stanzas,
   armoring for transport. The panel's threat model is narrower — database
   row exfiltration — and its operational model simpler: one process-wide
   secret held by the control plane.

2. **`ssl.issue_acme` (agent spec §4.11) returns nothing** — but the
   control plane must persist the issued certificate (`cert_pem_enc` /
   `key_pem_enc` columns already exist) to serve metadata, renewals and the
   cross-domain certificate list. Additionally, http-01 requires serving
   the challenge token over port 80, which in production belongs to nginx;
   an agent-side listener would fight the web server for the port.

## Decision

**1. Secrets at rest:** `apps/control-plane/src/common/secretbox.ts` —
AES-256-GCM with a key derived (scrypt, fixed app salt) from
`PANEL_SECRET_KEY` (≥ 32 bytes entropy; base64 or UTF-8). Envelope:
`v1:<iv>:<tag>:<ciphertext>`, base64 components. Properties:

- **Fail-closed on configuration**: a missing or short `PANEL_SECRET_KEY`
  throws at first use. Silently encrypting under an ephemeral default key
  would produce data unreadable after restart — worse than refusing to
  start.
- **Versioned envelope**: future migration to age or key rotation is a
  readable re-encryption pass, not archaeology.
- **No new dependencies.** age remains the right answer for the installer
  (P7) where offline key ceremony actually exists; this ADR records that
  divergence from the schema comments.

**2. ACME issuance contract:** `ssl.issue_acme` params gain `webroot` (the
site's document root, control-plane-supplied) and the result carries
`cert_pem`, `key_pem`, `expires_at`, `issuer`, `san_names`. The agent:

- serves http-01 challenge tokens from `<webroot>/.well-known/acme-challenge/`
  — the running webserver (which owns port 80) serves them; the agent never
  binds the port;
- confines the webroot to the hosting home root (C13), symlink-aware;
- persists the ACME account key (`acme-account.key`, 0600) so re-issuance
  reuses the same ACME account (rate-limit friendly);
- cleans up challenge files on every exit path;
- returns the PEM material to the control plane over the signed RPC channel
  for encrypted storage.

`challenge_type: dns01` is an explicit precondition (no DNS write path
exists yet) — a documented refusal, not a silent fallback.

## Consequences

- Certificates store as `cert_pem_enc` / `key_pem_enc` via SecretBox; the
  control plane can report expiry metadata without decrypting.
- The agent-side private key files (0600, root-only) remain the serving
  copy; the encrypted DB copy exists for renewals, migrations and
  reporting — two locations, both stated in the docs chapter.
- `PANEL_SECRET_KEY` becomes a required deployment setting, joining
  `CP_SIGNING_KEY_PATH` in the key-management runbook.
