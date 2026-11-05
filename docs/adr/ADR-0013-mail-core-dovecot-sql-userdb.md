# ADR-0013: Mail core — Dovecot reads credentials from the panel DB; the agent owns files, not passwords

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P4 (B07 email core)
- **Deciders:** Security review per BUILD_PLAN §2 WS7

## Context

B07 needs real mailboxes on the node: Postfix must route and deliver,
Dovecot must authenticate and serve IMAP. Two earlier patterns were on the
table:

1. **The FTP pattern (ADR-0011):** the agent holds everything — per-user
   config files plus a local userdb it rebuilds itself. Passwords travel to
   the agent (over the signed Unix socket), are hashed there, and live only
   in agent-managed files.
2. **The DNS pattern (ADR-0012):** the service (PowerDNS) is the authority
   and already has its own state store; the agent is a thin, validated
   writer.

Mail is neither. The schema (DDL-first, `specs/nexuspanel-schema-v2.0.sql`)
already commits the panel to owning mailbox state: `mailboxes.password_hash`
is a panel column with the comment "Dovecot SHA-512", and the batch plan
names "Dovecot SQL userdb against the panel DB". That is a third pattern:

3. **Dovecot reads the panel DB directly.** The panel is the credential
   authority; the agent is only a filesystem/config writer.

## Decision

**1. Dovecot userdb/passdb point at the panel PostgreSQL.** One-time node
wiring (runbook `docs/runbooks/`): a read-only SQL role `nexus_mail` with
`password_query` / `userdb_query` against `mail_domains` ⋈ `mailboxes`
(active rows only). The queries shipped in the runbook select **only**
`password_hash`, a composed `home` path, quota and uid/gid — the SQL role
can neither read other tables nor write anything.

**2. Password hashing happens in the control plane, not the agent.**
The CP hashes with Dovecot's native `{SSHA512}` scheme (base64 of
`SHA512(password ‖ salt)` + salt) and stores it in `mailboxes.password_hash`.
Consequences, all deliberate:

- The agent never sees a mailbox password. The password path is
  browser → CP → DB; there is no third copy anywhere.
- `mail.modify_mailbox` is amended (agent spec §4.8) to **drop the
  `password_hash` param**: rotation is a panel-DB update; the agent is not
  in the password path. Argon2id stays available for the day Dovecot nodes
  ship libsodium — the scheme is a single column value, swappable per row.
- The agent command channel carries no credential material for mail.

**3. The agent owns everything that is a file on the node:**

- Postfix maps under `/etc/postfix/nexuspanel/` — `virtual_domains_map`,
  `virtual_mailboxes_map`, `virtual_aliases_map` — flat managed files,
  rebuilt from full desired state on every mutation, then `postmap`ed.
  A missing `postmap` is an **honest skip** in the response (maps not
  rebuilt; routing cannot work until it is) — never a silent success,
  mirroring the ftp userdb precedent.
- Maildirs under `/srv/vmail/<domain>/<local_part>/` with the classic
  `cur/new/tmp` scaffold, owned by the `vmail` user (uid/gid via agent
  env; when unset — dev rigs — the chown is an honest skip in the response).
- Per-mailbox quota as a `maildirsize` file (`<bytes>S`).
- Autoresponders as Sieve vacation scripts in the mailbox's
  `.dovecot.sieve`. Scheduling windows (starts/ends) are a **panel-side
  truth**: the CP stores them and the UI marks a responder "scheduled" or
  "expired" honestly; the panel does not yet flip the Sieve file at window
  edges (job framework lands in B13).

**4. Delivery default is relay-only.** ADR-0002 stands: applications on the
node hand mail to the server-wide SMTP relay; a self-hosted MTA (local
Postfix listening for customer domains) is **explicit opt-in per mail
domain** from B08's deliverability work. The B07 email UI states this on
every mail domain card (D-11) — "stored — not yet routing" until B08 wires
transport.

## Consequences

- The agent's mail methods are purely file/config operations — testable
  with injected roots and fake `postmap` binaries, no mail stack in CI.
- Deleting a mail domain requires zero active mailboxes/aliases first
  (CP-enforced, 409); the agent cleans every map line for the domain.
- The panel DB becomes part of the IMAP authentication path — the daily
  audit-chain verification and backup jobs (B10) must treat `mailboxes`
  as tier-0 state. Backups of the panel DB therefore protect mail logins.
- A compromised control plane can read mailbox hashes; that is already the
  trust boundary (it holds Argon2id login hashes too). The SQL mail role
  shrinks what a **Dovecot** compromise can reach to hashes and paths only.
