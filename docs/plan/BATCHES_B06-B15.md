# NexusPanel — Batch Plan B06–B15 (Next 10 Batches)

**Operational batch plan | Companion to: `docs/plan/BUILD_PLAN.md`**
**Status:** PLANNED — presented 2026-11-05, following the completed combined B01–B05 delivery (P3: sites/domains, files+SSH keys, SSL/ACME, per-site PHP, config engine, plus FTP and site logs).
**Position:** 76 commits on `main`; phases P0–P3 complete. B06–B15 execute phases P4 → P5 → P6.

---

## 0. Standing rules applied to every batch

1. **Vertical slice:** agent command category → control-plane module → web UI → docs chapter, in the same batch. Never a backend-only batch.
2. **DDL-first:** schema changes land in `specs/nexuspanel-schema-v2.0.sql` first (ADR-0004); Prisma drift check must pass in CI.
3. **Allowlist discipline:** every new agent method is registered explicitly in `registry.go`; no generic exec; read-only classification reviewed per method.
4. **Security controls:** permission decorator (C6) on every new endpoint, hash-chained audit events for every privileged action, path-confinement tests for any new filesystem touch.
5. **Honest badges (D-11):** every UI surface ships empty/loading/error/success states and marks anything "stored — not yet enforced" or "planned" explicitly.
6. **Docs DoD:** each batch refreshes its chapter's live flows **and** the honest not-yet list; portal index "What works" table is corrected (currently stale at "M0 preview").
7. **Gates:** unit + integration (Testcontainers PG16/Valkey), `go test`, OpenAPI diff, permission-coverage CI, E2E smoke — all green before push.
8. **Delivery:** Conventional Commits, one-time push URL, CI verified on `origin/main`; master doc §11 batch-log entry per batch; PAT rotation reminder each batch.

---

## Phase P4 — Mail, DNS, Databases, Backups (B06–B10)

### B06 — DNS core (PowerDNS)

| Layer | Scope |
|---|---|
| Agent | `dns.*`: zone create/delete, record CRUD (A, AAAA, CNAME, MX, TXT, SRV, CAA) via PowerDNS API; DNSSEC enable/disable (`pdnsutil secure-zone`, DS surfacing); zone templates; BIND import/export; propagation checker method |
| Control plane | `dns` module + REST `/dns/zones`, `/dns/zones/:id/records`; auto-record hooks (site create → A/WWW; mail create → MX/SPF later in B08) |
| Web | DNS zone editor per domain: record table, add/edit/delete with RR-value validation, DNSSEC status card, honest dns-01 upgrade note on SSL panel |
| Docs | `dns.html` live chapter; not-yet list refresh (secondary DNS / AXFR: planned, honest) |

**Why first:** unlocks wildcard cert dns-01 (existing honest gap in `ssl.html`), DKIM/SPF/DMARC record writes (B08), and migration DNS cutover (B15).
**Exit:** zone + record E2E on a staged PowerDNS; DNSSEC chain validated with dig; OpenAPI diff clean.

### B07 — Email core (Postfix + Dovecot)

| Layer | Scope |
|---|---|
| Agent | `mail.*`: mail domain on/off, mailboxes (Dovecot SQL userdb against panel DB, Argon2id), aliases, catch-alls, forwarders, per-mailbox quotas |
| Control plane | `mail` module + `/mail/domains`, `/mail/boxes`, `/mail/aliases`; quota checks against package limits |
| Web | Email panel per domain: mailboxes, aliases, catch-all, quota bars; constitutional default shown honestly: **SMTP relay is the delivery default; self-hosted MTA is explicit opt-in** (spec M6 note) |
| Docs | `email.html` live chapter |

**Exit:** mailbox created → authenticated SMTP submission + IMAP delivery E2E on staged node; quota enforcement proven.

### B08 — Email deliverability & relay

| Layer | Scope |
|---|---|
| Agent | `mail.dkim_generate` (opendkim keys per domain), `mail.queue_*` (list/hold/release/delete) |
| Control plane | DKIM→DNS auto-record write (depends B06); SPF + DMARC wizard records; SMTP relay mode config (server-wide relay per Q2: SES/Mailgun/Postmark profile); autoresponders/vacation via Sieve |
| Web | Deliverability wizard (DKIM/SPF/DMARC one-pass with DNS record preview), mail queue tools, autoresponder editor |
| Docs | `email.html` deliverability section |

**Exit:** DKIM-signed mail passes SPF+DMARC alignment in staged test; queue tooling proven against a seeded bad queue.

### B09 — Databases (MariaDB 11)

| Layer | Scope |
|---|---|
| Agent | `database.*`: create/drop databases, users, grants (least-privilege by default), per-DB size/quota reporting, `mysqldump`/restore; `DatabaseEngineAdapter` interface honored (locked resolution 5: MySQL 8 + MariaDB 11 in v1.0) |
| Control plane | `databases` module + `/databases`, `/databases/:id/users`; credentials via SecretBox (ADR-0009 pattern), never in audit payloads |
| Web | Databases panel per account: DB list, user/grant editor, connection-string generator, phpMyAdmin/Adminer SSO link (signed, short-TTL) |
| Docs | `databases.html` live chapter |

**Exit:** DB lifecycle E2E; SSO round-trip; adapter interface reviewed so MySQL 8 addition is additive.

### B10 — Backups & restore

| Layer | Scope |
|---|---|
| Agent | `backup.*`: account/site/DB/backup jobs to local, S3-compatible, SFTP destinations; age encryption (C15); manifest + checksums; `restore_preview` + restore methods |
| Control plane | Backup policies (GFS retention), schedules via job framework, destination credential vaulting, restore-with-preview orchestration |
| Web | Backups panel: destinations, schedules, backup list with sizes, restore preview dialog, honest "verified restore" badges only when test-restore has actually run |
| Docs | `backups.html` live chapter |

**Exit (phase gate for P4):** encrypted backup restored on a clean node; C15 negative test — decryption without master key fails.

---

## Phase P5 — Security stack, audit depth, messaging (B11–B13)

### B11 — Firewall & fail2ban

- Agent `firewall.*`: nftables/ufw rule CRUD under a whitelist model with fail-closed validation (server-settings pattern); fail2ban jail status, ban list, unban (audited).
- Control plane `firewall` module; Web security panel (rules, bans, jail health); docs chapter.
- Exit: rule validation negative tests (no self-lockout rule accepted); ban/unban E2E audited.

### B12 — WAF & anti-malware

- ModSecurity per-site: off/detect/block, paranoia level, exclusion list — wired into the nginx vhost pipeline (config engine versioned + rollback applies).
- ClamAV: scheduled + on-demand scans, quarantine listing with audited delete/restore.
- Web: per-site WAF card, scan center; docs chapter.
- Exit: CRS rule fires in detect vs block on staged payload; quarantine flow E2E.

### B13 — Jobs, webhooks, notifications, audit depth

- BullMQ job center: long-running job states visible (§10 contract: queued/running/succeeded/failed + progress), retrigger with confirmation.
- Outbound webhooks: event subscriptions, HMAC signing, retry with backoff, dead-letter view (§9.4).
- In-app notification center; audit UI chain-verification view + daily verification cron with alert (C11).
- Also lands here: **Migration Center specification draft** (G-17 commitment from BUILD_PLAN P4) as `specs/nexuspanel-migration-spec-v1.0.md`.
- Exit: mid-chain audit tamper detected by the verification cron; webhook dead-letter E2E.

---

## Phase P6 — Apps, Git, staging, migrations (B14–B15)

### B14 — App installer & Git deploy

- App catalog: WordPress first (WP-CLI, runs as the account's user — never root), install/update, one-click staging clone (staging subdomain + config engine swap).
- Git push-to-deploy: GitHub/GitLab/Bitbucket webhook receivers, branch selection, deploy history + rollback, build logs visible.
- Web: Apps panel, Git deploys panel per site; docs chapters.
- Exit: fresh-account WP install < 5 min staged; push-to-deploy E2E with rollback.

### B15 — Migration Center (cPanel first)

- Import cPanel `cpmove-*`: analyze → dry-run → execute → verify (checksum parity per entity), entity-level mapping report, cutover + rollback plan (spec M15; acceptance = throughput + integrity, never wall-clock).
- DNS cutover helper consumes B06; mail import consumes B07/B08.
- Web: migration wizard with per-entity verification results; docs + migration guide.
- Exit: real cPanel account migrated in staging with full verification report.

---

## After B15 (not planned in detail here)

P7 — extension SDK runtime + `nexus-example-reporter` acceptance, performance SLO passes, installer finalization, cosign-signed GA artifacts + SBOM, docs regeneration (B16+).

## Dependencies at a glance

```
B06 DNS ──► B08 deliverability ─────────┐
   │            ▲                       │
   │         B07 mail core ─────────────┤
   │                                    ▼
   ├──────────────────────► B10 backups ◄── B09 databases
   │                                    │
   ▼                                    ▼
B15 migration ◄─────────── B14 apps/git ◄── B11/B12/B13 (P5 chain)
```

## Recovery notes (2026-11-05)

- Sandbox recycle wiped the local clone and the local working master doc; repo re-cloned from `origin/main` — **all 76 commits intact, zero work lost**.
- The local credential vault (PAT #1 storage) was lost with the recycle. Next push requires a fresh one-time credential; rotation reminder stands (4 issued to date).
- Master doc working copy to be rebuilt from `specs/` + git history at B06 time, with the batch log reconstructed from commit history and any un-verifiable register rows marked honestly.
