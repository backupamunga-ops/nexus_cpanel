# NexusPanel Migration Center — Specification v1.0 (DRAFT)

**Status:** Draft (G-17 commitment from BUILD_PLAN P4, delivered with B13; B15 implements it)
**Builds on:** API spec §4.21, DDL `migration_jobs` / `migration_entity_mappings` (v2.0), B06 DNS cutover, B07/B08 mail, B09 databases, B10 backups
**Governing rule (M15):** acceptance is **throughput + integrity, never wall-clock**. A migration is good when every entity verifies byte-true and the report says so — not when it finishes fast.

---

## 1. Purpose and scope

The Migration Center moves a hosting account from a source control panel
(cPanel first) into NexusPanel with **verifiable integrity at every step**:

- analyze (read-only inventory of the source archive/account),
- dry-run (a full plan with no writes),
- execute (ordered, resumable import),
- verify (checksum parity per entity, per file),
- cutover + rollback plan (DNS + mail, consuming B06/B08).

In v1.0 the source is a **cPanel account backup** (`cpmove-<user>.tar.gz`,
`backup-<date>_<user>.tar.gz`, or a `/home/<user>` skeleton produced by
`pkgacct`). Direct live-cPanel API pulls are explicitly OUT of scope for
v1.0 (they need credentials on the source box; the file-based path needs
only an artifact the operator already has).

## 2. Artifact intake and safety

- Upload (or agent-side read) of one `.tar.gz` artifact into the node's
  migration staging root (confinement mirrors the backup root rules:
  absolute paths rejected, `..` rejected, size + count caps, sha256 of the
  artifact recorded before anything else happens).
- `analyze` NEVER extracts to the live tree: it walks the tarball
  (streaming, entry-by-entry) and produces the inventory:
  - DNS zones (`dnszone` files),
  - mail: domains, forwarders, account lists (no passwords — see §6),
  - databases (`.sql.gz` dumps per database),
  - web roots (`public_html`, addon/parked domain dirs),
  - crons, SSL certs (when present), email quotas.
- Malformed artifacts fail analyze with a precise, per-entry reason. A
  partial inventory is NEVER silently promoted to a plan.

## 3. Entity mapping (the contract)

Every source entity maps to exactly one target entity (or is SKIPPED with a
reason). `migration_entity_mappings` is the ledger: one row per entity with
`source_ref`, `target_ref`, `checksum_source`, `checksum_target`,
`verify_status`. Rules:

| Source (cPanel) | Target (NexusPanel) | Verification |
|---|---|---|
| `username` | hosting account (renamed per operator mapping table; collision → fail analyze) | row parity + homedir checksum tree |
| `public_html/`, addon docroots | domains (primary/addon) + files | per-file sha256 parity (manifest diff, not vibe) |
| `dnszone` file | dns zone + records (B06 agent import) | AXFR/record-set diff vs source zone |
| email forwarders/aliases | mail aliases (B07) | count + per-alias content parity |
| mailboxes | mailboxes with quotas (B07); passwords NOT migrated (§6) | mailbox row parity |
| `<db>.sql.gz` | MariaDB database (B09 agent restore) | row count + checksum parity via `CHECKSUM TABLE` + dump sha256 |
| SSL cert/key | certificate store (P3 SSL) | cert/key pair match (moduli + CN/SAN) |
| crontab entries | per-account cron list (stored; execution = B13 job framework) | line-by-line parity report |

`SKIP` is always explicit and always reason-coded
(`unsupported-feature`, `policy-declined`, `collision`, `empty`).

## 4. Flow

```
create ──► analyze ──► dry-run ──► (approve) ──► execute ──► verify ──► report
   (upload)   (read-only)  (no writes)             (resumable)   (checksums)  (§5)
```

- **analyze** produces the entity inventory + preflight problems.
- **dry-run** renders the exact ordered plan (accounts → domains → files →
  DNS → mail → databases → SSL → crons) with per-entity target refs and
  estimated sizes. No writes anywhere. The dry-run report is the artifact
  the operator approves.
- **execute** runs the plan in order; every entity transition is journaled
  in `migration_entity_mappings` (status: pending → importing → imported →
  verified | failed | skipped). Execute is RESUMABLE: a stopped run
  continues at the first non-terminal entity. Failures do not abort the
  whole run; they mark the entity and continue, and the report aggregates.
- **verify** re-reads every imported entity and compares checksums with the
  source inventory (per §3). A migration with ANY failed verification is
  reported as failed overall — no partial-success dressing (D-11).
- **cutover** (optional, operator-driven): a DNS cutover plan consuming
  B06 — lower TTLs, then switch A/AAAA/MX/SPF/DKIM/DMARC records at the
  authoritative nameservers, with an explicit rollback plan (the previous
  records, stored, one click to revert). Mail cutover consumes B07/B08
  (relay profiles so inbound mail is held, not bounced, during the move).

## 5. The report

`GET /migrations/{id}/report` returns the mapping ledger rendered as:
per-entity status, checksum parity, skipped-with-reason, byte totals, and
the cutover/rollback plan. The report is the acceptance artifact — it is
audited (operation `migration.report`) and can be re-generated any time.

## 6. Passwords and secrets

cPanel artifacts contain password hashes (dovecot sha512, DB grants). The
Migration Center **never imports credentials**:

- mailboxes are created with RANDOM secrets; users reset via the panel
  (ADR-0013 discipline: the agent never sees mail passwords anyway);
- database users are recreated with fresh credentials; grants are mapped,
  not copied;
- SSL keys arrive inside the artifact and are stored per ADR-0009
  (SecretBox envelope) — they never appear in logs, reports or the API.

Rationale: importing foreign password hashes would (a) import their age and
weakness, (b) contradict the C9/C15 posture, (c) make "verify" impossible
for credentials anyway.

## 7. API surface (as pre-declared in API spec §4.21)

`POST /migrations` (upload/create) → `POST /{id}/analyze` →
`POST /{id}/dry-run` → `POST /{id}/execute` → `POST /{id}/cancel` →
`GET /{id}/report`. All routes are super-admin (`migration:*` permissions),
audited, and rate-limited like every other surface.

## 8. Acceptance (B15 exit)

1. A real cPanel account artifact migrates in staging with a FULL
   verification report (all entities verified or explicitly skipped with
   reason).
2. Kill the execute at any point → resume completes; the ledger shows no
   double-imports.
3. Every entity whose verification fails is visible in the report with its
   checksum pair — the operator can diff byte-for-byte.
4. DNS cutover plan is generated from B06 zones and is reversible in one
   audited step.

## 9. Out of scope for v1.0

Live source-panel API pulls (see §1), Plesk/DirectAdmin sources (P7+),
automated DNS provider cutover (the plan is generated; pressing the button
against third-party DNS APIs is a later feature), reseller-tree migration,
and mailing-list content migration.
