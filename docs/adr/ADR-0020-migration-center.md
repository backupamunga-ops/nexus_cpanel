# ADR-0020 — Migration Center: agent reads/extracts, panel owns the ledger, no credential imports

**Status:** Accepted (B15)
**Amends:** agent spec §4 (adds `migration.*`), API spec §4.21 (migration endpoints live + `GET /migrations/artifacts` shelf addition)
**Builds on:** DDL `migration_jobs` / `migration_entity_mappings` (v2.0, pre-provisioned), migration spec v1.0 (M15, G-17 draft from B13), ADR-0012 DNS (zone writes through DnsService), ADR-0013 mail (mailboxes via MailService), ADR-0015 databases (mariadb adapter + SecretBox credentials), C6 permission guard, D-11 honesty

## Context

B15 closes the batch plan with the Migration Center: cPanel `cpmove-*`
import with per-entity verification. The migration spec (§1–§8) fixed the
contract — analyze (read-only) → dry-run (zero writes) → execute
(resumable) → verify (checksum parity) → report, with acceptance measured
by **throughput + integrity, never wall-clock**. The open design questions
were where extraction happens, who owns the ledger, how the panel touches
provisioned resources without side doors, and what happens to the
credentials inside the artifact.

## Decision

### 1. The agent reads and extracts the artifact; the panel owns the ledger and the phase machine

The cpmove tarball lives on the node; only the agent can stream it. Six
agent methods cover the surface:

- `migration.list_artifacts` (read-only) — the migration shelf with
  size + sha256 recorded on sight;
- `migration.analyze` (read-only) — a streaming, entry-by-entry walk that
  NEVER extracts to the live tree; small members are hashed on the fly;
- `migration.extract_tree` — one `homedir/<dir>` subtree into the account
  home (`--no-same-owner`, chowned to the account user), returning a
  per-file sha256 manifest;
- `migration.extract_member` — one small member inline (zones, certs,
  crons; 2 MiB cap keeps the signed channel lean);
- `migration.hash_tree` (read-only) — the verify pass re-hash;
- `migration.import_database` — dump → temp file → **fresh** DB + user +
  grant (panel-generated credentials) → import → per-table row estimates.

The panel (`MigrationsService`) owns `migration_jobs` /
`migration_entity_mappings` and the status machine
(`analyzed → planned → importing → verifying → completed | failed |
canceled`). The three read-only methods are whitelisted in the agent's
read-only set; everything else is audited through the WAL like every
write.

### 2. Zones, mail and databases are created through the SAME panel services the panels use — no side doors

Execute imports entities through `DnsService.createZone` (ADR-0012
validation, PowerDNS single-writer), `MailService.createDomain/
createMailbox` (B07 policy, quota checks) and the B09 database flow —
never by writing agent methods around them. Consequences: naming rules,
package limits, record allowlists and audit entries all apply unchanged;
a zone the panel cannot legally represent (SOA, unknown RR types) fails
or is skipped **visibly**, not silently. A small zone-file parser
(`zonefile.ts`) maps BIND lines to record inputs: parenthesized
continuations joined, comments stripped, `$TTL` honored, every skipped
line reported in the mapping notes.

### 3. Credentials inside the artifact are NEVER imported (spec §6)

cPanel artifacts carry password hashes (dovecot sha512, DB grants).
Importing them would import their age and weakness (C9/C15) and make
verification impossible. Therefore:

- **mailboxes** are created with fresh random secrets (24-char,
  unambiguous alphabet) — shown to nobody, reset via the panel;
- **database users** are recreated with fresh credentials; the panel
  stores them in a SecretBox envelope (ADR-0009) exactly like a B09
  database; the dump streams into the agent via stdin — never argv;
- **SSL keys** are not imported in v1.0: cert members are extracted and
  checksummed for the report, and the mapping row is an explicit,
  reason-coded SKIP (`unsupported-feature`), never a silent partial.

### 4. SKIP is data, and the ledger is the truth across resumes

Every mapping row is `pending → importing → imported → verified | failed`
or `skipped` with a reason (`unsupported-feature`, `collision`,
`policy-declined`, `empty`). Skips are decided at analyze time (so the
dry-run shows them); collisions (a zone/mail domain/database name the
panel already manages, or a source username that exists as another
account) fail or skip with the name in the notes. Execute is resumable:
terminal rows are never touched, `importing` rows from a killed run are
retried, and the overall job status is computed from the ledger after
every run — a job with ANY failed verification reports `failed` (M15/D-11,
no partial-success dressing). Re-running a finished job imports nothing
twice.

### 5. `GET /migrations/artifacts` is a B15 addition to §4.21

The wizard needs the shelf listing (name, size, sha256) before it can
create a job; the pre-declared §4.21 surface assumed the artifact name
was known. The addition is read-only, `migration:list`-guarded, and the
hashes it returns are the same ones create pins into the ledger.

## Consequences

- The wizard stays DirectAdmin-simple: pick file → pick account → four
  plain steps; every entity verdict is one of verified / created / moved /
  skipped (reason) / failed, with a checksum pair where one exists.
- The cutover plan in the report is generated from the zones the
  migration actually created (records + TTL note + rollback reminder);
  pressing the button against third-party DNS APIs remains out of scope
  (migration spec §9).
- The in-memory digest maps (tree/member) mean a verify pass that runs in
  a *later process* than the import re-hashes and reports honestly
  ("re-hashed after a resumed run") instead of pretending parity it never
  computed.
- v1.0 imports into an **existing** target account; account creation
  stays a panel flow, and `create` refuses when the source username
  already belongs to a different account (collision → rename one side).
