# NexusPanel — As-Built Register

**Working master document | Companion to: Master Architecture v2.0, BUILD_PLAN v1.0, BATCHES_B06–B15**

| Field | Value |
|---|---|
| Version | 2.2 |
| Date | 2026-11-06 |
| Status | ACTIVE — reconstructed from `specs/` + git history after the 2026-11-05 sandbox recycle |
| Repo state | `origin/main` @ `4d988e5` — 108 commits, CI green (4/4 checks) |
| Docs portal | 26 chapters live, v0.6.0 badge, 32-shot screenshot set (`docs/portal/static/screenshots/p4/`) |

> **Provenance & honesty note.** The original working master doc was lost in the sandbox recycle of
> 2026-11-05. This register was rebuilt from the git log, ADR files, portal state and CI results —
> the commit history is the authoritative record. Rows describe what the repository verifiably
> contains; anything that requires a live server (real VM, real cPanel import, real DNS/mail
> delivery) is marked **dev-rig verified — live-VM acceptance pending** rather than claimed.

---

## 1. Status Snapshot (as of `49627f9`)

| Track | State |
|---|---|
| Phases P0–P6 | **Complete** — M0 skeleton through B15 Migration Center |
| Batches B01–B05 (P3 platform features) | Complete — packages, RBAC, 2FA, sessions, resellers, sites, files, SSL, PHP, config engine, logs, SSH, FTP |
| Batches B06–B10 (P4) | Complete — DNS, mail, deliverability, databases, backups + DirectAdmin-simple UI refresh |
| Batches B11–B13 (P5) | Complete — firewall/fail2ban, WAF/ClamAV, jobs/webhooks/notifications + audit verify cron |
| Batches B14–B15 (P6) | Complete — app installer/push-to-deploy, migration center |
| P7 (extensions & release engineering) | **Extension SDK runtime + `nexus-example-reporter` complete** (`f20abc4`) — registration/scope-review/one-time credentials, closed `/api/v1/ext/*` doorway (60/min, metadata-only), signed hooks + heartbeats, sandboxed widgets; release engineering landed — installer spec v1.0 + support matrix published, k6 SLO harness + nightly gate, cosign+SBOM release workflow (C19/C20) |
| ADRs | ADR-0001 … ADR-0022, all landed (`docs/adr/`) |
| CI | `agent (Go)` ✅ · `control-plane (NestJS)` ✅ · `web (Next.js)` ✅ · `schema drift (DDL ↔ Prisma)` ✅ |
| Gates at HEAD | go vet+test ok · jest 424 pass (35 suites) · typecheck ok · permissions:check ok · prisma:check clean · next build ok |
| UI | DirectAdmin-simple refresh landed (`a2eb83e`): grouped icon sidebar, dark/light themes, real dashboard, design tokens |

---

## 2. Batch Register (reconstructed from commit history)

| Batch | Scope | Key commits | ADR | Verification |
|---|---|---|---|---|
| P0 scaffold | Monorepo, normative spec set | `0271b1b`, `6551b13`, `4574f13` | 0001–0006 | specs imported |
| M0 skeleton | Go agent (signed JSON-RPC/Unix socket), NestJS control plane, Next.js shell, events | `fcbda91`…`106635e` | — | CI pipeline live (`6afa3a7`) |
| Platform core | DDL→Prisma generator, Argon2id auth, hash-chain audit, isolation.provision, portal rig | `87775cc`…`2cecf20` | 0004, 0007 | CI green; drift gate |
| B01–B05 | Packages+quota, C6 RBAC, C4 tokens, C2 2FA, C3 sessions, resellers (C14), server settings (D-11), sites/domains, files+trash (ADR-0008), SSL/ACME (ADR-0009), PHP pools, config engine v1, per-site logs, SSH keys (ADR-0010), FTP (ADR-0011) | `1bd0cb2`…`5d4aac1` | 0008–0011 | per-commit gates + CI |
| **B06** | DNS core — PowerDNS via HTTP API, DNSSEC via pdnsutil, zone/records CRUD, live checks, zone editor | `7493155`, `ca055a5`, `93319c2`, `32dad02` | 0012 | gates + CI |
| **B07** | Mail core — Postfix maps + Dovecot SQL userdb, maildirs, sieve; no secrets to agent; mailboxes/aliases/autoresponders with quota bars | `b382371`, `708d877`, `d39a203` | 0013 | gates + CI |
| **B08** | Deliverability — opendkim keys (`mail.apply_dkim`) → auto DNS record, SPF/DMARC wizard, server-wide relay profile, honestly-parsed queue tools | `a589e63`, `6e3abaa`, `19e18c1` | 0014 | gates + CI |
| **B09** | Databases — MariaDB adapter seam, unix-socket admin, confined dumps, SecretBox credentials, SSO tokens, sizes/grants UI | `5ac4636`, `36290c9`, `db47f09` | 0015 | gates + CI |
| **B10** | Backups — tar.gz+manifest, local/sftp/s3 transports, age encryption (C15), GFS retention (DDL), restore preview/verify, destinations round-trip test, honest schedule/verified badges | `facc374`, `9919774`, `cc1b090`, `7205ea6`, `292a713` | — | gates + CI |
| UI refresh | DirectAdmin-simple: grouped icon sidebar, themes, real dashboard, np-table/np-form/np-empty CSS; 20-shot reshot | `a2eb83e` | — | 20-shot set |
| **B11** | Firewall + fail2ban — managed nftables table, fail-closed apply, self-lockout guard, live jail health, audited unban | `6d32c95` | 0016 | gates: jest 363, 22-shot set |
| **B12** | WAF (ModSecurity per-site: off/detect/block, paranoia, exclusions) + ClamAV scans/quarantine with audited delete/restore | `82319d3` | 0017 | gates: jest 363+, 23-shot set |
| **B13** | Job center (BullMQ-shaped registry, explicit retriggers), HMAC webhooks (dead-letter + redrive + signed ping), notification center, daily audit-chain verify cron (C11), migration spec draft (G-17) | `4659e28` | 0018 | gates: jest 371, 27-shot set |
| **B14** | App installer — WordPress one-click (WP-CLI as account user, never root), staging clone; push-to-deploy (HMAC webhooks, release-symlink history/rollback) | `842bd97` | 0019 | gates: jest 383 |
| **B15** | Migration center — cPanel cpmove import: analyze → zero-write dry-run → resumable execute → verify (per-entity sha256, byte-for-byte checks), BIND zonefile parser, SKIP always explicit + reason-coded, artifact credentials never imported, report + DNS cutover/rollback plan | `49627f9` | 0020 | gates: jest 396 (13 new), 32-shot set |
| **P7** | Extension SDK runtime — register → scope review → approve (one-time creds) → operate; closed `/api/v1/ext/*` doorway (60/min, metadata-only resolvers), signed hooks + 60 s heartbeats, sandboxed dashboard widgets; `nexus-example-reporter` reference extension; release engineering: installer spec v1.0 + support matrix, k6 SLO harness + nightly gate, cosign+SBOM release workflow | `f20abc4` | 0021 | gates: jest 424 (28 new) |

---

## 3. Honest Acceptance Status (D-11)

Verified by automated gates and CI on the dev rig. **Not yet** exercised on a real server:

| Acceptance item (from plan) | State |
|---|---|
| B06 — wildcard-cert DNS-01 / real PowerDNS on VM | dev-rig verified — live-VM acceptance pending |
| B07/B08 — real inbound/outbound mail delivery, relay through provider | dev-rig verified — live-VM acceptance pending |
| B09 — live MariaDB 11 round trip | dev-rig verified — live-VM acceptance pending |
| B10 — real S3/SFTP round trip + real restore on VM | dev-rig verified — live-VM acceptance pending |
| B11 — nftables apply + fail2ban jails on live VM | dev-rig verified — live-VM acceptance pending |
| B12 — CRS fires detect-vs-block on staged payload | dev-rig verified — live-VM acceptance pending |
| B14 — fresh-account WP install < 5 min staged | dev-rig verified — live-VM acceptance pending |
| B15 — real cPanel account migrated in staging with full report | dev-rig verified — live-VM acceptance pending |
| P7 — example extension passes against a fresh install; API p95 ≤ 300 ms + agent op p95 ≤ 1 s on reference hardware; installer E2E on a live VM | SDK runtime: dev-rig verified (`extensions.service.spec` + `ext-proxy.service.spec`, 28 tests; example extension E2E pending the live rig) — SLO harness landed, thresholds enforced nightly for public API; live-VM acceptance pending |

**Recommended next milestone:** one live-VM acceptance run executing the pending rows above in
dependency order (B06 DNS → B07/B08 mail → B09 → B10 → B11 → B12 → B14 → B15), using the portal's
Getting-started and server-settings chapters as the runbook.

---

## 4. ADR Index (all landed)

| ADR | Decision |
|---|---|
| 0001 | MariaDB-only (v1.0) |
| 0002 | SMTP relay phasing |
| 0003 | Reseller custom domains |
| 0004 | DDL is the schema source of truth |
| 0005 | Agent sees metadata-only file ops |
| 0006 | Kickoff scope rulings |
| 0007 | Partial unique indexes |
| 0008 | Filesystem content ops |
| 0009 | Secrets at rest (SecretBox) + ACME contract |
| 0010 | SSH authorized_keys managed-line reconcile |
| 0011 | FTP virtual users via pam_userdb |
| 0012 | DNS = PowerDNS (HTTP API + pdnsutil) |
| 0013 | Mail core: Dovecot SQL userdb; no passwords to the agent |
| 0014 | Deliverability: DKIM auto-record + relay profile |
| 0015 | Databases: MariaDB adapter seam |
| 0016 | Firewall: managed nftables + fail2ban |
| 0017 | WAF (ModSecurity per-site) + ClamAV |
| 0018 | Jobs, webhooks, notifications, audit depth |
| 0019 | Apps & git deploy (release-symlink model) |
| 0020 | Migration center (cpmove, verify-first) |
| 0021 | Extension SDK runtime (out-of-process, scope-reviewed) |
| 0022 | Installer ships the web origin as a systemd unit (not a static export) |

---

## 5. Conventions That Survived the Recycle

- **Screenshots:** the Playwright rig (`e2e/screenshots.mjs`) is part of every batch loop — every UI
  surface is re-shot into `docs/portal/static/screenshots/p4/` (now 32 shots) and embedded in the
  portal chapters, which double as the user manual.
- **UI standard:** DirectAdmin-simple — a non-technical user must be able to navigate; plain-language
  steps, honest badges, grouped icon sidebar. New screens follow `a2eb83e` tokens/components.
- **Push hygiene:** one-time inline push URLs only; never commit credentials; rotate push tokens
  after each use.
- **Gates before push:** go vet+test · jest · typecheck · permissions:check · prisma:check ·
  next build — then CI must be green on `origin/main`.

---

## 6. What's Next

1. **Live-VM acceptance run** — the procedure now exists:
   `docs/runbooks/acceptance-p4-p7.md` (install.sh first drive + one verdict
   table per pending Section 3 row, evidence captured to
   `/root/acceptance-evidence/`). Execute it on a fresh VM and record the
   verdicts.
2. **P7 remainder:** per-call confirmation queue for extension write scopes
   (v1.x trust levels, ADR-0021 §2), extension storage namespaces (SDK spec
   §8), GA tag + changelog. (`install.sh` itself has landed — its first real
   drive is step 1 of the runbook.)
3. **First release:** push a `v*` tag — `release.yml` builds the agent binary,
   SBOMs and keyless cosign signatures; no secrets setup required.
4. Standing: revoke the tokens exposed in chat; issue a fresh one-time token
   for the next push.
