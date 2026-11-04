# NexusPanel — End-to-End Build Plan

**Operational execution plan | Companion to: NexusPanel Master Project Documentation v1.0**

| Field | Value |
|---|---|
| Version | 1.0 |
| Date | 2026-11-05 |
| Status | ACTIVE — build authorized by project owner ("let's start building") |
| Team | 10 people (master spec §16.3 + 2 UI/UX designers) |
| Target | v1.0 GA through 8 phases (P0–P7), estimated 22–24 weeks with a fully-staffed team |
| Repo | `github.com/backupamunga-ops/nexus_cpanel` |

---

## 1. Operating Model

- **Specification is law.** The five normative documents govern. Code that contradicts them is a bug; needed changes go through ADRs (Engineering Constitution §P.6).
- **Trunk-based delivery.** Protected `main`, short-lived branches, Conventional Commits, squash merges. Every PR references a phase ID (P0…P7) and workstream (WS1…WS8).
- **Build as we commit.** The repository receives working, reviewed increments continuously — never long-lived dead-end branches.
- **Vertical slices over layers.** After M0, every feature ships as API + UI + docs + tests in the same phase — no "backend year, frontend year."
- **Definition of Done (every feature):** code + tests · OpenAPI diff clean · permission decorator (C6) · audit events hash-chained · docs page + regenerated screenshots · a11y checks green · changelog entry.

## 2. Workstreams

| WS | Workstream | Staff | Owns |
|---|---|---|---|
| WS1 | Platform & Infra | DevOps/SRE | Monorepo, CI/CD, installer, environments, releases, observability |
| WS2 | Control Plane | Backend #1 + #2 | NestJS API, Prisma/schema, queues, config engine, audit chain |
| WS3 | Agent | Backend #2 (+ Tech Lead review) | Go agent: all 15 command categories, WAL, drift, signing |
| WS4 | Web UI | Frontend #1 + #2 | Next.js app, all screens, real-time surfaces |
| WS5 | Design System & UX | UI/UX #1 + #2 + Product | Design system, screen specs, a11y, usability tests |
| WS6 | Docs & Screenshots | Tech Writer (v0.4+) + UI/UX #2 | Docs portal, Playwright screenshot rig, runbooks |
| WS7 | Security | Security Eng (v0.5+) | C1–C20 verification, fuzzing, pentest, release signing |
| WS8 | QA & E2E | All + SRE | Test strategy, E2E suites, load tests, release gates |

## 3. Phase Plan

### P0 — Foundations (Week 1) ← CURRENT PHASE

| WS | Deliverables |
|---|---|
| WS1 | Monorepo layout, CI skeleton (lint/typecheck/test/build gates), docker-compose dev stack (PostgreSQL 16 + Valkey), release engineering conventions |
| WS2 | Prisma wired to DDL (CI drift check), NestJS app skeleton, `/health` `/ready` `/version` |
| WS3 | Go module, JSON-RPC 2.0 framing over Unix socket, Ed25519 signature verification, typed allowlist registry (account.* methods), stub execute |
| WS4 | Next.js app shell, design-token plumbing, login page shell |
| WS5 | Design-system draft: tokens (dark-first, `#6366f1` primary, Inter, 8px), core component list |
| WS6 | Docs portal skeleton + full IA stub; ADRs 0001–0006 for locked decisions |
| — | **Specs imported into `/specs`** (all 5 normative docs + extracted `schema.sql`) |

**Exit criteria:** CI green on `main`; `docker compose up` boots control plane against real PostgreSQL/Valkey; agent binary compiles and answers a signed `system.health` over its socket; specs are versioned in-repo.

### P1 — M0 "Hello, privileged agent" (Week 2)

One vertical thread through every layer: login → create test account → NestJS → signed mTLS → agent creates Linux user + cgroup slice → hash-chained audit entry → UI shows account with live agent usage.

| WS | Deliverables |
|---|---|
| WS2 | Auth module (Argon2id + JWT + refresh rotation), accounts module (create/suspend/delete minimal), agent-proxy client (mTLS + Ed25519 signing), audit-chain writer + verify endpoint |
| WS3 | `account.create/suspend/resume/delete/usage`, `isolation.provision` (cgroup v2 slice), WAL read-only mode, capability hardening |
| WS4 | Login + 2FA prompt, accounts list + create dialog, live usage card (WebSocket) |
| WS5 | Account screens final spec; usability test script v1 |
| WS6 | M0 user-guide chapter + first automated screenshots |
| WS7 | Signature/tamper negative tests; path-confinement fuzz round 1 |

**Exit criteria:** M0 flows clean on a fresh VM; tampered signature, expired command, and control-plane-restart WAL-drain tests pass.

### P2 — Identity, Accounts, Resellers (Weeks 3–5)

- Full RBAC + permission decorator coverage (C6 CI check live) · API tokens with scopes (C4) · sessions UI (C3) · TOTP 2FA complete (C2)
- Packages CRUD + quota JSON · hosting account lifecycle + access sharing + clone · resellers with nesting, branding, custom domain (Q3) + session isolation (C14)
- UI: admin console navigation, users/tokens/accounts/packages/resellers screens
- Docs: accounts & packages & resellers chapters + screenshots

**Exit:** cross-account isolation suite (C7) green; permission CI check rejects any undecorated controller.

### P3 — Sites, Files, SSL, Config Engine (Weeks 6–9)

- Domains/subdomains/aliases/redirects · PHP-FPM pools per site (8.1–8.4) · Let's Encrypt issue/renew/revoke (http-01 + dns-01)
- File manager (browser), trash with 30-day purge, FTP/SFTP, SSH keys
- Config engine v1: versioned configs, validate → apply → health-check → auto-rollback, drift detection (15 min, alert-only)
- Agent: `filesystem.*`, `nginx.*`, `php.*`, `ssl.*`, `config.*` categories
- UI: sites hub, file manager (keyboard-first), SSL screens, config version timeline
- Docs: sites/PHP/SSL/files chapters + screenshots; design system v1.0 frozen

**Exit:** drift demo + auto-rollback demo on staged config breakage; cert auto-renewal proven; C8/C13 fuzz rounds green.

### P4 — Mail, DNS, Databases, Backups (Weeks 10–13)

- Postfix/Dovecot: domains, mailboxes, aliases, catch-alls, autoresponders, mailing lists, DKIM, queue tools; server-wide SMTP relay (Q2)
- PowerDNS: zones, records, templates, import/export, DNSSEC (ZSK/KSK), propagation checks
- MariaDB 11 provisioning (create/delete/users/grants/dump/restore), phpMyAdmin SSO
- Backups: destinations (local/S3/SFTP), schedules, checksum + verify, restore preview, age encryption (C15)
- Agent: `mail.*`, `dns.*`, `database.*`, `backup.*`
- Migration spec drafted (Backend #1) — G-17 commitment
- Docs: mail/DNS/databases/backups chapters + screenshots

**Exit:** DKIM-signed E2E mail flow; DNSSEC chain validated; encrypted backup restored on clean node; C15 negative test (decrypt without master key fails).

### P5 — Security Stack, Audit UI, Messaging (Weeks 14–16)

- nftables/ufw rule manager · fail2ban jails/bans/unban · ModSecurity per-site (off/detect/block, paranoia, exclusions) · ClamAV scan + quarantine UI
- Audit UI with chain verification view · daily verification cron + alerts (C11)
- BullMQ job center, outbound webhooks with retry/dead-letter, in-app notifications
- Security engineer at full ramp: controls verification matrix signed off, external pentest scheduled
- Docs: security/audit/webhooks chapters + screenshots

**Exit:** C16–C18 verification suites green; mid-chain audit tamper detected by verification; incident playbook #1 tabletop complete.

### P6 — Apps, Git, Staging, Migrations (Weeks 17–20)

- App catalog (WordPress first, then Laravel/Joomla/Drupal), install/update/staging clones
- Git deployments: GitHub/GitLab/Bitbucket, webhook-triggered, rollback
- Staging environments (clone site → staging subdomain → push/pull)
- Migration tool: cPanel/DirectAdmin/Plesk analyze → dry-run → execute → verify, entity-level mapping reports
- Docs: apps/git/staging chapters + screenshots; migration guide

**Exit:** real cPanel account migrated in staging with verification report; git push-to-deploy E2E; app install on fresh account < 5 min.

### P7 — Extensions, Hardening, Beta → GA (Weeks 21–24)

- Extension SDK runtime + `nexus-example-reporter` acceptance test (runs unmodified against fresh install)
- Performance passes against SLOs (API p95 ≤ 300 ms, agent op p95 ≤ 1 s); nightly k6 load suite
- Installer spec finalized from the proven v0.1 path; support matrix published
- Beta program → bug triage → v1.0 GA tag, cosign-signed artifacts + SBOM (C19/C20)
- Docs: complete portal, API reference published, all screenshots regenerated for GA

**Exit:** GA checklist 100%; example extension passes; load targets met on reference hardware.

### Post-GA queue (v1.2+)

`DatabaseEngineAdapter` (MySQL 8, PostgreSQL) · per-account SMTP relay UI · extension trust levels · billing-bridge extension (G-11 decision) · webmail evaluation (G-12) · marketplace groundwork.

## 4. M0 Scope (acceptance contract)

**In scope:** single admin login (email+password, Argon2id; 2FA enroll deferred to P2) · one "create test account" action · agent executes `account.create` + `isolation.provision` (cgroup v2) · audit entry hash-chained end-to-end · accounts list with live usage via WebSocket · negative suite (tamper/expiry/WAL).

**Explicitly out:** sites, mail, DNS, databases, SSL, backups, apps, resellers, extensions — those start P2+.

**Why this order:** M0 is the cheapest full-stack proof. If the schema, protocol, or trust model has a flaw, it surfaces in week 2 — not after 50 features are built on it.

## 5. Testing Strategy by Layer

| Layer | Tools | Gates |
|---|---|---|
| Schema | Prisma validate + CI DDL diff | Zero drift allowed |
| Control plane | Jest + Testcontainers (PG16 + Valkey) | Unit ≥ 80% changed lines; integration green |
| API contract | OpenAPI diff CI job | Any undeclared change fails |
| Agent | `go test` + integration VM suite | Allowlist negative tests; signature tamper tests |
| Isolation | Cross-account suite (C7) | Must pass before any release |
| E2E | Playwright | Smoke on PR; full suite nightly |
| Load | k6 | Nightly; SLO report weekly |
| Security | fuzzing, axe, testssl, SCA | Phase gates per C1–C20 |

## 6. Documentation & Screenshot Track (parallel, every phase)

1. Docs portal lives at `/docs` in-repo; every feature PR includes its docs page (DoD).
2. Playwright rig screenshots the demo environment (seeded, deterministic) on every UI-affecting merge → `/docs/static/screenshots/<version>/`.
3. Tech writer (from P2 onward) owns prose; engineers own accuracy; UI/UX #2 owns visual consistency.
4. API reference auto-published from the OpenAPI artifact.
5. Release checklist includes: docs build green + screenshots regenerated + changelog.

## 7. Timeline Summary

| Phase | Weeks | Cumulative | Hard dependency |
|---|---|---|---|
| P0 Foundations | 1 | W1 | none |
| P1 M0 | 1 | W2 | P0 |
| P2 Identity/Accounts | 3 | W5 | M0 |
| P3 Sites/Files/SSL/Config | 4 | W9 | P2 |
| P4 Mail/DNS/DB/Backups | 4 | W13 | P3 (config engine) |
| P5 Security/Audit | 3 | W16 | P4 |
| P6 Apps/Git/Migrations | 4 | W20 | P4 |
| P7 Extensions/Hardening/GA | 4 | W24 | P5+P6 |

Parallelization notes: WS5 (design system) runs one phase ahead of WS4 implementation at all times; WS6 docs lag implementation by ≤ 1 phase; P5 and P6 overlap W17–20 with disjoint workstreams; installer spec is authored during P0/P1 (not deferred to a crunch).

## 8. Rules of Engagement

1. No feature starts without its screen spec (WS5) and API contract entry — the two 1-page artifacts.
2. Any spec deviation = ADR before code.
3. Secrets never enter the repo or CI logs (G-23/G-24 policy).
4. `main` is always releasable; feature flags for incomplete UI.
5. Weekly: demo (recorded), SLO report, spec-drift review.

---

*This plan is versioned in-repo at `docs/plan/BUILD_PLAN.md`. Changes via PR + ADR where architectural.*
