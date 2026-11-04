> Source: normative specification — master architecture & product spec, imported 2026-11-05.
> Status: NORMATIVE. Changes require an ADR per the Engineering Constitution (§P.6).

# NexusPanel Master Architecture & Product Specification v2.0

**Status:** Authoritative Specification
**Supersedes:** PRD v1.0, Revision documents, Engineering Constitution v1.0 (this document *incorporates* the constitution as its preamble)
**Version:** 2.0
**Date:** November 2026
**Owner:** Founding Team

---

## Preamble — The Engineering Constitution (Binding)

This specification is governed by the constitution confirmed in the prior round. It is reproduced here as the binding preamble. Every subsequent section of this document is subordinate to it. If any conflict exists between a later section and the preamble, **the preamble wins**, and the later section is considered defective and must be amended.

### P.1 — The Thesis

> **NexusPanel is an independent hosting operating system: it manages an entire hosting company, from the physical server layer to the customer's individual mailbox — built with no artificial limitations, and shipped with the discipline of a platform you could bet a business on.**

### P.2 — The Ten Engineering Principles

1. No artificial product limitations.
2. No per-account licensing restrictions.
3. No dependence on cPanel, DirectAdmin or Plesk.
4. No reinventing mature infrastructure software unnecessarily.
5. No root access from the web application.
6. No feature locked exclusively to the GUI.
7. No architecture that prevents future multi-server expansion.
8. No compromising security for convenience.
9. No migration without verification and recovery planning.
10. No shortcuts that make future development harder.

### P.3 — The Four-Stage Delivery Model

| Stage | Meaning | Enforcement |
|---|---|---|
| **Architectural Core** | Interface/contract exists in v0.1; implementation may be minimal or empty | Locked at v0.1 review |
| **Delivery Core** | Fully functional in v1.0, meeting the completion definition (§P.5) | Locked at v1.0 GA review |
| **Delivery Expanded** | Ships after GA, in confidence | Locked at v1.x release |
| **Delivery Advanced** | Requires revenue maturity or scale | Explicitly deferred |

### P.4 — The Five Locked Resolutions

1. **OS:** Ubuntu Server 24.04 LTS only in v1.0; `OSAdapter` interface ships in v0.1. No OS is added to the supported matrix until its full integration test suite passes in CI.
2. **Installer:** One-line installer is the v0.1→v1.0 method. It must be idempotent, pre-flight checked, and resumable. Appliance image evaluated at v1.2.
3. **Reseller depth:** Data model supports unlimited nesting. Default policy caps at 2 levels; server admins can raise. No code ceiling, admin-controlled policy.
4. **Licensing:** No per-account charge in the panel software — permanently. Mechanism (per-server / open-core / feature tiers / managed service) decided at v0.4. No per-account assumption may be embedded in the code before that decision.
5. **Customer DB engines:** MySQL 8 + MariaDB 11 in v1.0. PostgreSQL-as-customer-engine is Delivery Expanded (v1.2). `DatabaseEngineAdapter` interface ships in v0.1.

### P.5 — Feature Completion Definition

A feature is complete only when all nine exist: (1) REST API endpoints; (2) UI screens with empty/loading/error/success states; (3) background jobs where non-instant; (4) permission model enforced at API layer; (5) audit logging through the privileged daemon; (6) error handling with actionable next steps; (7) operator + API documentation; (8) acceptance tests (unit, integration, E2E); (9) migration path if schema touched.

### P.6 — The No Silent Divergence Rule

Any change to a locked decision requires a written amendment with (a) reason, (b) migration path, (c) date and version. No "we just changed it in the code" path. Applies to founders equally.

### P.7 — The Additional Locked Rules

- **Identity model:** Users ≠ hosting accounts. Many-to-many with roles. Locked before v0.1.
- **Audit immutability:** Hash-chained audit records from v0.1. Tamper-evident.
- **Panel self-update:** The panel updates itself through the same configuration engine. No special-case shell script.
- **No half-built shipping:** A feature that cannot complete to §P.5 on its planned timeline moves to a later stage. It is not shipped under a different label.

---

## Section 1 — Product Definition and Positioning

### 1.1 What NexusPanel Is

NexusPanel is a self-hosted, API-first hosting control panel that provides cPanel/WHM-class functionality through a modern, AI-assisted interface, with a commercial philosophy that eliminates per-account licensing, an architecture designed for multi-server operation from day one, and a migration engine that makes cPanel/DirectAdmin/Plesk replacement a credible business decision.

### 1.2 What NexusPanel Is Not (v1.0)

- Not a Kubernetes operator. Runs on VMs and bare metal.
- Not a Windows hosting platform. Linux only.
- Not a billing engine. Integrates with existing billing.
- Not a page builder, CMS, or website editor.
- Not a managed service. It's software that hosting providers run.

### 1.3 Target Users

| Persona | Size | Primary Needs |
|---|---|---|
| Hosting Provider (SMB) | 1–10 staff, 50–2,000 accounts | Migration from cPanel, cost control, reliability |
| Reseller | 1–5 staff, 10–500 accounts | White-labeling, quota control, client mgmt |
| Agency / Developer | 2–50 staff, 5–200 sites | Staging, Git deploy, multi-site management |
| Server Admin | 1–3 staff | Observability, security, API automation |
| End Customer | Any | Simple file/email/DB management, SSL |

### 1.4 Competitive Position

| Competitor | Strength | Weakness NexusPanel Exploits |
|---|---|---|
| cPanel/WHM | Maturity, familiarity, ecosystem | Per-account tax, dated UX, single-server |
| DirectAdmin | Cheap, lightweight | Dated UX, narrow ecosystem, limited API |
| Plesk | Modern UX, extensions | Per-account tax, closed ecosystem, Windows-centric legacy |
| CloudPanel | Modern, free | No reseller, no email, narrow feature set |
| RunCloud | Modern, good UX | SaaS-only, no self-host, limited DNS/email |
| HestiaCP | Free, open-source | Dated UX, no isolation profiles, no API |

**Positioning statement:** *"cPanel's feature depth, CloudPanel's UX, RunCloud's API discipline — self-hosted, with no per-account tax, and a migration path that actually works."*

---

## Section 2 — Complete Feature Inventory and Parity Matrix

### 2.1 Feature Inventory by Module (18 modules)

Each module is annotated with its **delivery stage** per §P.3.

#### M1 — Super Admin Console (WHM Equivalent)
**Stage:** Delivery Core (core surface); Delivery Expanded (WHM parity depth)

**v1.0 functionality:**
- Account management (create/suspend/reactivate/terminate/restore)
- Package management (hosting plans, resource limits)
- Reseller management (create, permissions, inheritance)
- Server configuration (PHP, Nginx, mail, DNS)
- Service management (start/stop/restart/monitor)
- IP management (shared/dedicated IPv4/IPv6)
- SSL management (AutoSSL, cert admin)
- Backup policies and server-wide restores
- Transfers and migrations
- Security (firewall, WAF, malware, access controls)
- Updates (panel, OS, services)
- Logs (server-wide activity, diagnostics)
- Notification center

**Parity comparison:** Full WHM parity is a Delivery Expanded goal; v1.0 covers the operational core (~70% of WHM's daily-use surface).

#### M2 — Customer Hosting Panel
**Stage:** Delivery Core

Full surface for account holders: dashboard, sites, email, databases, files, SSL, backups, apps, DNS (if granted), cron, SSH keys, FTP, PHP management, logs, API tokens.

#### M3 — Reseller Management
**Stage:** Delivery Core (single-level default); Delivery Expanded (unlimited nesting)

Reseller creates/manages child accounts, defines packages, views usage. Branding (logo, colors, login page, email templates) configurable. Depth capped at 2 by default; server admin can raise per Decision 3.

#### M4 — Website and Domain Management
**Stage:** Delivery Core

Domains, subdomains, addon domains, aliases, redirects, document root, per-site PHP version + extensions + php.ini, Nginx/Apache config with validation and rollback, staging environments, HTTPS/HSTS, custom error pages, hotlink protection, directory password protection, MIME types, compression, caching.

#### M5 — DNS Management
**Stage:** Delivery Core

PowerDNS integration, authoritative zone management, all record types (A, AAAA, CNAME, MX, TXT, SRV, CAA, TLSA, NAPTR), DNSSEC, zone templates, zone import/export (BIND), secondary DNS, zone transfers (AXFR/IXFR), glue records, reverse DNS where upstream supports, propagation checker, DNS health diagnostics, auto-record-creation for sites/email.

#### M6 — Email Hosting Management
**Stage:** Delivery Core (core); Delivery Expanded (advanced)

Postfix + Dovecot + Roundcube. Mailboxes, aliases, catch-all, autoresponders, vacation messages, forwarders, mailing lists, quotas, spam filtering (SpamAssassin) with quarantine and scoring, greylisting, mail queue management, delivery tracking, DKIM/SPF/DMARC auto-generation + wizard, mail reputation monitoring, SMTP auth controls, webmail SSO, mailbox migration (imapsync), **SMTP relay mode** (SES/Mailgun/Postmark) as a first-class deployment option alongside self-hosted MTA.

**Important constitutional note:** The default for new installations is SMTP relay. Self-hosted MTA is fully supported but requires explicit opt-in. This is a *delivery default*, not a *capability limit*.

#### M7 — Database Management
**Stage:** Delivery Core (MySQL 8, MariaDB 11); Delivery Expanded (PostgreSQL-as-customer-engine at v1.2)

Create/delete databases and users, grants, quotas, phpMyAdmin/Adminer integration (SSO), automated backups with retention, import/export, connection string generator. `DatabaseEngineAdapter` interface from v0.1.

#### M8 — File and FTP/SFTP Management
**Stage:** Delivery Core

Upload/download, archive operations, permission editor with safety prompts, Monaco code editor (40+ languages), search (filename + grep), trash with 30-day retention, FTP/SFTP account management per site, SSH jailed accounts.

#### M9 — PHP and Runtime Management
**Stage:** Delivery Core

Multiple PHP versions (7.4–8.4) installed simultaneously, per-domain version, per-domain extensions, per-domain php.ini, PHP-FPM pool configuration, memory/execution limits, OPcache, error log management, PHP health checks. Clear distinction between **supported** (patched) and **legacy** (EOL but functional) versions, with warnings — never silent unpatched runtimes.

#### M10 — SSL and Security Management
**Stage:** Delivery Core

Let's Encrypt auto-issuance/renewal, wildcard support (DNS-01 + HTTP-01), firewall UI (UFW/nftables), Fail2ban with jail management, ModSecurity + OWASP CRS per-site toggle, ClamAV scanning (scheduled + on-demand), login protection, 2FA (TOTP + backup codes), session management, audit log viewer.

#### M11 — Backup and Disaster Recovery
**Stage:** Delivery Core

Full server, per-account, per-site, per-database backups. Destinations: local, S3-compatible (MinIO, AWS, B2), SFTP. GFS retention. One-click restore with preview. Encrypted backups (age). **Backup verification via automated test-restore.** Restore of files, databases, mailboxes, DNS zones, or full accounts.

#### M12 — Application Installer
**Stage:** Delivery Core (core apps); Delivery Expanded (breadth)

WordPress (WP-CLI-based), Joomla, Drupal, Laravel, Ghost, custom app deployment, Node.js/Python templates, Git webhook-triggered deploy, one-click clone/staging. All installers run as the account's user, not root.

#### M13 — Git and Developer Deployment
**Stage:** Delivery Core (basic); Delivery Expanded (full)

Connect GitHub/GitLab/Bitbucket, push-to-deploy, branch selection, deployment history, rollback, environment variables, staging environments linked to branches.

#### M14 — Server and Infrastructure Management
**Stage:** Delivery Core (single-server scope); Delivery Advanced (orchestrator)

Service management, monitoring (CPU/RAM/disk/IO/network), IP management, network config, kernel/system tuning, scheduled tasks, log center, server health checks, resource usage per account.

#### M15 — Migration Center
**Stage:** Delivery Core

Sources: cPanel (`cpmove-*` backups), DirectAdmin, Plesk. Full account, individual site, database-only, email-only. Source inspection, compatibility analysis, dry-run, data transfer, verification (checksum parity), cutover planning, rollback planning, migration reports, incremental sync. **Acceptance measured by throughput (MB/s) and integrity parity — never by wall-clock promise.**

#### M16 — API, CLI, and Automation
**Stage:** Delivery Core

OpenAPI 3.1-documented REST API covering 100% of GUI operations. Scoped API tokens with IP allowlisting and rate limits. Webhooks (event subscriptions with retry). CLI tool (`nexus`) mirroring common operations. Terraform provider is Delivery Advanced.

#### M17 — Billing and Client Management
**Stage:** Delivery Advanced (integration-first)

**Not built in-house in v1.x.** Ship WHMCS, Blesta, and HostBill connectors. Billing engine considered only post-revenue, and only if integration proves insufficient.

#### M18 — AI Assistant and Extension Marketplace
**Stage:** Delivery Expanded (AI diagnostics); Delivery Advanced (marketplace)

- **AI (v1.2+):** Prepared-failure-mode diagnostics (port conflict, PHP-FPM crash, disk full, DNS misconfig, SSL expiry), guided setup, log summarization, config explanation. **Read-first; execute-with-confirmation.** Provider-agnostic gateway. Rate-limited. Global kill switch.
- **Marketplace (v2.0+):** Extension SDK, permission-scoped extensions, sandboxing, review process, distribution.

### 2.2 Explicit Parity Matrix (cPanel/WHM vs. NexusPanel)

| cPanel/WHM Capability | NexusPanel Stage | Notes |
|---|---|---|
| Account create/suspend/terminate | Delivery Core | Plus restore, which cPanel lacks natively |
| Packages and quotas | Delivery Core | cgroup v2 enforcement (better than cPanel's rlimit) |
| Reseller creation | Delivery Core | Unlimited nesting supported; 2-level default |
| Domain/subdomain/addon management | Delivery Core | — |
| PHP version selection | Delivery Core | Superior: per-site extensions and ini from v1.0 |
| Email accounts + webmail | Delivery Core | Roundcube SSO |
| Email forwarders/aliases/autoresponders | Delivery Core | — |
| Spam filtering + quarantine | Delivery Core | SpamAssassin with UI |
| DKIM/SPF/DMARC | Delivery Core | Auto-gen + wizard (cPanel is weaker here) |
| Mailing lists | Delivery Core | Mailman |
| MySQL/MariaDB management | Delivery Core | phpMyAdmin SSO |
| PostgreSQL management | Delivery Expanded | v1.2 |
| File manager | Delivery Core | Monaco editor superior to cPanel's |
| FTP accounts | Delivery Core | Plus SFTP |
| Cron jobs | Delivery Core | — |
| SSH keys / jailed shell | Delivery Core | — |
| Let's Encrypt / AutoSSL | Delivery Core | Wildcard via DNS-01 |
| Firewall (CSF) equivalent | Delivery Core | UFW/nftables + Fail2ban |
| ModSecurity | Delivery Core | OWASP CRS with per-site toggle |
| ClamAV | Delivery Core | — |
| Backup / restore | Delivery Core | Superior: verified restore, S3, encryption |
| DNS zone editor | Delivery Core | PowerDNS + DNSSEC + AXFR/IXFR |
| DNSSEC | Delivery Core | cPanel supports via third-party; native here |
| WordPress Toolkit equivalent | Delivery Core | WP-CLI-based installer + staging |
| Git deployment | Delivery Core | cPanel has it via plugin; native here |
| Node.js/Python apps | Delivery Core | — |
| WHM server config | Delivery Core (~70%) | Expanded parity in v1.x |
| IP management | Delivery Core | — |
| SSL host config | Delivery Core | — |
| Account transfers | Delivery Core | Migration Center |
| cPanel-to-cPanel transfer | N/A | We do cPanel→NexusPanel |
| Plugin ecosystem | Delivery Advanced | Extension SDK in v0.1; marketplace v2.0 |
| Billing (WHMCS) | Integration | Delivery Advanced if ever built |
| Multi-server / clustering | Delivery Advanced | Architecture ready from v0.1 |
| Container isolation | Delivery Expanded | Enhanced profiles in v1.x |
| WHM API / UAPI parity | Delivery Core | Our own, superior documented API |

**Summary:** NexusPanel v1.0 reaches ~85% of cPanel/WHM daily-use parity, and ~40% of the cPanel ecosystem breadth (which is intentionally delivered through the extension SDK rather than built in-house).

---

## Section 3 — Architecture

### 3.1 High-Level System Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CLIENT LAYER                                   │
│  Next.js 15 Frontend (TypeScript · Tailwind · shadcn/ui · TanStack)    │
│  Responsive web · Command palette · Dark/light · Keyboard-first        │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │ HTTPS + WebSocket (TLS 1.3)
┌────────────────────────────────▼───────────────────────────────────────┐
│                          EDGE / REVERSE PROXY                           │
│  Nginx: TLS termination · rate limiting · WAF · static asset caching   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
┌────────────────────────────────▼───────────────────────────────────────┐
│                    CONTROL PLANE (NestJS)                               │
│  REST API · WebSocket · OpenAPI 3.1 · Auth (JWT + 2FA) · RBAC          │
│  Webhooks · Audit log writer · Job orchestration (BullMQ)              │
└──┬───────────────┬────────────────┬───────────────┬────────────────────┘
   │               │                │               │
┌──▼─────┐  ┌──────▼──────┐  ┌──────▼──────┐  ┌────▼──────────┐
│Postgres│  │Valkey+BullMQ│  │Prometheus   │  │ Audit store   │
│(panel) │  │(queues)     │  │(metrics)    │  │(hash-chained) │
└────────┘  └─────────────┘  └─────────────┘  └───────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  CONFIGURATION ENGINE   │
                    │  validate → apply →     │
                    │  health-check → rollback│
                    └────────────┬────────────┘
                                 │ Unix socket + mTLS
┌────────────────────────────────▼───────────────────────────────────────┐
│              PRIVILEGED NODE AGENT (Go)                                 │
│  Command allowlist · OSAdapter · cgroup v2 · systemd · file ops        │
│  Desired-state reconciliation · drift detection · rollback             │
└──┬─────────┬──────────┬───────────┬──────────┬──────────┬─────────────┘
   │         │          │           │          │          │
┌──▼───┐ ┌───▼────┐ ┌───▼────┐  ┌───▼────┐ ┌──▼─────┐ ┌──▼──────┐
│Nginx │ │PHP-FPM │ │Postfix │  │PowerDNS│ │MySQL/  │ │Filesystem│
│Apache│ │(multi- │ │Dovecot │  │(zones) │ │MariaDB │ │/home/... │
│      │ │ version)│ │Rcube   │  │        │ │        │ │          │
└──────┘ └────────┘ └────────┘  └────────┘ └────────┘ └──────────┘
   │
┌──▼────────────────────────────────────────────────────────────────────┐
│  PER-ACCOUNT ISOLATION LAYER                                          │
│  Linux user · cgroup v2 slice · PHP-FPM pool · namespace profile      │
│  (Standard / Enhanced / Container / Premium — delivery staged)        │
└───────────────────────────────────────────────────────────────────────┘
```

### 3.2 The Five Architectural Layers

**Layer 0 — Foundations (must exist before any feature):**
- Configuration Engine (validate/apply/health-check/rollback primitives)
- Privileged Node Agent (Go, Unix socket, mTLS, allowlist, audit)
- Hash-chained audit log
- OSAdapter interface (`UbuntuAdapter` only)
- DatabaseEngineAdapter interface (MySQL/MariaDB implementations)
- Isolation-profile interface (Standard implementation)

**Layer 1 — Control Plane:**
- NestJS API layer (REST + WebSocket)
- Identity & auth (users, sessions, 2FA, JWT, RBAC)
- PostgreSQL panel database (Prisma ORM)
- Valkey + BullMQ (jobs, queues)
- Prometheus metrics endpoint

**Layer 2 — Domain Modules:**
- 16 Delivery Core modules (M1–M16 minus M17/M18)
- Each owns its API endpoints, UI routes, background jobs, permissions, audit events

**Layer 3 — Node Agent:**
- Go binary, single static build
- Talks to control plane only (no direct DB access)
- All system mutations pass through here
- Drift detection on a schedule
- Emits metrics to Prometheus, audit events to control plane

**Layer 4 — Managed Services:**
- Nginx/Apache, PHP-FPM, Postfix/Dovecot, PowerDNS, MySQL/MariaDB, Dovecot, Fail2ban, ModSecurity, ClamAV, certbot/lego
- Configured exclusively by the node agent; never hand-edited (drift detected and reconciled)

### 3.3 The Configuration Engine (Critical Subsystem)

This is the constitutional heart of NexusPanel. Every configuration change — customer site, email, DNS, panel itself — flows through the same pipeline.

```
Panel State (PostgreSQL)
        │
        ▼
   ┌─────────────────┐
   │ Template Engine │  ← per-module template library
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Render Draft    │  ← not applied
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Validator       │  ← schema + semantic + conflict detection
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Health-check    │  ← pre-flight: does this config parse? conflict?
   │ (dry run)       │
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Apply (atomic)  │  ← write to staging path, symlink swap
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Service reload  │  ← graceful, per-service
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Health-check    │  ← post-flight: is service healthy?
   └────────┬────────┘
            ▼
      ┌─────┴─────┐
      │ Healthy?  │
      └─────┬─────┘
       yes  │  no
      ┌─────▼─────┐        ┌──────────────────┐
      │ Commit    │        │ Automatic rollback│
      │ + audit   │        │ + alert + audit   │
      └───────────┘        └──────────────────┘
```

Every apply is:
- **Versioned** (git-like history per config file)
- **Attributed** (who, when, why — via audit log)
- **Reversible** (rollback to any prior version)
- **Idempotent** (re-apply of same state is a no-op)
- **Observable** (metrics for apply duration, success rate, rollbacks)

**Constitutional rule:** No code path may write to a managed service's configuration except through this engine. The Go agent enforces this by refusing config-direct writes without an engine-signed transaction token.

### 3.4 The Privileged Node Agent

**Language:** Go 1.23+
**Communication:** Unix domain socket at `/run/nexuspanel/agent.sock` + mTLS; commands are signed by the control plane using a per-installation Ed25519 key.

**Responsibilities:**
- Create/delete/modify Linux users and groups
- Create/manage filesystem directories with correct ownership and permissions
- Apply cgroup v2 slices with quotas
- Generate, validate, apply, and reload service configurations (via Configuration Engine)
- Manage systemd services (start/stop/restart/status)
- Issue and install TLS certificates
- Manage Postfix/Dovecot/PowerDNS mail/DNS state
- Manage per-account resource accounting (read cgroups, report usage)
- Execute filesystem operations with strict path confinement
- Report drift (detected divergence between desired and actual state)

**Explicitly NOT allowed:**
- Execute arbitrary shell commands from control plane
- Open TCP ports other than its metrics endpoint
- Bypass the configuration engine
- Read the control plane's database
- Access credentials for external services

**Command allowlist:** The agent implements a fixed set of typed operations. Every operation is a named method with typed parameters. There is no `exec()` primitive.

**Audit:** Every agent action emits a structured audit event, hash-chained, written to both local WAL (for durability during control-plane outages) and forwarded to the control plane.

### 3.5 The Multi-Server Architecture (Architectural Core, Not Delivery Core)

Even though v1.0 deploys as a single server, the architecture treats the control plane and node agent as separate services from day one. The contract between them is defined in v0.1.

**Node types (planned):**
- **Control node** — runs NestJS API, PostgreSQL, Valkey, the frontend (may be colocated in v1.0)
- **Hosting node** — runs the Go agent + managed web/PHP/database services
- **DNS node** — runs PowerDNS (can be primary or secondary)
- **Mail node** — runs Postfix/Dovecot (can be clustered later)
- **Backup node** — runs backup storage target
- **Monitoring node** — Prometheus + long-term storage (ClickHouse)

In v1.0, all node types are colocated on one server. The agent's registration protocol, the control plane's node table, and the per-module "which node does this run on" routing all exist from v0.1. Adding a second server in v1.5 requires no re-architecture — only enablement.

**The contract:** `control ↔ agent` is a versioned, mTLS-signed API. Adding new node types extends the contract; it does not rewrite it.

### 3.6 The Identity Model (Locked)

```
┌──────────┐         ┌──────────────────────────┐        ┌──────────────────┐
│  users   │◄───────►│ user_hosting_account_    │◄──────►│ hosting_accounts │
│          │   many-  │ access                   │  many-  │                  │
│ (person) │   to-    │ (role: owner/admin/member│   to-   │ (Linux user,     │
│          │   many   │  /readonly)              │   many  │  cgroup, quota)  │
└──────────┘         └──────────────────────────┘        └──────────────────┘
                                                                  │
                                                                  ▼
                                                          ┌──────────────────┐
                                                          │ resellers        │
                                                          │ (parent_id,      │
                                                          │  depth)          │
                                                          └──────────────────┘
```

**Rules:**
- A `user` is a login identity (email, password, 2FA, sessions).
- A `hosting_account` is a provisioned resource (Linux user, filesystem, quotas).
- Access is mediated through `user_hosting_account_access` with roles.
- A `reseller` is a `hosting_account` granted reseller capability; `parent_reseller_id` supports nesting up to policy depth.
- One user may have access to many hosting accounts. One hosting account may have many users.
- API tokens, sessions, and audit log entries attach to `users`, not to `hosting_accounts`.

**Consequence:** An agency logs in once, sees a cross-account dashboard, and manages 30 clients without 30 sessions. This is a meaningful UX difference from cPanel and is reflected in every screen and endpoint from v0.1.

### 3.7 The Audit Store (Locked)

Every privileged action writes to an audit store with hash-chaining:

```
audit_entry {
  id: uuid
  timestamp: timestamptz
  actor_user_id: uuid
  actor_ip: inet
  hosting_account_id: uuid (nullable)
  node_id: uuid
  operation: string
  parameters: jsonb (redacted secrets)
  outcome: enum (success|failure|partial)
  prior_hash: sha256
  this_hash: sha256(prior_hash || canonical_entry)
}
```

**Guarantees:**
- Tamper-evident: verification walks the chain and detects any insertion, deletion, or modification.
- Durable: written to PostgreSQL WAL first, then materialized. Agent has local WAL for control-plane outage durability.
- Retained: default 1 year; configurable; exportable.

**Future:** If compliance requires WORM, the chain is preserved and the storage backend swaps to an immutable target. The contract (hash chain, verification endpoint) is fixed from v0.1.

### 3.8 The Isolation Layer (Architectural Core)

Interface defined in v0.1; Standard profile implemented in v1.0.

**Profiles:**

| Profile | Implementation | Stage |
|---|---|---|
| **Standard** | Linux user per account · cgroup v2 slice (CPU/RAM/IO/IOPS/process count/entry processes) · PHP-FPM pool per site · filesystem perms · process restrictions | Delivery Core |
| **Enhanced** | + Namespaces (mount, PID, network where viable) · restricted mounts · syscall filtering (seccomp) · stronger process separation | Delivery Expanded |
| **Container** | Full container per account · CPU/memory limits · isolated networking · isolated storage | Delivery Expanded |
| **Premium** | Dedicated VM or microVM per account | Delivery Advanced |

**The interface (`IsolationProvider`):**
- `provision(account)`
- `apply_limits(account, limits)`
- `read_usage(account)`
- `suspend(account)`
- `resume(account)`
- `destroy(account)`

Every account is assigned an isolation profile at creation. Server admins choose default profiles per package. Migration between profiles is supported (Standard → Enhanced → Container requires agent work; Container → Standard requires teardown).

### 3.9 The Extension SDK (Architectural Core)

Interface defined in v0.1; marketplace is Delivery Advanced.

**Extension model:**
- Extensions are **out-of-process services** (not plugins injected into the control plane).
- They communicate with the control plane via the extension protocol (an extension of the node-agent contract, in reverse — the extension registers with the control plane).
- Extensions declare **permission scopes** (e.g., `sites:read`, `email:write`, `dns:read`, `backups:write`).
- The control plane enforces scope at every API boundary; extensions cannot exceed declared scopes.
- Extensions have their own storage namespace; they cannot read panel tables directly.
- Extensions are installed/uninstalled by the server admin only.
- Extensions can register UI widgets through a defined component contract (React lazy-loaded modules, sandboxed in iframe where untrusted).

**Why out-of-process:** Out-of-process extensions cannot crash the panel, cannot bypass audit, cannot escape their scope. The cost is a slightly higher extension-development ceiling — acceptable for the security guarantees.

**SDK deliverables (v0.1 interface; v1.0 working SDK):**
- Extension protocol specification
- Node.js and Python extension client libraries
- Example extension (a simple "server info widget")
- Extension manifest schema
- Permission scope reference

### 3.10 OS Adapter (Architectural Core)

Interface defined in v0.1; `UbuntuAdapter` is the only implementation in v1.0.

**The interface:**
- `install_package(name, version)`
- `remove_package(name)`
- `manage_service(name, action)`
- `read_service_status(name)`
- `apply_firewall_rule(rule)`
- `apply_cgroup_limits(account, limits)`
- `php_package_source(version)`
- `filesystem_layout(name)`
- `selinux_or_apparmor_mode()`
- `expected_unit_names()`

Adding Debian 13 in v1.2 = implementing `DebianAdapter` + passing the full integration test suite in CI. No core rewrite.

---

## Section 4 — Database Schema (Foundational Entities)

Full schema is defined in a separate document (`nexuspanel-schema-v2.0.sql`), but the foundational entities are specified here for architectural review.

### 4.1 Entity Groups

**Identity & Access:**
- `users` — login identity
- `sessions` — active sessions per user
- `two_factor_secrets` — TOTP secrets (encrypted)
- `api_tokens` — scoped tokens
- `user_hosting_account_access` — M:N + role
- `roles` — owner/admin/member/readonly (extensible)
- `permissions` — granular capability list per role

**Hosting:**
- `hosting_accounts` — Linux user, filesystem root, isolation profile, package
- `packages` — hosting plans (quotas, features)
- `resellers` — hosting account + reseller flag, parent_id, depth
- `domains` — top-level domains owned by accounts
- `subdomains`, `aliases`, `redirects` — site topology
- `document_roots` — file paths per site
- `php_configurations` — per-site PHP version, extensions, ini overrides
- `nginx_vhosts` — generated config + version history

**Email:**
- `mail_domains` — domains with mail enabled
- `mailboxes` — email accounts
- `aliases` — forwarding rules
- `autoresponders`, `vacation_messages`
- `mailing_lists`
- `dns_records` (MX, DKIM, SPF, DMARC live in DNS)

**DNS:**
- `dns_zones` — PowerDNS-backed zones
- `dns_records` — all record types
- `dns_zone_templates`
- `dnssec_keys` — encrypted

**Database (customer-facing):**
- `database_engines` — MySQL, MariaDB, PostgreSQL (availability per account)
- `databases` — customer databases
- `database_users`
- `database_grants`

**Files:**
- `file_accounts` — FTP/SFTP accounts
- `ssh_keys`
- `trash_entries` — trashed files with retention

**SSL & Security:**
- `certificates` — Let's Encrypt + manual, per site
- `firewall_rules`
- `fail2ban_jails`
- `modsecurity_policies`
- `login_attempts`

**Backups:**
- `backup_jobs` — scheduled job definitions
- `backup_runs` — execution history
- `backup_destinations` — S3/SFTP/local
- `restore_previews`

**Applications & Deployment:**
- `installed_applications` — WP, Joomla, etc.
- `git_deployments` — repos, branches, history
- `staging_environments`

**Infrastructure:**
- `nodes` — control, hosting, dns, mail, backup, monitoring
- `node_agents` — registered agents per node
- `services` — managed services with health status
- `resource_usage` — time-series (Prometheus primary; Postgres is summary)

**Jobs & Events:**
- `jobs` — BullMQ job records (id, type, status, params, result)
- `webhooks` — endpoint registrations
- `webhook_deliveries` — attempt history
- `notifications` — in-panel notification records

**Configuration & Audit:**
- `config_versions` — every applied config, versioned
- `config_transactions` — engine apply operations
- `audit_entries` — hash-chained
- `drift_events` — detected divergence between desired and actual

**Migration:**
- `migration_jobs` — source platform, target account, progress
- `migration_mappings` — source→target entity mappings
- `migration_reports`

**Extensions:**
- `extensions` — installed extensions, scopes, version
- `extension_permissions` — granted scopes

### 4.2 Schema Principles

- **Every table has `id` (uuid v7 for time-ordered inserts), `created_at`, `updated_at`.** No exceptions.
- **Soft delete** for all entities users might recover (domains, mailboxes, databases, files). Hard delete only for audit and logs.
- **Every foreign key is indexed.** No exceptions.
- **Every table has an `owner_id`** (user or hosting account) where logically applicable, for row-level filtering in the API layer.
- **No secrets in plaintext.** All secrets encrypted at rest using age with keys managed by the control plane.
- **Timezone discipline:** `timestamptz` everywhere. UTC storage.
- **Enum discipline:** every enum has a documented migration path if values are added.

---

## Section 5 — Backend Module Architecture (NestJS)

### 5.1 Module Structure

```
apps/api/src/
├── main.ts
├── app.module.ts
├── modules/
│   ├── auth/                    # JWT, sessions, 2FA, API tokens
│   ├── identity/                # users, access, roles, permissions
│   ├── hosting/                 # hosting accounts, packages, resellers
│   ├── sites/                   # domains, subdomains, aliases, redirects
│   ├── php/                     # PHP versions, pools, extensions
│   ├── webserver/               # Nginx/Apache config generation
│   ├── email/                   # mailboxes, aliases, dkim, queue
│   ├── dns/                     # zones, records, dnssec
│   ├── database/                # MySQL/MariaDB/Postgres customer DBs
│   ├── files/                   # file ops, FTP/SFTP, SSH keys
│   ├── ssl/                     # certificates, ACME
│   ├── security/                # firewall, fail2ban, modsec, clamav
│   ├── backup/                  # jobs, destinations, restore
│   ├── apps/                    # installers (WP, etc.), Git deploy
│   ├── nodes/                   # node registry, agent communication
│   ├── config-engine/           # Configuration Engine primitives
│   ├── audit/                   # hash-chained audit log writer + verifier
│   ├── jobs/                    # BullMQ job registry
│   ├── webhooks/                # event → webhook delivery
│   ├── notifications/           # in-panel notifications
│   ├── migrations/              # Migration Center
│   ├── extensions/              # Extension SDK host
│   └── ai/                      # AI gateway (Delivery Expanded)
├── common/
│   ├── guards/                  # auth, permission, rate limit
│   ├── interceptors/            # logging, audit, error
│   ├── pipes/                   # validation (zod)
│   ├── filters/                 # error responses
│   └── decorators/
├── infra/
│   ├── prisma/                  # ORM client
│   ├── valkey/                  # Valkey client + BullMQ
│   ├── agent-client/            # Go agent communication
│   ├── prometheus/              # metrics
│   └── storage/                 # S3/SFTP clients
└── config/                      # runtime config
```

### 5.2 Module Contract

Every domain module must include:

1. `*.controller.ts` — REST endpoints (OpenAPI annotated)
2. `*.service.ts` — business logic
3. `*.module.ts` — NestJS module definition
4. `*.permissions.ts` — permission definitions registered with RBAC
5. `*.events.ts` — domain events emitted (consumed by webhooks and audit)
6. `*.jobs.ts` — background job definitions (registered with BullMQ)
7. `*.agent-commands.ts` — typed agent operations this module can request
8. `dto/` — request/response DTOs (zod-validated)
9. `tests/` — unit + integration + E2E

### 5.3 Request Lifecycle

```
HTTP request
  → Nginx (TLS, rate limit, WAF)
  → NestJS
  → AuthGuard (JWT verification)
  → PermissionGuard (scope check)
  → RateLimitGuard (per-token, per-IP)
  → ValidationPipe (zod DTO)
  → Controller
  → Service
      → [if privileged] Configuration Engine
          → validate → Agent (mTLS signed command)
          → health check
          → apply / rollback
      → AuditLog.write (hash-chained)
      → EventEmitter.emit (domain event)
  → Response
  → Webhook delivery enqueued (async)
```

### 5.4 API-First Enforcement (Constitutional)

**Enforced at CI:** Every UI screen that mutates state must have a corresponding documented API endpoint. The build fails if any `apps/web` route calls a panel-internal RPC that is not exposed via `/api/v1/*`.

**Enforced at build time:** OpenAPI spec is generated from controllers. Any endpoint without a corresponding controller method (i.e., implemented outside the documented API) fails the build.

**Enforced at review:** Every PR touching `apps/web` must reference the API endpoint it consumes. No exceptions.

---

## Section 6 — Frontend Route and Navigation Architecture (Next.js)

### 6.1 Three Surfaces

| Surface | Route prefix | Primary users |
|---|---|---|
| **Customer Panel** | `/` | Hosting account users |
| **Reseller Console** | `/reseller/*` | Resellers |
| **Super Admin Console** | `/admin/*` | Server admins |

Cross-account context switcher at the top of every surface (agency UX). Command palette (`Cmd/Ctrl+K`) navigates across all surfaces the user has access to.

### 6.2 Customer Panel Routes

```
/                                Dashboard
/sites                           Sites list
/sites/[domain]                  Site detail
  /sites/[domain]/files          File manager
  /sites/[domain]/php            PHP config
  /sites/[domain]/ssl            SSL
  /sites/[domain]/logs           Logs
  /sites/[domain]/staging        Staging env
  /sites/[domain]/git            Git deployment
/email                           Email domains
/email/[domain]                  Mailboxes, aliases, forwarders
/email/[domain]/[mailbox]        Mailbox detail
/databases                       Databases list
/databases/[db]                  DB detail, users, phpMyAdmin
/dns                             Zones (if granted)
/dns/[zone]                      Zone editor
/files                           File manager (cross-site)
/ssl                             Certificates
/backups                         Backups and restore
/apps                            Installer marketplace
/apps/[app]                      App instance detail
/cron                            Cron jobs
/ssh                             SSH keys, jailed shell
/ftp                             FTP/SFTP accounts
/logs                            Cross-site log search
/api-tokens                      API token management
/profile                         User profile, 2FA, sessions
/notifications                   Notification center
/help                            Help, AI assistant entry
```

### 6.3 Reseller Console Routes

```
/reseller                        Reseller dashboard
/reseller/accounts               Child accounts
/reseller/accounts/new           Create child account
/reseller/packages               Reseller's package definitions
/reseller/branding               White-label config
/reseller/usage                  Usage reports
/reseller/api-tokens             Reseller API tokens
```

### 6.4 Super Admin Console Routes

```
/admin                           Server dashboard
/admin/accounts                  All hosting accounts
/admin/packages                  Server-wide packages
/admin/resellers                 Reseller management
/admin/nodes                     Node registry (v1.0: single node)
/admin/services                  Service management
/admin/php                       PHP versions
/admin/webserver                 Nginx/Apache config
/admin/email                     Mail server config
/admin/dns                       DNS server config
/admin/ips                       IP management
/admin/ssl                       AutoSSL config
/admin/backups                   Backup policies
/admin/security                  Firewall, Fail2ban, ModSec, ClamAV
/admin/updates                   Panel + OS updates
/admin/extensions                Extension SDK
/admin/audit                     Audit log viewer
/admin/logs                      Server logs
/admin/migrations                Migration Center
/admin/settings                  Server settings
/admin/users                     User management
```

### 6.5 Frontend Architecture Principles

- **Server components by default**; client components for interactivity.
- **TanStack Query** for all API state; no raw `fetch` in components.
- **Zustand** for local UI state only (no server state).
- **shadcn/ui** as the component library; no custom primitives without a review.
- **Design tokens** centralized in `tailwind.config.ts`; no ad-hoc colors.
- **Command palette** (`Cmd+K`) is non-negotiable — it's how power users navigate.
- **Empty/loading/error/success** states are mandatory on every screen (per §P.5).
- **Optimistic updates** where safe; server confirms asynchronously.
- **WebSocket** for live updates (job progress, service status, real-time metrics).
- **Accessibility:** WCAG 2.1 AA — tested with axe in CI on every route.

### 6.6 Design Language

- **Linear/Stripe-inspired.** Dense information, restrained color, generous whitespace.
- **Dark mode first**, light mode parity.
- **Typography:** Inter (UI), JetBrains Mono (code).
- **Color:** neutral base with a single accent (configurable per reseller branding).
- **Motion:** subtle, purposeful, never decorative.

---

## Section 7 — Privileged Go Agent Architecture

*(Interface contract defined here; full implementation reference is a separate document.)*

### 7.1 Binary and Deployment

- Single static Go binary per node type (v1.0: `nexuspanel-agent` for hosting node; DNS and mail agent modules compile into the same binary in v1.0, with separate binaries in v1.x).
- Installed as a systemd service: `nexuspanel-agent.service`.
- Runs as a dedicated system user (`nexusagent`) with a tight capability set.
- Unix socket at `/run/nexuspanel/agent.sock`, mode 0600, owned by `nexusagent:nexusagent`.

### 7.2 Command Protocol

**Transport:** Unix socket + mTLS. Every command is signed by the control plane's Ed25519 key.

**Message format:** JSON-RPC 2.0 with a typed `method` field.

**Command example:**
```json
{
  "jsonrpc": "2.0",
  "id": "req_01H...",
  "method": "account.create",
  "params": {
    "username": "acct_00042",
    "package_id": "pkg_standard",
    "isolation_profile": "standard",
    "quotas": { "cpu": 200, "mem": 1024, "disk": 10240, "processes": 50 }
  },
  "signature": "base64(ed25519_signature)",
  "issued_at": "2026-11-15T12:00:00Z",
  "expires_at": "2026-11-15T12:01:00Z"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "req_01H...",
  "result": { "account_id": "...", "linux_uid": 10042, "status": "created" },
  "audit_entry": { "prior_hash": "...", "this_hash": "..." }
}
```

### 7.3 Command Allowlist

Every operation is a named method. There is **no `exec()` primitive**. The complete method list is enumerated in the agent specification (separate document) and versioned with the control plane.

**Categories:**
- `account.*` — create, modify, suspend, resume, delete, quotas
- `isolation.*` — provision, apply_limits, read_usage
- `filesystem.*` — mkdir, chown, chmod, quota, trash
- `service.*` — start, stop, restart, status, reload
- `config.*` — apply (via configuration engine), rollback, drift_check
- `php.*` — install version, manage pool
- `nginx.*` — apply vhost, reload, test
- `mail.*` — create mailbox, apply postfix config, reload
- `dns.*` — create zone, apply record set, reload
- `database.*` — create db, create user, grant, revoke
- `ssl.*` — issue, renew, install, revoke
- `firewall.*` — add rule, remove rule, list
- `fail2ban.*` — ban, unban, jail status
- `backup.*` — snapshot, restore (with explicit path confinement)
- `system.*` — service ops, health, metrics

### 7.4 Desired-State Reconciliation

The agent runs a periodic drift check (default every 15 minutes, configurable) that compares:
- Generated configuration files on disk vs. the configuration engine's record of what should be there
- Service state vs. expected state
- Filesystem ownership vs. panel state
- cgroup limits vs. package quotas

Drift is reported to the control plane as a `drift_event` and surfaced in the admin UI. **The agent does not silently overwrite drift** — it reports, and the admin chooses reconcile or investigate. This is the constitutional rule from §P.7.

### 7.5 Local WAL for Resilience

If the control plane is unavailable, the agent:
- Continues to serve read operations (service status, filesystem reads).
- Queues audit events in a local WAL.
- Rejects write operations with a clear error ("control plane unreachable; panel actions unavailable; existing sites continue serving").
- On control-plane restoration, drains WAL and reconciles state.

This preserves customer site uptime even if the panel itself is down — a genuine reliability advantage over cPanel.

---

## Section 8 — Server Provisioning and Isolation Architecture

### 8.1 Provisioning Flow (v1.0, single-server)

```
1. Admin installs NexusPanel (one-line installer)
   ├── Pre-flight: OS check (Ubuntu 24.04), resources (min 2GB RAM, 20GB disk)
   ├── Install control plane: Node.js runtime, NestJS build, PostgreSQL, Valkey
   ├── Install node agent: Go binary, systemd service
   ├── Install managed services: Nginx, PHP-FPM, Postfix, Dovecot, PowerDNS, MySQL/MariaDB
   ├── Initialize PostgreSQL schema, seed admin user
   ├── Generate mTLS keys for control plane ↔ agent
   └── Start services, health check, print admin URL + initial credentials

2. Admin logs in, completes onboarding
   ├── Configure server hostname, IPs
   ├── Set default PHP version, default isolation profile
   ├── Configure DNS (primary/secondary or self-hosted)
   ├── Configure email (SMTP relay or self-hosted — default is relay)
   ├── Add S3 backup destination (or local fallback)
   └── Create first package, first reseller (optional), first account
```

### 8.2 Per-Account Provisioning

When an account is created:

```
1. Validate package quotas and current capacity
2. Control plane → Agent: account.create
3. Agent:
   ├── Create Linux user (uid from range, no login shell by default)
   ├── Create /home/<user>/ with locked-down perms
   ├── Create cgroup v2 slice: /sys/fs/cgroup/nexus/<user>/
   │   ├── cpu.max, memory.max, io.max, pids.max
   ├── Create PHP-FPM pool
   ├── Create systemd user slice
   ├── Register with isolation provider (Standard profile)
4. Control plane:
   ├── Insert hosting_accounts row
   ├── Insert user_hosting_account_access row
   ├── Insert audit entry
   ├── Emit account.created event → webhooks
5. Account is ready for sites, mailboxes, databases
```

**Timing target:** account ready for site creation in < 30 seconds (P95).

### 8.3 Site Provisioning

```
1. User: create site (domain, PHP version, etc.)
2. Control plane:
   ├── Validate domain, DNS ownership (optional), SSL eligibility
   ├── Render Nginx vhost template
   ├── Validate config (dry-run)
3. Control plane → Agent: config.apply (nginx vhost)
4. Agent:
   ├── Write to staging path, symlink swap
   ├── nginx -t (validate)
   ├── systemctl reload nginx
   ├── Health check: HTTP HEAD to site
5. If healthy: commit + audit + emit event
   If unhealthy: rollback + alert + audit failure
6. Enqueue: SSL issuance (ACME HTTP-01 or DNS-01)
7. Enqueue: DNS record creation (if DNS is managed)
8. Enqueue: default mail configuration (if mail enabled)
```

**Timing target:** site reachable with valid SSL in < 60 seconds (P95, excluding DNS propagation).

### 8.4 Isolation Profiles (Implementation Stages)

| Profile | v1.0 | v1.x | v2.x |
|---|---|---|---|
| Standard | ✅ Full | — | — |
| Enhanced | Interface only | ✅ Full | — |
| Container | Interface only | ✅ Full | — |
| Premium (VM) | Interface only | — | ✅ Full |

Each profile is a `IsolationProvider` implementation. The agent selects the provider per account based on `hosting_accounts.isolation_profile`.

### 8.5 Resource Management Engine

**Tracked metrics per account (from cgroup v2 + PHP-FPM + filesystem):**
- CPU (usage in nanoseconds, throttled time)
- Memory (current, peak, limit)
- Disk (usage, inodes, quotas)
- IO (read/write bytes, IOPS)
- Process count (pids.current vs. pids.max)
- Entry processes (PHP-FPM pool)
- Bandwidth (per-site via Nginx log parser)

**Enforcement:**
- Hard limits (cgroup v2) — process is killed or throttled when exceeded
- Soft limits (alerts) — admin notification at 80%, 90%, 100%
- Suspension (account-level) — if a package over-quota policy is set to suspend, agent suspends on breach

**Reporting:**
- Real-time via WebSocket (dashboard widgets)
- Time-series via Prometheus (queryable, graphable)
- Summary tables in PostgreSQL (per-account monthly, per-package)

---

## Section 9 — API Specifications

### 9.1 API Design Principles

- **RESTful** with resource-oriented URLs.
- **Versioned:** `/api/v1/...`. Breaking changes require `/api/v2/`.
- **JSON** request/response. Errors follow RFC 7807 (Problem Details).
- **Authentication:** Bearer JWT (web) or Bearer API token (programmatic). 2FA enforced for admin roles.
- **Authorization:** RBAC + ownership check at the API layer, never the UI.
- **Idempotency:** All non-GET endpoints accept `Idempotency-Key` header. Same key + same body within 24h returns the original response.
- **Pagination:** Cursor-based (`?cursor=...&limit=50`). No offset pagination for primary collections.
- **Filtering:** Query parameters (`?status=active&package=pkg_standard`). Documented per endpoint.
- **Sorting:** `?sort=created_at&order=desc`. Whitelist per endpoint.
- **Rate limiting:** Per-token and per-IP; documented per endpoint; returns `Retry-After`.
- **OpenAPI 3.1** spec generated from controllers, published at `/api/docs`.
- **Webhooks:** Event subscriptions with `url`, `secret`, `events[]`. Signed with HMAC-SHA256. Retries with exponential backoff.

### 9.2 API Surface Overview

| Group | Endpoints | Notes |
|---|---|---|
| `/api/v1/auth` | login, refresh, logout, 2fa setup/verify, sessions | JWT + refresh tokens |
| `/api/v1/users` | CRUD, sessions, 2FA | Self-service + admin |
| `/api/v1/tokens` | create, list, revoke | Scoped API tokens |
| `/api/v1/accounts` | CRUD, suspend, resume, restore | Hosting accounts |
| `/api/v1/packages` | CRUD | Hosting plans |
| `/api/v1/resellers` | CRUD, nesting, permissions | — |
| `/api/v1/domains` | CRUD | Sites |
| `/api/v1/domains/{d}/subdomains` | CRUD | — |
| `/api/v1/domains/{d}/redirects` | CRUD | — |
| `/api/v1/domains/{d}/php` | get, put | Per-site PHP config |
| `/api/v1/domains/{d}/ssl` | issue, renew, revoke, list | — |
| `/api/v1/domains/{d}/logs` | query | Nginx logs |
| `/api/v1/domains/{d}/staging` | create, list, destroy | — |
| `/api/v1/domains/{d}/git` | connect, deploy, history, rollback | — |
| `/api/v1/mail/domains` | CRUD | — |
| `/api/v1/mail/domains/{d}/mailboxes` | CRUD, quota, usage | — |
| `/api/v1/mail/domains/{d}/aliases` | CRUD | — |
| `/api/v1/mail/domains/{d}/forwarders` | CRUD | — |
| `/api/v1/mail/queue` | list, flush, retry | — |
| `/api/v1/dns/zones` | CRUD, import, export | — |
| `/api/v1/dns/zones/{z}/records` | CRUD | All record types |
| `/api/v1/dns/zones/{z}/dnssec` | enable, disable, list keys | — |
| `/api/v1/databases` | CRUD | MySQL/MariaDB (v1.0) |
| `/api/v1/databases/{db}/users` | CRUD | — |
| `/api/v1/files` | list, upload, download, move, delete, chmod | Path-scoped |
| `/api/v1/files/search` | query | Name + content |
| `/api/v1/ftp` | CRUD | FTP/SFTP accounts |
| `/api/v1/ssh/keys` | CRUD | SSH keys |
| `/api/v1/ssl/certificates` | CRUD, issue, renew | Cross-domain |
| `/api/v1/security/firewall` | CRUD rules | — |
| `/api/v1/security/fail2ban` | list, ban, unban | — |
| `/api/v1/backups` | CRUD jobs, run, list runs | — |
| `/api/v1/backups/{run}/restore` | preview, execute | — |
| `/api/v1/apps` | list, install, uninstall | — |
| `/api/v1/apps/{id}` | status, update, staging | — |
| `/api/v1/nodes` | list, register, health | Admin only |
| `/api/v1/services` | list, start, stop, restart, status | Admin only |
| `/api/v1/audit` | query, verify | Admin only |
| `/api/v1/migrations` | create, dry-run, execute, verify | — |
| `/api/v1/webhooks` | CRUD | — |
| `/api/v1/notifications` | list, mark read | — |
| `/api/v1/extensions` | list, install, uninstall | Admin only |

*(Full endpoint specification with request/response schemas: separate OpenAPI document.)*

### 9.3 CLI (`nexus`)

Commands mirror the API 1:1 for common operations:
```
nexus auth login
nexus accounts list / create / suspend / restore
nexus sites list / create / delete
nexus dns zones list / records add
nexus mail boxes create / list
nexus backups run / restore
nexus services status / restart
nexus audit tail
nexus migrations cpanel import --source=... --dry-run
```

CLI uses the same API tokens; no special-case backend.

### 9.4 Webhooks

Event catalog (namespaced):
```
account.created / suspended / resumed / deleted
site.created / deployed / ssl_issued / ssl_expiring
mailbox.created / quota_exceeded
dns.zone_created / record_changed / dnssec_enabled
database.created / deleted
backup.completed / failed / restore_completed
service.down / up
firewall.rule_added
security.login_failed_threshold
migration.completed / failed
node.drift_detected
```

Signed with HMAC-SHA256 using the webhook's secret. Retries: 1m, 5m, 30m, 2h, 12h; max 5 attempts. Dead-letter after final failure, queryable via API.

---

## Section 10 — Queue and Background Job Specifications

### 10.1 Job Framework

- **BullMQ** on Valkey.
- **Queues per domain** (isolation of critical path): `critical` (auth, session), `sites`, `mail`, `dns`, `db`, `backups`, `ssl`, `migrations`, `webhooks`, `notifications`.
- **Concurrency per queue:** configured per queue; `backups` and `migrations` are low-concurrency (they're heavy), `webhooks` high-concurrency.
- **Retry policies per job type:** exponential backoff with jitter. Non-retryable jobs (validation failures) fail immediately.
- **Dead-letter queue** for exhausted retries; queryable and replayable via admin UI.

### 10.2 Long-Running Jobs

The following are always enqueued, never run in request path:

| Job | Typical duration | Queue | Notes |
|---|---|---|---|
| SSL issuance | 10s–2m | `ssl` | ACME challenge |
| Site provisioning | 5s–30s | `sites` | Nginx apply + reload |
| DNS zone creation | 2s–10s | `dns` | PowerDNS apply |
| DNS propagation check | 30s–5m | `dns` | External DNS queries |
| Backup | minutes–hours | `backups` | Depends on size |
| Backup verification | minutes | `backups` | Test-restore |
| Full account restore | minutes–hours | `backups` | — |
| cPanel migration | minutes–hours | `migrations` | Depends on account size |
| App install (WordPress) | 30s–2m | `sites` | WP-CLI |
| OS/panel update | 5m–30m | `critical` | Staged, rollbackable |
| Mail queue flush | 2s–1m | `mail` | Postfix |
| Malware scan | minutes–hours | `security` | ClamAV |
| Webhook delivery | ms–seconds | `webhooks` | Retried |

### 10.3 Job Contract

Every job must:
- Have a typed payload (zod schema).
- Be idempotent OR carry an explicit idempotency key.
- Emit progress events (consumed by UI via WebSocket).
- Emit a completion/failure event (consumed by webhooks).
- Write an audit entry if it mutates privileged state.
- Handle graceful cancellation (BullMQ job cancellation + agent mid-flight cancel where supported).
- Have a documented failure mode (what does the system do if this fails?).

### 10.4 The Panel Self-Update Job (Constitutional)

Per §P.7, panel updates run through the Configuration Engine. The update job:

1. Downloads signed update manifest and artifacts.
2. Verifies signature against the installation's trusted key.
3. Runs pre-flight: current version compatibility, disk space, service health.
4. Applies database migrations to a shadow schema (validates first).
5. Applies code update atomically (new directory + symlink swap).
6. Runs post-update health checks (panel reachable, key services healthy, schema consistent).
7. **On any failure: rollback to prior code + prior schema + prior config.**
8. Writes audit entry.
9. Emits `panel.updated` event → notification to admins.

**Constitutional rule:** A panel update that fails health checks leaves the panel in its exact prior state. Never "mostly updated." Never "half-migrated."

---

## Section 11 — Security and Permission Models

### 11.1 Threat Model (Summary)

**Assets:**
- Customer data (files, databases, email)
- Customer credentials
- Panel admin credentials
- TLS private keys
- DKIM private keys
- Backups (contain everything above)

**Adversaries:**
- Malicious authenticated customer (lateral movement, privilege escalation)
- Compromised customer account (abuse of resources, spam, malware)
- External attacker (panel vulnerabilities, credential stuffing)
- Insider (malicious or careless admin)
- Supply chain (dependency compromise)

**Out of scope for v1.0:**
- Physical attacks
- Hypervisor-level attacks (below our layer)
- State-level actors

### 11.2 Authentication

- **Password:** Argon2id, minimum 12 chars, complexity optional but encouraged.
- **2FA:** TOTP (RFC 6238) with backup codes. Enforceable per role by server admin.
- **Sessions:** Short-lived JWT (15 min) + refresh token (7 days, rotating). Refresh token bound to device fingerprint.
- **API tokens:** Opaque tokens (not JWT), hashed at rest (SHA-256), scoped, expirable, IP-allowlistable.
- **SSO:** None in v1.0 (Delivery Expanded: SAML/OIDC).

### 11.3 Authorization (RBAC)

**Roles (default):**
- **Server Admin** — full panel access
- **Reseller** — control over own child accounts, own packages, own branding
- **Account Owner** — full control of own hosting account
- **Account Admin** — same as owner minus account deletion
- **Account Member** — configurable per-account; can be read-only or scoped
- **Account Read-Only** — view everything, mutate nothing

**Permission model:** A permission is a string `resource:action` (e.g., `site:create`, `mailbox:delete`, `backup:restore`, `firewall:manage`). Roles map to permission sets. Custom roles supported (Delivery Expanded).

**Enforcement:** Every controller method is annotated with required permissions. A `PermissionGuard` rejects requests before business logic. **Never rely on UI to hide unauthorized actions.**

### 11.4 Isolation (Defense in Depth)

Layer 1: **Network** — each account has no listening services except those explicitly provisioned (web on 80/443 via shared Nginx, mail on standard ports).

Layer 2: **Filesystem** — `/home/<user>/` owned by user, mode 0700 at root. Other accounts cannot read.

Layer 3: **Process** — Linux user isolation. No `sudo` to other users. No capability escalation.

Layer 4: **cgroups** — CPU/RAM/IO/process limits enforce resource fairness.

Layer 5: **PHP-FPM** — per-site pool, `open_basedir` set to site root + `/tmp/<user>`.

Layer 6: **Agent confinement** — the agent runs as `nexusagent`, cannot access `/home/*` except via controlled operations with explicit user context.

Layer 7: **Enhanced (Delivery Expanded)** — namespaces, seccomp, network isolation.

### 11.5 Secrets Management

- **At rest:** All secrets encrypted with age; keys derived from a master key stored in `/etc/nexuspanel/keys/` (mode 0400, root-owned, never leaves the server).
- **In transit:** TLS 1.3 everywhere. mTLS between control plane and agent.
- **In memory:** Secrets zeroed after use where feasible. Never logged.
- **In DB:** Secrets stored encrypted; decrypted only in the service layer, never sent to the UI.
- **In logs:** Redaction rule — any field named `password`, `secret`, `key`, `token`, `private` is auto-redacted by the logging interceptor.

### 11.6 Configuration Engine Security

The engine is a *trust boundary*. Its guarantees:
- **No arbitrary code execution.** Templates are rendered from a fixed set of validated variables.
- **No shell interpolation.** Never `String.format("nginx -t %s", path)`. Always `exec.Command("nginx", "-t", path)`.
- **Path confinement.** All file operations restricted to `/etc/nexuspanel/`, `/etc/nginx/`, `/etc/php/`, `/etc/postfix/`, `/etc/dovecot/`, `/etc/powerdns/`, `/home/`, and explicit temp dirs. No `..` escapes.
- **Configuration injection is prevented** by schema validation of all template variables (e.g., a domain name must match a strict regex; a path must resolve within its site root).

### 11.7 Audit and Compliance

- Every privileged action → hash-chained audit entry (§3.7).
- Audit verification endpoint: `POST /api/v1/audit/verify` (admin-only).
- Retention: 1 year default; configurable; exportable to S3.
- Compliance postures supported (not certified in v1.0): SOC 2 readiness, GDPR (data export + deletion flows in Delivery Expanded).

### 11.8 Vulnerability Management

- Dependency scanning in CI (Snyk, Dependabot, or equivalent).
- SAST in CI (Semgrep).
- SBOM generated per release (SPDX).
- Signed releases (minisign or cosign).
- Public disclosure policy: 90-day coordinated disclosure.
- Bug bounty program (Delivery Expanded — target v1.1).

---

## Section 12 — Migration Architecture

### 12.1 Design Principles

- **Never destructive at the source.** Migration reads from source backups or a copied source — never from the live source server.
- **Always dry-run first.** A dry-run reports every element that will migrate, every element that cannot, and why.
- **Always verifiable.** Post-migration, checksums are compared for files, row counts for databases, message counts for mailboxes, record counts for DNS zones.
- **Always reversible.** Migration creates a target account that can be destroyed if verification fails. Source remains untouched.
- **Never promise wall-clock time.** Acceptance is throughput and integrity, not speed.

### 12.2 Migration Flow

```
1. Admin or reseller initiates: source=cPanel, backup file / source URL
2. Migration analysis:
   ├── Parse backup format (cpmove-*.tar.gz or direct rsync)
   ├── Identify entities: domains, subdomains, databases, mailboxes,
   │   forwarders, DNS zones, cron, SSL certs, files
   ├── Compare with target capabilities
   ├── Generate compatibility report: what will migrate, what won't, why
3. Dry-run:
   ├── Simulate provisioning: create temp account in a sandbox
   ├── Report estimated size, duration, entity counts
   ├── Report any incompatibilities (e.g., unsupported PHP version)
4. Admin approves
5. Execute:
   ├── Create target account (if not existing)
   ├── Stream files → target
   ├── Create databases, import SQL
   ├── Create mailboxes, imapsync mail
   ├── Create DNS zones, import records
   ├── Restore SSL certs or re-issue via ACME
   ├── Create cron jobs
   ├── Create FTP/SSH accounts
6. Verification:
   ├── File checksum parity
   ├── DB row count parity
   ├── Mailbox message count parity
   ├── DNS record count parity
   ├── HTTP reachability test
   ├── SSL validity test
7. Cutover planning:
   ├── DNS change plan (TTL lowering, change window, rollback plan)
   ├── Email MX change plan
   ├── Warning: email must be paused or synced incrementally
8. Post-cutover:
   ├── Incremental sync window (optional, for email)
   ├── Report generation: what migrated, what didn't, manual steps
```

### 12.3 Source Platform Adapters

Each source platform has an adapter implementing a common interface:

```
interface MigrationSourceAdapter {
  inspect(source): SourceInventory
  plan(inventory, target): MigrationPlan
  extract(entity, destination): void
  verify(entity, target, checksum): VerificationResult
}
```

**v1.0 adapters:**
- `CPanelAdapter` — parses `cpmove-<user>.tar.gz`; also supports WHM account backup.
- `DirectAdminAdapter` — parses DA backup tarball.
- `PleskAdapter` — parses Plesk backup (XML + tarball).

**v1.x adapters:**
- `NexusPanelAdapter` — NexusPanel-to-NexusPanel (for multi-node moves).

### 12.4 What Migrates (cPanel → NexusPanel)

| cPanel Element | Migration Behavior |
|---|---|
| Home directory files | Full copy, checksum verified |
| Databases (MySQL) | Dump + import, row count verified |
| Database users & grants | Mapped to target (passwords preserved if extractable) |
| Email accounts | Mailbox created; messages imapsync'd |
| Email forwarders | Migrated |
| Email autoresponders | Migrated |
| Mailing lists | Migrated (Mailman) |
| DNS zones | Imported if PowerDNS is enabled; exported as BIND otherwise |
| SSL certs | Re-issued via Let's Encrypt if possible; imported otherwise |
| Cron jobs | Migrated (paths adjusted) |
| FTP accounts | Migrated (passwords reset — cannot extract) |
| PHP version | Mapped to nearest supported version; report if mismatch |
| PHP extensions | Mapped; report if unavailable |
| SSL/TLS settings | Re-generated |
| .htaccess rules | Preserved; partially translated to Nginx (report untranslatable) |
| Spam filter rules | Migrated (SpamAssassin) |
| MX records | Migrated as DNS records |
| Subdomains | Migrated as subdomains |
| Addon domains | Migrated |
| Parked domains | Migrated as aliases |
| IPv6 assignments | Migrated if target supports |

### 12.5 What Cannot Migrate

Explicitly reported, not silently dropped:
- cPanel-specific configuration (CSF rules, cPanel-specific plugins)
- cPanel's proprietary mail filters (migrated as best-effort)
- Application-level caches (regenerated)
- Some `.htaccess` rewrite rules (Nginx translation may fail; reported)
- Custom Perl modules installed by user
- Some older PHP versions (EOL, not supported)

### 12.6 Migration Metrics (Acceptance)

- **Throughput:** measured in MB/s file transfer + messages/min mail sync; recorded per migration.
- **Integrity:** checksum parity pass rate = 100% for files; row count parity = 100% for DBs; message count parity = 100% for mailboxes (after incremental sync completes).
- **Coverage:** % of source entities migrated; reported.
- **Duration:** recorded, not promised.

---

## Section 13 — Deployment and Installation Architecture

### 13.1 Supported Environments (v1.0)

- **OS:** Ubuntu Server 24.04 LTS (x86_64, arm64)
- **Minimum:** 2 vCPU, 4 GB RAM, 20 GB SSD, 1 IPv4
- **Recommended:** 4 vCPU, 8 GB RAM, 100 GB SSD, 1 IPv4 + /64 IPv6
- **Network:** Public IP required; DNS resolution functional; port 25 outbound recommended (for self-hosted mail) but not required (SMTP relay mode)
- **Virtualization:** KVM, VMware, Hyper-V, bare metal. LXC/OpenVZ supported with caveats (cgroup v2 nesting).

### 13.2 One-Line Installer

```
curl -fsSL https://get.nexuspanel.io | sudo bash
```

**Pre-flight checks (fail-fast, no partial installs):**
1. OS version, architecture
2. Available RAM, disk, inodes
3. Port conflicts (80, 443, 3306, 5432, 25, 587, 993, 53)
4. Existing Nginx/Apache/MySQL/Postfix (conflict handling: warn + offer to stop, or abort)
5. Network connectivity (DNS, HTTPS to update server)
6. Systemd presence, cgroup v2 availability
7. User is root (or sudo capability)

**Install stages (each stage resumable):**
1. System packages + repositories
2. Node.js runtime
3. PostgreSQL, Valkey
4. Nginx, PHP-FPM (multiple versions)
5. Postfix, Dovecot, Roundcube
6. PowerDNS (optional in v1.0)
7. MySQL/MariaDB (customer DB engine)
8. Panel core (NestJS build, static assets)
9. Node agent (Go binary)
10. Frontend (Next.js build served by Nginx)
11. Database schema init + seed
12. TLS cert for panel (Let's Encrypt or self-signed)
13. Agent registration
14. Initial admin user + password (printed once)
15. Health checks, final report

**Idempotency:** Re-running the installer on a partially-installed system completes the install. Re-running on a fully-installed system validates and reports "already installed" without touching anything.

**Resumability:** If a stage fails, the installer exits with the specific failure and instructions. Re-running picks up from the failed stage.

### 13.3 Installation Logs and Diagnostics

- Installer writes structured logs to `/var/log/nexuspanel/install-*.log`.
- On failure, a diagnostic bundle is offered (tar.gz of logs, system info, config).
- Support can be given a single command to produce the bundle.

### 13.4 Configuration at Install Time

Optionally non-interactive via environment variables or a config file:
```
NEXUSPANEL_HOSTNAME=panel.example.com
NEXUSPANEL_ADMIN_EMAIL=admin@example.com
NEXUSPANEL_ADMIN_PASSWORD=<auto-generated-if-unset>
NEXUSPANEL_TIMEZONE=UTC
NEXUSPANEL_MAIL_MODE=relay  # or self-hosted
NEXUSPANEL_DB_ENGINE=mysql  # customer DB engine
```

Non-interactive install supports fully automated provisioning (Ansible, Terraform, cloud-init).

### 13.5 Upgrades

**Panel upgrade command:** `nexus update` (CLI) or "Update" button in admin UI.
- Runs the self-update job (§10.4).
- Staged updates: major versions have a "stability" channel (stable, beta, nightly). Stable default.
- Rollback: `nexus rollback` reverts to prior version, prior schema, prior config.

**Service upgrades:** OS packages, PHP versions, and managed services update through the panel's own maintenance jobs. Admins can schedule them.

### 13.6 Backup of the Panel Itself

The panel backs itself up:
- PostgreSQL dump (encrypted)
- Configuration engine version history
- Agent's local state
- Extensions and their state

Backups go to the same destinations as customer backups. Restoring a panel from backup is a documented runbook.

---

## Section 14 — Testing and Release Strategy

### 14.1 Test Pyramid

**Unit tests** (per module, ≥ 80% line coverage on business logic):
- Service layer logic
- Configuration rendering
- Validation rules
- Permission checks

**Integration tests** (against a real VM per supported OS):
- Provision a VM (Ubuntu 24.04)
- Run installer
- Provision accounts, sites, mailboxes, DBs, DNS zones
- Verify: HTTP reachability, SSL, DNS resolution, mail delivery (to a local sink), DB access
- Test failure modes: kill services mid-operation, verify rollback

**End-to-end tests** (Playwright, against a real panel):
- Critical user journeys: signup→account→site→SSL→deploy→backup→restore
- Admin journeys: account creation, package management, migration
- Reseller journeys: child account creation, branding

**Security tests:**
- SAST (Semgrep) per PR
- DAST (OWASP ZAP) per release candidate
- Dependency scanning (Snyk) daily
- Penetration test: external, per major release

**Migration tests:**
- Fixture cPanel backups (small, medium, large; various configurations)
- Migration to fresh NexusPanel, verify integrity
- Idempotency test: re-run migration, verify no duplication

**Fault injection:**
- Simulate control plane outage; verify agent WAL drains
- Simulate agent crash; verify control plane recovers gracefully
- Simulate configuration invalid state; verify rollback
- Simulate disk full; verify behavior is safe (panel becomes read-only, sites continue)

### 14.2 CI/CD Pipeline

```
Push → Lint → TypeCheck → Unit tests → Build
     → Spin up Ubuntu VM → Integration tests
     → Spin up second VM (v1.x: Debian) → Integration tests
     → E2E tests (Playwright)
     → SAST, dependency scan
     → SBOM generation
     → Artifact signing
     → Release candidate (staging channel)
```

Release gates:
- **Stable channel:** all tests pass on all supported OS; no high-severity findings; two consecutive nightly builds pass.
- **Beta channel:** all tests pass; medium-severity findings documented.
- **Nightly:** tests pass on current commit.

### 14.3 Feature Flags

New features are merged behind feature flags. Flags are:
- Scoped per-account or server-wide
- Auditable (who enabled what, when)
- Removable (a feature that ships without a code cleanup task to remove the flag is a failed review)

### 14.4 Release Versioning

- **SemVer:** `MAJOR.MINOR.PATCH`.
- **MAJOR:** breaking API or schema changes; migration path required.
- **MINOR:** new features, backwards-compatible.
- **PATCH:** bug fixes, security patches.
- **Security patch SLA:** critical CVEs patched within 72h; high within 7 days.

### 14.5 Documentation as a Release Gate

Every release includes:
- Updated OpenAPI spec
- Updated operator docs (install, upgrade, backup, restore, migrate)
- Updated changelog
- Migration guide for MINOR/MAJOR versions

A release without docs is not a release.

---

## Section 15 — Commercial Licensing and Extension Architecture

### 15.1 Licensing Philosophy (Locked)

**No per-account tax. Ever.**

### 15.2 Licensing Mechanism (Open Until v0.4)

Candidates evaluated at v0.4:
1. **Per-server flat license** — most likely; consistent with constitution.
2. **Open core** — free core panel; paid enterprise modules (reseller, migration, multi-node, extended support).
3. **Per-server base + feature tiers** — base panel free, advanced modules paid.
4. **Managed service** — NexusPanel is not sold as software; it's the panel of a hosting provider we operate.

**Constraint (locked):** No per-account assumption may be embedded in the code before v0.4. No license count column, no activation flags, no per-account gating in the UI.

### 15.3 Extension Model (Architectural Core)

Defined in §3.9. Commercial rules:
- Extensions are **free to develop**; SDK is open.
- Extensions are **permission-scoped**; no extension has implicit full access.
- Extensions are **reviewable** (Delivery Expanded: a marketplace with review process).
- Extensions are **sandboxed** (out-of-process; cannot read panel DB directly).
- Extensions can be **paid or free**; marketplace supports both (Delivery Advanced).
- Extensions are **versioned**; the SDK has SemVer; incompatible extensions are disabled with clear reporting.

### 15.4 White-Labeling (Reseller)

Configurable per reseller:
- Logo (SVG)
- Primary color (hex)
- Login page background
- Panel title (text)
- Support email
- Custom domain (points to panel via DNS CNAME; panel issues TLS via ACME)

**Not white-labelable in v1.0** (Delivery Expanded):
- Custom email sending domain (panel emails come from `nexuspanel.io` — reseller-branded emails in v1.x)
- Custom panel path
- Custom API base URL
- Removal of "Powered by NexusPanel" footer (this is a deliberate v1.0 constraint — open-core if licensing mechanism demands it)

### 15.5 Support Model

- **Free tier:** community forum + documentation (if open-core).
- **Paid tier:** email support with SLA (if commercial).
- **Enterprise:** dedicated support, migration assistance, custom SLAs (if commercial).

Support model is part of the licensing decision at v0.4.

---

## Section 16 — Roadmap and Delivery Milestones

### 16.1 Phase Structure

| Phase | Duration (est.) | Scope | Exit Criteria |
|---|---|---|---|
| **v0.1 — Foundations** | 10 weeks | Config engine primitives, Go agent (command allowlist, audit, WAL), identity model, PostgreSQL schema, NestJS skeleton, Next.js shell, `OSAdapter` interface, `DatabaseEngineAdapter` interface, `IsolationProvider` interface (Standard), auth + 2FA, API skeleton + OpenAPI, one-line installer | Admin can install, log in, see an empty dashboard. Agent responds to a health ping. |
| **v0.2 — Sites + SSL + Files** | 10 weeks | Domains, subdomains, PHP-FPM per site, Nginx vhost generation, Let's Encrypt, file manager (upload/download/edit), FTP/SFTP accounts, per-site logs | User can create a site, install WordPress manually, get SSL, upload/edit files. |
| **v0.3 — Email + DNS + DB** | 12 weeks | Postfix/Dovecot/Roundcube, DKIM/SPF/DMARC, forwarding, quotas, SMTP relay mode; PowerDNS zones, records, DNSSEC; MySQL/MariaDB provisioning, phpMyAdmin SSO | User can receive email, manage DNS, create databases. |
| **v0.4 — Resellers + Packages + Backups** | 10 weeks | Packages, cgroup v2 quotas, reseller accounts (2-level default), backup engine (local + S3, encrypted, verified restore), app installer (WordPress), Git deploy (basic) | Reseller can create child account with quotas. Backup/restore tested end-to-end. |
| **v0.5 — Migration + AI Diagnostics + WHM surface** | 10 weeks | Migration Center (cPanel, DA, Plesk), dry-run, verification; AI diagnostics on prepared failure modes; WHM admin console depth; server monitoring, service management | cPanel account migrated with integrity verification. AI answers "why is site down" for 5 known failure modes. |
| **v1.0 — GA** | 6 weeks | Security audit (external pentest), docs finalization, install hardening, support tooling, release signing, SBOM, legal | External pentest clean. Documentation complete. First 10 beta hosts migrated. |
| **Total to v1.0** | **~58 weeks** | | |

### 16.2 Post-GA Roadmap

| Version | Scope |
|---|---|
| **v1.1** | Bug fixes, Debian 13 (if test matrix passes), container isolation profile, PostgreSQL as customer engine |
| **v1.2** | Enhanced isolation, AI expansion (more failure modes), reseller unlimited nesting enablement |
| **v1.5** | Multi-server orchestration (control plane + node agent split), DNS node, mail node |
| **v2.0** | Extension Marketplace, Premium isolation (VM), full multi-OS matrix |
| **v2.x** | Orchestrator depth (placement, capacity, live migration), billing engine (only if commercially justified) |

### 16.3 Team Composition (Recommended)

For the timeline above:
- 1 × Tech Lead / Architect
- 2 × Backend engineers (NestJS + Go)
- 2 × Frontend engineers (Next.js + design)
- 1 × DevOps / SRE (installer, testing, CI)
- 1 × Security engineer (part-time, ramping up at v0.5)
- 1 × Technical writer (starting v0.4)
- 1 × Product/Designer (ongoing)

Total: 8–9 people. Under-resourced teams should extend timeline, not compress scope.

---

## Section 17 — Open Questions and Deferred Decisions

### 17.1 Decision Pending (per constitution)

| # | Question | Decide By |
|---|---|---|
| 1 | Licensing mechanism (per-server / open core / feature tiers / managed) | v0.4 |
| 2 | AI provider (BYO-key default; bundled as premium add-on?) | v0.5 |
| 3 | Whether self-hosted mail becomes default-opt-in in a future version | v1.5 (data-driven) |
| 4 | Support tier SLA details (if commercial) | v1.0 |
| 5 | Marketplace revenue share (if marketplace is built) | v2.0 |

### 17.2 Deferred to Post-v2.0

- Kubernetes operator
- Windows hosting
- Managed billing engine
- Mobile native apps
- Autonomous AI remediation
- Multi-datacenter orchestration
- Edge DNS

---

## Section 18 — Appendix: Glossary and References

### 18.1 Glossary

| Term | Definition |
|---|---|
| **Hosting account** | A provisioned resource (Linux user, filesystem, quotas, services). Distinct from a user. |
| **User** | A login identity. May access multiple hosting accounts. |
| **Reseller** | A hosting account with reseller capability and child accounts. |
| **Delivery Core** | Feature stage: fully functional in v1.0, meets §P.5 completion definition. |
| **Architectural Core** | Feature stage: interface/contract exists in v0.1; implementation may be minimal. |
| **Configuration Engine** | The centralized system that renders, validates, applies, health-checks, and rolls back all service configurations. |
| **Node Agent** | The privileged Go binary on each node that executes system operations on behalf of the control plane. |
| **Drift** | Divergence between the configuration engine's desired state and the actual state on disk. |
| **Audit chain** | The hash-chained sequence of privileged actions; tamper-evident by construction. |
| **Isolation profile** | The per-account isolation strategy: Standard, Enhanced, Container, Premium. |

### 18.2 Reference Documents

- `nexuspanel-schema-v2.0.sql` — Full PostgreSQL schema
- `nexuspanel-agent-spec-v1.0.md` — Complete agent command allowlist and protocol
- `nexuspanel-openapi-v2.0.yaml` — Generated OpenAPI 3.1 specification
- `nexuspanel-installer-spec-v1.0.md` — Installer stage-by-stage specification
- `nexuspanel-migration-spec-v1.0.md` — Migration Center detailed specification
- `nexuspanel-extension-sdk-v1.0.md` — Extension protocol and SDK reference
- `nexuspanel-security-model-v1.0.md` — Detailed threat model and security controls

### 18.3 Amendments

Any change to a locked decision in this document requires a written amendment recorded in the appendix with:
- The decision being amended
- The reason
- The migration path for anything already built
- Date and version

**No silent changes.**

---

## Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-10 | Founding Team | Initial PRD |
| 2.0 | 2026-11 | Founding Team | Master Architecture & Product Specification; incorporates Engineering Constitution v1.0; resolves all five open decisions; establishes four-stage delivery model; adds identity model, audit chain, config engine, agent spec, extension SDK, and full 18-section architecture |

---

**Next action:** Review of this document, followed by issuance of the companion specification documents listed in §18.2. No code is written until this document is signed off and the schema document is reviewed.

**Sign-off:**

- [ ] Founding Engineer
- [ ] Founding Engineer
- [ ] (Additional stakeholders as applicable)
