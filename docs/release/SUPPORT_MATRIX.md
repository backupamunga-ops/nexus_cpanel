# NexusPanel v1.0 Support Matrix

**Status:** published at P7 · honest per the D-11 rule — a cell says what is
**verified**, not what is hoped. "Dev rig" = the repeatable docker/postgres
bring-up of `docs/runbooks/m0-fresh-vm.md` + CI; "live VM" = the pending
acceptance run (AS-BUILT §3).

## Host operating system

| OS | Arch | Status |
|---|---|---|
| Ubuntu 22.04 LTS | amd64 | dev-rig verified — live-VM acceptance pending |
| Ubuntu 24.04 LTS | amd64 | expected (same package set) — untested |
| Debian 12 | amd64 | expected (runbook prerequisite) — untested |
| any distro with systemd + PostgreSQL 16 + Node ≥ 20 | amd64 | best-effort — installer not published yet |

The agent requires Linux: cgroup v2 slices, nftables, ModSecurity/ClamAV
integration, Dovecot/Postfix maps. There is no non-Linux agent, by design.

## Runtime dependencies

| Component | Version | Notes |
|---|---|---|
| PostgreSQL | 16 | 38-table canonical DDL (ADR-0004); uuidv7 via pgcrypto-style helpers |
| Node.js | ≥ 20 (CI pins 22) | control plane + web, npm workspaces |
| Go | ≥ 1.23 (go.mod toolchain) | build-time only |
| Valkey / Redis | 8.x | dev compose ships Valkey 8; queue work is BullMQ-shaped (ADR-0018) |

## Panel feature surfaces (narrowed from browsers)

| Browser | Web UI | Notes |
|---|---|---|
| Chrome/Chromium current-1 | dev-rig verified (Playwright rig, 32-shot set) | primary target |
| Firefox current-1 | dev-rig verified (rig includes firefox runs in CI where available) | — |
| Safari 17+ | expected — WebKit quirks unverified | no known blockers; CSS uses standard tokens |
| Mobile browsers | responsive sidebar + tables; not acceptance-tested | usable, not promised |

## Agent-managed subsystems (live-VM acceptance pending per AS-BUILT §3)

| Subsystem | Verified on dev rig | Needs live VM |
|---|---|---|
| isolation.provision (cgroup v2 slices) | yes (fakes + real slice on rig) | sustained multi-account load |
| DNS (PowerDNS API + DNSSEC) | fakes | real PowerDNS + real resolver |
| Mail (postfix/dovecot maps, DKIM) | fakes + config renders | real delivery, relay provider |
| Databases (MariaDB adapter) | socket-level on rig | live MariaDB 11 round trip |
| Backups (tar.gz + sftp/s3, age) | fakes + local transport | real S3/SFTP round trip |
| Firewall/fail2ban (nftables) | transactional apply on rig | live VM apply + self-lockout guard |
| WAF (ModSecurity) + ClamAV | config renders, scan fakes | CRS fires detect-vs-block on staged payload |
| Apps / push-to-deploy | WP-CLI fakes + git hooks on rig | fresh-account WP install < 5 min |
| Migrations (cpmove) | parser + verify on rig | real cPanel export import |
| Extensions SDK | in-process + example extension E2E on rig | third-party extension review |

## Extension SDK compatibility promise (SDK spec §12)

An extension built against SDK v1.0 keeps working across all NexusPanel
v1.x (MINOR/PATCH) and the first MAJOR with a deprecation window of ≥ 2
MINOR releases + migration guide. Panel contract version: `1.0.0`.
