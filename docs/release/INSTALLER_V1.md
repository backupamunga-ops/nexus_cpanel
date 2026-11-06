# NexusPanel Installer Spec v1.0 (finalized)

**Status:** NORMATIVE for the v1.0 `install.sh` · finalized at P7 from the proven v0.1 path
**Provenance:** every step below is grounded in `docs/runbooks/m0-fresh-vm.md` — the runbook
that has actually brought the stack up repeatedly on fresh VMs (dev rig). The installer
SCRIPT itself lands with the live-VM acceptance run; this document is its contract.

## 1. What the installer must produce

A single-node Ubuntu 22.04+/Debian 12 host running:

| Component | How it runs | Privilege |
|---|---|---|
| PostgreSQL ≥ 16 | systemd service (native package, not docker, on production hosts) — PGDG 16 where the codename is published, distro-archive PostgreSQL otherwise (Ubuntu 26.04 ships 18; live-VM acceptance finding) | `postgres` |
| Control plane (`apps/control-plane`) | `systemd/nexuspanel-api.service` | unprivileged `nexuspanel` user |
| Web (`apps/web`) | `systemd/nexuspanel-web.service` — Next.js server, loopback-only (**amended by ADR-0022**: the app's same-origin `/api/v1` rewrites need the Node server, so it is not a static export) | unprivileged `nexuspanel` user |
| Agent (`apps/agent`) | `systemd/nexuspanel-agent.service` | root — the ONLY root-adjacent process, explicit capability set, no auto-root (infra/README, agent spec §2) |

Non-negotiables carried from infra/README.md:

- The control plane NEVER runs as root and never touches the OS directly —
  every privileged operation is a signed Ed25519 command to the agent.
- Master key generated at install time, `/etc/nexuspanel/keys/` root-owned
  and read-only to the `nexuspanel` service group (dir 0750, secrets 0640
  root:nexuspanel — never service-writable; the live-VM run corrected the
  original '0400 root', which the unprivileged control-plane unit cannot
  read), offline backup prompt at the end of install (security model §3.1).
- Self-update accepts ONLY cosign-signed release manifests (C19/C20, §6 below).

## 2. Steps (each maps 1:1 to a proven runbook step)

1. **Packages** — install PostgreSQL (16 from PGDG when the codename is
   published; the distro archive otherwise, floor ≥ 16 — the canonical DDL and
   Prisma use nothing 16-specific), node ≥ 20 (NodeSource), go ≥ 1.23
   (toolchain only for the agent build), git. `docker` is NOT required on
   production hosts; the dev compose file is a dev-rig convenience.
2. **Database** — create role `nexuspanel` + database `nexuspanel`; apply
   `specs/nexuspanel-schema-v2.0.sql` (the canonical DDL, ADR-0004). The
   runbook's docker initdb mount does the same thing on the dev rig.
3. **Keys** — `npm run keys:generate --workspace apps/control-plane`
   produces `control-plane-signing.key` (0640 root:nexuspanel),
   `control-plane-signing.pub`
   (raw base64 → agent), and the SecretBox master key (`secrets.key`,
   `CP_SECRETS_KEY_PATH`, 0640 root:nexuspanel). Existing keys are never
   overwritten — the installer must fail loudly if keys exist rather than
   rotate them silently.
4. **Environment** — write `/etc/nexuspanel/nexuspanel.env` (mode 0640,
   root:root, sourced by both units) with exactly the runbook's names:
   `DATABASE_URL`, `CP_SIGNING_KEY_PATH`, `CP_SECRETS_KEY_PATH`,
   `AUTH_JWT_SECRET` (≥ 32 random chars — sessions survive restarts),
   `AGENT_SOCKET_PATH`, `GLOBAL_PREFIX=api/v1`, `PORT=3000`.
   `DEV_ADMIN_EMAIL` / `DEV_ADMIN_PASSWORD` are dev-rig ONLY — the installer
   creates the first super admin interactively instead (one-time prompt,
   written nowhere).
5. **Build** — `npm ci` at root; `npm run build --workspaces --if-present`;
   `make agent` (go build). Artifacts owned by the service users.
6. **Units** — install the two systemd units from `infra/systemd/`, enable
   + start agent first, then control plane; health gate:
   `curl -fsS http://localhost:3000/api/v1/health` must return 200 before
   the installer reports success.
7. **Verification** — the installer ends by creating the first admin,
   logging in via the API once, and printing the audit-chain head so the
   operator can re-verify it later (`POST /audit/verify`).

## 3. Hardening baseline (C10)

- UFW/nftables: 22 (or the operator's SSH port), 80/443; the API port is
  localhost-only unless a reverse proxy is configured.
- PostgreSQL listens on the unix socket + localhost only.
- `fail2ban` sshd jail enabled (the panel's own fail2ban module manages the
  panel's jails, not the host's sshd).
- Automatic security updates (`unattended-upgrades`) on.
- The agent's systemd unit restricts everything per agent spec §2; the
  control plane unit sets `NoNewPrivileges=true`, `ProtectSystem=strict`,
  `ProtectHome=yes`, `PrivateTmp=yes`.

## 4. Uninstall

`nexuspanel-uninstall` stops both units, removes them, and leaves the
database and `/etc/nexuspanel/keys/` in place with an explicit prompt —
the operator decides what data to destroy, never the installer.

## 5. Upgrade

Stop control plane → apply new DDL migrations (forward-only, ADR-0004) →
rebuild → restart → health gate → audit-chain verify. The agent is only
restarted when its binary changed; its WAL drains on reconnect (runbook §5).

## 6. Self-update contract (C19/C20)

Releases are cosign-signed (see `.github/workflows/release.yml`): the SBOM
and each artifact are signed with keyless cosign, and the provenance is
attached to the GitHub Release. The panel's updater (P7 follow-up) accepts
only manifests whose signature verifies against the embedded Rekor
bundle — unsigned or self-built binaries are a support matter, never an
update path.

## 7. Public origin (`public-origin <hostname>`)

The 8 install steps leave the web (:5173) and API (:3000) **loopback-only**;
operators reach the panel over an SSH tunnel. This subcommand puts a TLS
reverse proxy in front — the standard way to serve the panel on a real
domain:

- `sudo infra/install.sh public-origin panel.example.com`
- `sudo infra/install.sh public-origin off` — back to loopback/tunnel-only

Contract:

1. **Proxy = Caddy.** Distro-archive package first, official repo fallback.
   Caddy was chosen because certificate issuance, renewal, and the
   HTTP→HTTPS redirect need no operator choreography (decision: ADR-0023).
2. **Same-origin routing.** `https://<hostname>/api/v1/*` (REST *and* the
   WebSocket event stream) proxies to `127.0.0.1:3000`; everything else to
   `127.0.0.1:5173`. The browser never talks to any other origin; both
   upstreams stay loopback-only.
3. **DNS honesty gate.** The hostname must resolve to the machine's public
   address or the run aborts (override for NAT: `FORCE_PUBLIC_ORIGIN=1`).
   Non-public suffixes (`.local`, `.test`, …) are refused outright.
4. **Health gate.** The command returns only after
   `https://<hostname>/api/v1/health` and the web root answer over real TLS
   (120 s budget covers first issuance).
5. **Firewall.** ufw allows exactly 22/80/443 — unchanged by this step.
6. **Hardening headers.** HSTS (1 year), `nosniff`, `same-origin` referrer;
   `Server` is stripped. Access log lands in
   `/var/log/caddy/nexuspanel-access.log` (fail2ban fuel for a later batch).
7. **Reversibility.** Re-running rewrites `/etc/caddy/Caddyfile` (previous
   version kept as `Caddyfile.bak`); `off` neutralizes it. `uninstall`
   reports the Caddy removal path but never removes it silently.
8. **Loopback stays the default.** The panel is reachable without any
   domain; a public origin is an operator choice, and restricting it to
   office IPs (Caddy `remote_ip` matcher) is documented in the install
   guide.
