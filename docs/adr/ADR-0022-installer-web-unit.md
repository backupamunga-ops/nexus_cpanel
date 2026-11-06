# ADR-0022 — The installer ships a third systemd unit: the web origin is a service, not a static export

**Status:** Accepted (live-VM acceptance batch)
**Implements:** installer spec v1.0 §1 (amended), BUILD_PLAN P7 "installer finalization"
**Builds on:** `apps/web` (Next.js 15, `next.config.js` rewrites), ADR-0004 (no code change), installer spec §3 hardening baseline

## Context

Installer spec v1.0 §1 lists **two** systemd units (API + agent) and describes
the web layer as "built to static assets, served by the control plane's origin
or a reverse proxy". That description does not match what `apps/web` actually
is:

- `next.config.js` proxies same-origin `/api/v1/*` to the control plane via
  **rewrites** — a Next.js server feature. Static export (`output: 'export'`)
  disables rewrites, so the exported build would break the browser's
  same-origin API path.
- The control plane (`main.ts`) serves **no** static files — there is no
  ServeStatic and none is planned before GA.

So neither "served by the control plane's origin" nor "static assets" is
implementable without changing shipped code. Shipping an installer that
pretends otherwise would fail at step 6 of its own spec.

## Decision

`infra/systemd/` ships **three service units** (the installer enables all three) plus a one-shot
preparer unit for the delegated cgroup v2 root the agent's `isolation.provision` assumes
(`nexuspanel-cgroups.service` — `subtree_control` resets at reboot, so this cannot be
install-time-only work):

| Unit | Runs | Binds |
|---|---|---|
| `nexuspanel-agent.service` | the Go agent (root — the only root-adjacent process, installer spec §1) | unix socket `/run/nexuspanel/agent.sock` + `127.0.0.1:9101` |
| `nexuspanel-api.service` | control plane, unprivileged `nexuspanel` | `:3000` (firewalled to loopback reach; ufw baseline opens only 22/80/443) |
| `nexuspanel-web.service` | `next start` for `apps/web`, unprivileged `nexuspanel` | `127.0.0.1:5173` |
| `nexuspanel-cgroups.service` (oneshot) | mkdir + group-own `/sys/fs/cgroup/nexuspanel`, enable cpu/memory/pids on the root `subtree_control` | — |

The web unit binds **loopback only** (`next start -H 127.0.0.1`). Operators
reach the panel over an SSH tunnel or put their own reverse proxy on 80/443;
the installer never exposes 5173 publicly. Public reverse-proxy configuration
remains an operator concern in v1.0 (support matrix, not installer scope).

`/api/v1` reachability from the browser is unchanged: the Next server's
rewrites proxy same-origin `/api/v1/*` to `CONTROL_PLANE_INTERNAL_URL`
(default `http://127.0.0.1:3000`), set in the web unit.

## Consequences

- Installer spec §1's "two units" table is amended by this ADR (one line added
  to `docs/release/INSTALLER_V1.md`); the non-negotiables are untouched: the
  control plane and web both run as the unprivileged `nexuspanel` account, and
  the agent remains the only root-adjacent process.
- Hardening directives are shared by both Node units (`NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`, address-family
  allow-list), per installer spec §3.
- If web later becomes a true static export (no rewrites, no SSR), the unit is
  deleted and the reverse proxy serves files directly — this ADR is then
  superseded, not silently edited.
- The agent unit implements the installer spec's "root + explicit capability
  set" model. Agent spec §2's non-root `nexusagent` + ambient-capabilities
  model stays the recorded hardening target and is expected as an acceptance
  finding on the live VM, not silently dropped.
