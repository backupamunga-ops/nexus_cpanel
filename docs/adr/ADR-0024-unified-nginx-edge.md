# ADR-0024 — One edge for panel and sites: nginx owns 80/443 (`public-origin` nginx engine)

Date: 2026-11-06 · Status: Accepted · Amends: ADR-0023 (Caddy stays
selectable via `public-origin <hostname> caddy`, no longer the default)

## Context

ADR-0023 gave the panel a public TLS origin through bundled Caddy. The next
day the operator installed nginx for the Sites console (§4.7) and the box
refused to start it: `bind() to 0.0.0.0:80 failed (98: Address already in
use)` — Caddy held 80/443 (live-VM finding #16, the exact collision
UI-BACKLOG item 5 predicted). Two daemons cannot share the web ports, and
§4.7's serving engine IS nginx: agent-managed `conf.d` vhosts, `nginx -t`
health gates, config_versions rollback. There is a second, quieter hazard:
nginx loads `conf.d/*.conf` (agent site vhosts) BEFORE the panel-origin
vhost, so a site created on the panel's own hostname would shadow the panel
itself — one UI click away from taking the panel offline.

## Decision

1. **nginx is THE edge.** `public-origin <hostname>` now installs nginx +
   certbot and writes `/etc/nginx/sites-available/nexuspanel-panel` — the
   same same-origin routes as the old Caddyfile (`/api/v1/*` → :3000,
   including the ws event stream; everything else → :5173). The panel origin
   and every site vhost live on one daemon.
2. **Certificate migration, not re-issuance.** The engine reuses an existing
   certificate from `/etc/nginx/ssl/` or the previous Caddy edge
   (`/var/lib/caddy/.local/share/caddy/certificates/…`); only when none
   exists does certbot issue — after nginx owns :80, so the HTTP-01
   challenge can complete. Renewal rides the standard certbot timer until
   the §SSL milestone (agent-side ACME) takes over.
3. **The panel hostname is reserved.** `public-origin` persists
   `PANEL_PUBLIC_HOSTNAME` in `/etc/nexuspanel/nexuspanel.env`; the control
   plane refuses (409, layman wording) any site, subdomain, or alias on that
   exact name (`SitesService`, finding #16).
4. **Caddy retires cleanly and reversibly.** The engine disables — never
   purges — caddy; its Caddyfile, `.bak`, and certificates stay on disk.
   `public-origin off` removes the nginx panel vhost as well and drops the
   reservation.

## Consequences

- One web server to reason about. For an operator migrating from
  DirectAdmin/cPanel there is "the web server", full stop (the layman rule).
- Site vhosts serve HTTP on :80 today; per-site TLS arrives with the §SSL
  milestone, which now has exactly one daemon to integrate with.
- The panel hostname can never be taken down by a Sites click; the guard
  fails fast with a human reason instead of a shadowing incident.
- A fresh `public-origin` run installs nginx + certbot (heavier than Caddy
  alone) — which any node running Sites needs anyway.
