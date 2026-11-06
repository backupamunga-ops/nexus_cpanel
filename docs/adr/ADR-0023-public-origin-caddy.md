# ADR-0023 — Public origin: bundled Caddy TLS proxy (`public-origin`)

Date: 2026-11-06 · Status: Accepted · Supersedes: the "bring your own reverse
proxy (planned installer phase)" note in `docs/release/INSTALL_GUIDE.md`

## Context

The installer's non-negotiable posture (installer spec §1–§3) ships the web
origin on `127.0.0.1:5173` and the control plane on `127.0.0.1:3000`; only
SSH (22) and web (80/443) are open in ufw. The first drive of the installer
on real hardware (AS-BUILT §1, 2026-11-06) proved the tunnel path, but the
operator immediately asked the production question: *"we are using .local —
can we put the panel on `server.billucsolutions.co.ke`?"* A control panel is
used daily, from phones and offices; an SSH tunnel is a developer path, not
a product. The gap to close: serve the panel on a real hostname with real
TLS, without weakening the loopback posture, and without making operators
hand-roll nginx + certbot.

Also surfaced during that run: the API unit answered on `0.0.0.0:3000`
(ufw-shielded only) because `main.ts` hard-coded the bind address — fixed in
the same batch (finding #11) with a `HOST` environment override, set to
`127.0.0.1` in the shipped unit; `upgrade` now re-installs unit files so
`/etc/systemd` can never drift from the repo (finding #11b).

## Decision

1. **Bundled subcommand**: `infra/install.sh public-origin <hostname>`
   (spec §7). One command takes a live install from tunnel-only to
   `https://<hostname>`; `public-origin off` reverts. Loopback-only remains
   the default posture.
2. **Caddy, not nginx+certbot.** Automatic Let's Encrypt issuance/renewal
   and the HTTP→HTTPS redirect require zero operator choreography, which is
   the whole point of a layman-operable panel. nginx remains fully
   supported for operators who prefer it — the subcommand simply never
   claims port 80/443 if they don't run it.
3. **Same-origin routing.** `…/api/v1/*` (REST and the raw-ws event stream)
   proxies to `127.0.0.1:3000`; everything else to `127.0.0.1:5173`. The
   clients are already same-origin by construction (`web/lib/api.ts` uses a
   relative `/api/v1` base; `web/lib/events.ts` derives `wss://` from
   `window.location`), so no CORS, cookie-scope, or mixed-content surface
   appears.
4. **Honest gates.** DNS must resolve to the machine (or
   `FORCE_PUBLIC_ORIGIN=1`), and the command only succeeds after both the
   API health check and the web root answer over real TLS.

## Consequences

- A fresh install is reachable at a real domain in one command; certificates
  renew themselves; HSTS is on from day one.
- The panel login page becomes internet-reachable. Mitigations in depth:
  Argon2id + rate limits + optional 2FA at the app layer, fail2ban at the
  host layer, and a documented one-liner Caddy `remote_ip` allowlist for
  operators who only ever manage from fixed IPs.
- `/var/log/caddy/nexuspanel-access.log` gives the firewall/WAF batches a
  real log source to police later.
- Non-origin hostnames hitting the box get Caddy's default 200 empty
  response on 80 (and no TLS cert) — harmless, invisible in the panel.
