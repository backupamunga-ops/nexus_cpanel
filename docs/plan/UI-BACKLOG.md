# UI backlog — "a layman can navigate it" (standing directive, 2026-11-06)

The operator's rule of thumb for every screen: a non-technical user must be able
to understand what a section does and what will happen before they click.
Improve as we go — each shipped batch picks up the items that touch it.

## Seeded items (2026-11-06, first live-VM drive)

1. **DirectAdmin-style sectioned navigation.** Group the sidebar into the
   familiar DirectAdmin partitions (Account Manager / E-mail Manager / System
   Info & Files / Extra Features …) instead of a flat feature list, so a
   migrating cPanel/DirectAdmin admin finds things by muscle memory and a
   layman sees a small number of big, obvious areas.
2. **Centralized DNS management.** One DNS area listing every zone, with
   record editing in a single place (DirectAdmin style) — explicitly NOT the
   cPanel pattern of a per-domain zone editor buried in each domain's page
   (operator's words: "dns zone is cpanel style i just want the direct admins
   style where dns management is done at a central place"). ADR-0012's
   PowerDNS core already models zones centrally; this item is about the UI
   shape only.
3. **Username policy hint, inline.** Account creation rejects anything not
   all-lowercase (live test: "Amunga" → policy error, "amunga" → uid 1000).
   The form should say "lowercase letters, digits, dashes" next to the field
   and normalize as the user types, instead of failing after submit.
4. **Serving prerequisites surfaced before the click (done as of finding
   #15).** The Sites console shows whether nginx is installed / healthy on the
   node, so "create site" never dies with a raw agent error on a fresh box.
   Extend the same pattern to the other modules that depend on optional node
   software (PHP versions, MariaDB, PowerDNS, fail2ban): state what is
   missing, in words, with the operator task that closes the gap.
5. **Serving-stack coexistence design — RESOLVED 2026-11-06, ADR-0024.**
   `public-origin` now provisions the nginx edge (the same daemon that serves
   the agent's site vhosts), retires Caddy reversibly, reuses its certificate,
   and persists `PANEL_PUBLIC_HOSTNAME` so Sites refuses to shadow the panel
   (409 with a layman message; live-VM finding #16). UI follow-up: surface
   the reservation inline in the Sites form (pre-click, like item 4) so the
   operator learns the rule before submitting, not after.
