# ADR-0006: v1.0 scope rulings — single-node control, gaps adopted, license pending

- **Status:** Accepted (owner defaults applied at build kickoff, 2026-11-05)
- **Phase:** P0

## Context

At kickoff the owner authorized the build on defaults for open decisions D-5…D-10
(gaps G-01…G-24) per the Master Project Documentation §9.

## Decision

1. **v1.0 is single-node control:** one control plane manages nodes through their
   agents (registry, health, per-service control). Placement/orchestration scheduling
   is deferred to v1.x with an explicit spec (G-14).
2. **Gap recommendations G-01…G-24 adopted**, notably: design-system spec (G-01),
   docs portal + screenshot rig from P0 (G-07/G-08), ADR process (G-18), trunk-based
   delivery policy (G-19), CI secret policy (G-24).
3. **Billing stays out of core** — first-party "billing bridge" extension after v1.0 (G-11).
4. **Webmail: none in v1.0** unless the owner opts in later (G-12).
5. **License: pending (D-9).** `LICENSE.md` is a placeholder; resolved before first
   public release.

## Consequences

- The two UI/UX designer seats start immediately on the design system (G-01), ahead
  of P2 UI implementation.
- Any reversal of these rulings is a new ADR that supersedes this one.
