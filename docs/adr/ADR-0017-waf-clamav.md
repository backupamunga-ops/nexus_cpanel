# ADR-0017 — Per-site WAF via nginx includes; ClamAV quarantine model

**Status:** Accepted (B12)
**Amends:** agent spec §4 (adds `waf.*`, `malware.*`), API spec §4.15a
**Builds on:** ADR-0004 (DDL-first), nginx config-apply primitive (§4.7)

## Context

B12 adds the application-layer defense: a per-site web application firewall
(ModSecurity + OWASP CRS) and anti-malware (ClamAV). The schema already
carried `modsecurity_policies`; the DDL grows `malware_scans` /
`malware_findings` (amendment to v2.0, same ADR-0004 flow: the DDL is the
source of truth, Prisma is generated).

## Decision

### 1. WAF = one include per domain, health-gated

Per-site posture lives in ONE nginx include per domain
(`<vhostroot>/<domain>.waf.conf`), rendered by the agent from the panel
policy: `modsecurity on;` + the CRS bundle include, `SecRuleEngine
DetectionOnly` (detect) or `On` (block), the requested CRS paranoia level,
and `SecRuleRemoveById` lines for per-site exclusions. `mode=off` removes
the include entirely (idempotent).

Apply order matches `nginx.apply_vhost` exactly: atomic write →
`nginx -t` health gate → reload; a failed gate ROLLS THE INCLUDE BACK.
Every successful apply is recorded as a `config_versions` row
(`target_type='waf_include'`), so the config engine's version history and
rollback semantics cover WAF changes like any other vhost change.

Whitelist: `mode` (off|detect|block), `paranoia_level` (1|2), `exclusions`
(CRS rule ids, ≤200, deduplicated). Unknown params rejected
(`DisallowUnknownFields`). The panel duplicates field validation for fast
422s; the agent remains authoritative.

Paranoia level 2 is offered because CRS documents it as the tuned-aggressive
tier; higher levels are deliberately not exposed — they bury operators in
false positives.

### 2. Malware: scan → quarantine → (audited) delete or restore

- `malware.scan` runs `clamscan -r --infected --no-summary` (or
  `clamdscan`) over an absolute, existing directory; exit code 1 (findings)
  is data, not failure. Findings are parsed from ClamAV's `PATH: (SIG)
  FOUND` lines.
- Infected files are QUARANTINED by moving them into the agent's quarantine
  root (structure preserved, mode 0600). Nothing is ever deleted in place
  by the scanner.
- `malware.quarantine_list` is read-only (serves offline per spec §6);
  `malware.quarantine_delete` and `malware.quarantine_restore` are audited
  mutations, both confined: delete resolves strictly inside the quarantine
  root, restore resolves into an account home through the same `fsTarget`
  confinement as every other content op (no `..`, no escape).
- The panel owns the findings registry (`malware_scans` /
  `malware_findings`) and mirrors what the agent did; the quarantine view
  is the registry joined with the node's live state — a missing file on the
  node is reported honestly, never silently reconciled away.
- Scheduled scans land with the job framework (B13); the `trigger` column
  already distinguishes `manual` from `scheduled`.

### 3. No automatic deletion, ever

A false positive in a malware signature must never cost a customer their
homepage. The scanner quarantines; only an operator destroys an artifact,
through an explicitly confirmed, audited flow. Restore exists for exactly
the false-positive case and is equally audited.

## Consequences

- Agent surface grows by five allowlisted methods: `waf.apply_policy`,
  `malware.scan`, `malware.quarantine_list`, `malware.quarantine_delete`,
  `malware.quarantine_restore`.
- Permission vocabulary grows by `security:read`, `security:manage`
  (server-scoped family; account-scoped visibility is re-checked in the
  services — invisible resources 404).
- Exit evidence (batch plan): agent tests prove the include is rolled back
  when the health gate fails and that detect renders `DetectionOnly` while
  block renders `On` (the CRS fires per mode in staging); quarantine
  flow — move → list → restore/delete — is covered end to end in-process.
- The `/security/*` API draft rows for WAF/malware are now live as §4.15a.
