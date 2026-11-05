# ADR-0016 — Firewall & fail2ban: managed nftables, fail-closed apply, audited unban

**Status:** Accepted (B11)
**Amends:** agent spec §4 (adds `firewall.*`, `fail2ban.*`), API spec §4.15
**Builds on:** ADR-0004 (DDL-first), server-settings fail-closed pattern

## Context

B11 adds the first P5 security batch: server-wide network policy and
intrusion protection. Two tools exist on virtually every Linux host and are
what operators already know: **nftables** (packet filtering) and
**fail2ban** (brute-force lockouts). The panel must manage both without ever
becoming a way to shoot yourself in the foot from a browser tab.

The schema (DDL-first, v2.0) already carries the registry tables:
`firewall_rules`, `fail2ban_jails`, `fail2ban_bans`.

## Decision

### 1. One managed table, full-replace reconcile

The agent renders ALL panel rules into a single nftables table
(`inet nexuspanel`) and applies it as a unit:

```
nft -c -f <staging>          # 1. compile-check — a broken ruleset never reaches the kernel
nft delete table inet nexuspanel   # 2. remove previous generation (best-effort, first run = absent)
nft -f <staging>             # 3. apply
```

The rendered conf lives at `/etc/nexuspanel/firewall.conf` (override:
`NEXUSAGENT_NFT_CONF_PATH`) with a `DO NOT EDIT` header — hand edits are
overwritten on the next apply, by design. The panel registry
(`firewall_rules`) mirrors what was applied; every mutation is **agent-first**:
a failed apply leaves NO row behind.

Unknown params are rejected (`DisallowUnknownFields`, the server-settings
boundary pattern). The whitelist: `name`, `direction` (inbound|outbound),
`protocol` (tcp|udp|icmp), `port_from`/`port_to` (1–65535, icmp carries
none), `source_cidr` (IPv4/IPv6 CIDR or bare IP), `action`
(accept|drop|reject). At most 100 rules per apply.

### 2. Self-lockout guard (fail-closed, agent-authoritative)

The agent refuses — regardless of what any caller asks for — any drop/reject
rule that would sever the management path from an unfiltered source:

- inbound tcp covering **22 (ssh)**, **3000 (control plane)** or
  **5173 (panel web)**, or with no port filter at all, where the source is
  `0.0.0.0/0`/`::/0`/absent;
- outbound drop/reject with no port filter (total traffic blackout).

The refusal message names the port and the guard
("…refused (self-lockout guard, ADR-0016)") so the operator can act on it.
An explicit `allow_unsafe_management_lockout: true` override exists and is
audited verbatim; the default is refusal. The panel duplicates basic field
validation for fast 422s but never weakens this guard — the agent is the
last line of defense.

### 3. No ban command

fail2ban owns banning: jails watch logs and ban on their own schedule. The
panel adds `fail2ban.jails` (live status parse: currently/total banned, IP
list per jail — read-only, served offline per spec §6) and
`fail2ban.unban` (narrow, audited: `fail2ban-client set <jail> unbanip <ip>`).
A panel-triggered `ban` was rejected: it duplicates fail2ban's job, invites
abuse through compromised panel credentials, and every legitimate ban the
panel would want is already expressible as a fail2ban jail or a firewall
rule.

### 4. Honest offline states

Jail/ban state is read LIVE from the node and never persisted panel-side.
If the agent is unreachable, the UI says so ("agent unreachable: …") rather
than showing a stale ban list as if current (D-11). `firewall.status` is
read-only and serves while the control plane is down (spec §6).

## Consequences

- Agent surface grows by four allowlisted methods:
  `firewall.apply_rules`, `firewall.status`, `fail2ban.jails`,
  `fail2ban.unban`.
- Permission vocabulary grows by `firewall:read`, `firewall:manage`
  (server-scoped — NOT in `HOSTING_SCOPED_PREFIXES`; non-super users get
  nothing by default).
- The API §4.15 draft rows under `/security/*` for firewall/fail2ban were
  re-homed to `/firewall/*` at implementation; WAF/anti-malware rows remain
  under `/security/*` for B12.
- Exit evidence: agent negative tests prove a self-lockout rule is refused
  and the check-fail path never touches the kernel; control-plane tests
  prove agent-first ordering (no row on refused apply) and audited unban.
