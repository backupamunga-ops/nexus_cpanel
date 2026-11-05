# ADR-0012: `dns.*` on PowerDNS — API-first zone authority, pdnsutil for DNSSEC

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P4 (mail, DNS, databases, backups) — DNS core
- **Deciders:** Backend #2 (agent), Backend #1 (control plane), Tech Lead review per BUILD_PLAN §1

## Context

DNS is Delivery-Core scope (master spec M5: PowerDNS integration, all record
types, DNSSEC, templates, import/export, propagation checks). The agent spec
§4.9 already reserved eight `dns.*` methods, the DDL already carries
`dns_zones` / `dns_zone_templates` / `dns_records` / `dnssec_keys`, and the
SSL chapter carries an honest gap: wildcard (dns-01) certificates are blocked
on the DNS write path. The agent imports no third-party Go modules, so the
implementation must be stdlib-only.

Constraints that shape the design:

1. PowerDNS must remain the single authority for zone data. Mirroring zone
   state in the panel DB and serving answers from the mirror would create a
   second source of truth — exactly the divergence class the constitution
   forbids.
2. The agent never talks to the Internet on behalf of tenants and never
   shells out where a protocol exists; but DNSSEC tooling in PowerDNS is
   `pdnsutil`, a binary — that one is precondition-checked like `openssl`
   and `db_load` before it (ADR-0011 pattern).
3. SOA serials must survive panel-driven full replaces without operator
   ritual, or secondaries and caches go stale silently.

## Decision

### Transport — PowerDNS HTTP API

Zone and record mutations go through the PowerDNS HTTP API
(`NEXUSAGENT_PDNS_API_URL`, default `http://127.0.0.1:8081/api/v1`,
`X-API-Key` from `NEXUSAGENT_PDNS_API_KEY`). Missing configuration is a
**precondition error at command time** — dns.* fails loudly on an
unconfigured node instead of pretending. The HTTP client is an injected Dep,
so tests run against a fake API server with zero network.

Zones are created with `kind: Native` and `soa_edit_api: DEFAULT`:

- **Native** matches v1.0 reality: single node, no secondaries. Native zones
  still export in AXFR format via the API's export endpoint, so the
  `dns.axfr_export` contract holds. Master/secondaries arrive with the
  multi-server roadmap (v1.5), where the kind becomes a deployment choice —
  a one-line change at the create call.
- **`soa_edit_api: DEFAULT`** makes every API patch bump the serial
  automatically. This is what makes `dns.apply_records` (full replace) safe.

### SOA policy

`dns.create_zone` seeds a conventional SOA (`ns1.<zone>.
hostmaster.<zone>. <unixtime> 10800 3600 604800 3600`) when the payload has
none, and reports `soa_seeded: true` — the operator sees the row and can
re-create with an explicit SOA. `dns.apply_records` **rejects any SOA in the
payload** and never deletes or replaces the live SOA rrset; the serial is
owned by the nameserver, not the panel.

### Record model

Names are relative to the zone (`www`, `a.b`, `*.sub`) or absolute with a
trailing dot; absolute out-of-zone names are rejected. Allowed types: A,
AAAA, CNAME, MX, TXT, SRV, CAA, NS. MX requires `priority`, SRV requires
`priority/weight/port` — the agent composes them into wire content
(`"10 mail.example.com."`), which is what PowerDNS stores. TTL 60–604800
(default 3600). Apex CNAME is rejected. TXT content containing whitespace is
quoted at the API boundary. PowerDNS's own validation errors (422s) surface
verbatim as precondition errors — the nameserver's text is the actionable
part.

`dns.apply_records` diffs the desired set against **live** PowerDNS state
(GET zone first), so out-of-band edits inside PowerDNS are reconciled by the
next panel save instead of silently diverging.

### DNSSEC via pdnsutil

`enable_dnssec` / `disable_dnssec` run `pdnsutil secure-zone` /
`unsecure-zone`, then parse `pdnsutil show-zone` to return the **DS and
DNSKEY material the registrar needs** plus per-key rows. If secure-zone
"succeeds" but no material appears, the command fails loudly (D-11: never
report a secured zone we cannot show material for). The read path is a new
read-only method:

- `dns.get_dnssec` (`zone`) — live DNSSEC state without mutating. This is
  the only method added to §4.9 beyond the original eight.

`dnssec_keys` (panel DB, `private_key_enc NOT NULL`) is deliberately **not
written** in this batch: key material stays inside PowerDNS's own database
and the panel surfaces live state from the node. Archiving exported private
keys into the panel's encrypted store is a follow-up — the table exists, the
flow is documented as not-yet-built rather than faked.

### Control-plane shape

API spec §4.9 endpoints are implemented on top of the mirror registry
(`dns_zones` / `dns_records` rows written only after the agent call
succeeds — agent-first, like ftp.*). Record-level POST/PATCH/DELETE are
implemented as validate → recompute full desired set → `dns.apply_records`
→ transactional mirror replace; there is no record-level agent primitive by
design (one writer, one diff, one serial bump). Zone-check and export are
direct agent reads. **Propagation checking runs in the control plane, not
the agent**: querying public resolvers is not a privileged node operation,
and keeping it out of the agent allowlist preserves the minimal-execution
posture. `dnssec_keys` rows are not created (see above).

### Rejected alternatives

- Agent shells out to `pdnsutil zone-list` for records instead of the API —
  parse-drift-prone, and the API is the supported interface.
- Panel writes to PowerDNS directly (no agent hop) — violates §P.2.5 (no
  root access from the web application) in spirit: the privileged boundary
  is the agent, and every privileged action must sit behind the signed
  allowlist + hash-chained audit.
- BIND zonefiles on disk — reinvents PowerDNS's registry and forks authority
  (constitution P.2.4).
