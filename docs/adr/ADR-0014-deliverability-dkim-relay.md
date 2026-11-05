# ADR-0014: Deliverability — DKIM keys are minted control-plane-side; DNS records are auto-written through the DNS module; relay config is server-wide in system_settings

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P4 (B08 deliverability & relay)
- **Deciders:** Security review per BUILD_PLAN §2 WS7

## Context

B08 wires deliverability on top of B07 (mail core) and B06 (DNS core):

1. **DKIM**: keys must exist on the node (opendkim signs), the public half
   must land in DNS (`<selector>._domainkey.<domain>` TXT), and the panel
   must show an honest "signing active" state.
2. **SPF/DMARC**: one-pass wizard records that must not silently fight an
   existing TXT at the same name.
3. **Relay**: ADR-0002 locked a *server-wide* relay for v1.0; the API spec's
   `POST /mail/domains/{id}/relay` assumed per-domain relay, and the schema
   carries the (v1.2) per-account override table.
4. **Queue tooling**: postqueue is the only honest source of queue state.

## Decision

**1. DKIM key minting is a control-plane job.** The CP generates an RSA-2048
keypair (`node:crypto`), sends the **private PEM to the agent over the
signed Unix socket** (`mail.apply_dkim`), which stores it at
`/etc/opendkim/keys/<domain>/<selector>.private` (0600), derives the public
half itself and returns the exact DNS TXT value. The panel then **writes the
DNS record through the DnsService module call** (not HTTP): one code path
for wizard and API, one audit chain, PowerDNS stays the only DNS writer.
`mail_domain_dkim` (DDL-first, new table) tracks selector + rotation state.
If no managed DNS zone exists for the mail domain, the endpoint fails 409
and returns the record for manual insertion at the operator's DNS host —
never a silent "done".

Rotation mints a fresh selector (default `s<unixts>`), writes the new TXT
and keeps the old one; removing an old selector's TXT is an explicit manual
step so in-flight mail is not broken.

**2. opendkim wiring is agent-side and honestly skippable.** The agent
maintains managed `KeyTable`/`SigningTable` snippet files and reports
`opendkim: applied|skipped:<reason>`. A node without opendkim still gets the
key file + DNS record (harmless), and every response states that signing is
not active until opendkim runs. The panel badge is "stored — not signing"
in that case (D-11).

**3. SPF/DMARC upserts are DNS-module writes with explicit conflict rules.**
SPF: exactly one TXT at the apex starting `v=spf1` — if one exists and was
not panel-written, the wizard refuses with the existing value (manual
merge), else it replaces the panel-written one. DMARC: one TXT at
`_dmarc.<domain>`; same rule. Both endpoints return the record as applied.

**4. Relay config is server-wide (ADR-0002 stands).** Stored in
`system_settings` under `mail.relay` (provider, host, port, username, and
SecretBox-encrypted credentials — AES-256-GCM, ADR-0009). The per-account
override table stays unused until v1.2 as decided in ADR-0002. The API
surface is `GET/PUT/DELETE /mail/relay` — an amendment to §4.8's
per-domain routes, recorded here. Enforcement is **explicitly honest**:
storing the profile does not yet rewrite the node's Postfix transport;
transport wiring lands with the config-engine Postfix pipeline and is
badged "stored — not yet routing" until then.

**5. Queue tooling reads the truth, then acts.** `mail.queue_list` parses
`postqueue -p` (queue id, size, arrival, sender, first recipient, deferred
reason); `mail.queue_flush` maps to `postqueue -f` (whole queue) or
`postqueue -i <id>`; `mail.queue_retry` maps to `postsuper -r <id>`.
Missing binaries are honest errors — the panel must never show an "empty
queue" it cannot see.

## Consequences

- The DKIM private key lives in exactly two places: the panel process
  memory (transient) and the node key file (0600). No database copy, no
  audit payload (audit carries selector + fingerprints only).
- DNS writes for mail records are indistinguishable from manual DNS edits
  in the audit chain (same `dns.record.*` operations) — by design; the mail
  operation adds its own `mail.dkim.enable` / `mail.spf.apply` events.
- The queue API is server-wide (jwt, `mail:queue:*`), matching §4.8's auth
  column; it is not account-scoped because postqueue state is not.
