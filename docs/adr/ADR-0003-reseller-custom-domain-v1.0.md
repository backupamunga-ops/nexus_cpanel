# ADR-0003: Reseller custom panel domains ship in v1.0

- **Status:** Accepted (locked, Batch 1 Q3)
- **Phase:** P0

## Context

Resellers want `panel.resellerbrand.com` instead of the provider's panel host. Schema
columns (`resellers.custom_domain`, `custom_domain_status`, `custom_domain_ssl`) exist
in the DDL.

## Decision

Custom reseller panel domains are a **v1.0 feature**. Session cookies are scoped to
the request Host, and Host is validated against `resellers.custom_domain` per
security control **C14** (cross-reseller session isolation is tested in CI).

## Consequences

- C14 integration tests are a P2 exit criterion, not a later hardening item.
- The reseller branding UI includes domain status (pending | active | error) from v1.0.
