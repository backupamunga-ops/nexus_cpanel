# ADR-0001: MariaDB 11 is the only customer database engine in v1.0

- **Status:** Accepted (locked, Batch 1 Q1)
- **Phase:** P0
- **Deciders:** Project owner, Tech Lead

## Context

The panel provisions customer databases. Supporting multiple engines multiplies
provisioning, backup, and security-test surface. The schema (`databases.engine`)
already carries `mariadb | mysql | postgres`.

## Decision

v1.0 provisions **MariaDB 11 only**. MySQL 8 and PostgreSQL support arrive in v1.2
behind a `DatabaseEngineAdapter` interface defined in the control plane. The v1.0
agent implements only the MariaDB branch; the interface exists from the start so the
v1.2 expansion is additive, not a rewrite.

## Consequences

- One engine to harden, back up, and document for GA.
- `DatabaseEngineAdapter` is an abstraction seam from day one (not YAGNI — it is
  scheduled v1.2 work).
- Docs for v1.0 state MariaDB-only explicitly to set provider expectations.
