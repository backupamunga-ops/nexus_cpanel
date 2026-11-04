# ADR-0004: SQL DDL is the source of truth; Prisma is generated and validated in CI

- **Status:** Accepted (locked, Batch 1 header)
- **Phase:** P0

## Context

Two schema representations (hand-written DDL and ORM schema) drift silently. The
panel's correctness, migrations, and audit posture depend on them matching.

## Decision

`specs/nexuspanel-schema-v2.0.sql` is the **single source of truth**. The Prisma
schema is generated/validated **against the DDL in CI** (drift check fails the build).
The DDL is loaded verbatim by the dev compose stack on first boot.

## Consequences

- Engineers edit the `.sql` file, then regenerate/adjust Prisma — never the reverse.
- The CI `schema-drift` job graduates from placeholder to enforcement in P1 when the
  Prisma schema lands.
- Raw SQL migrations remain the mechanism for DDL evolution (with ADRs).
