# ADR-0007: Partial unique constraints in the canonical DDL are expressed as partial unique indexes

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P1 (M0)
- **Deciders:** Backend #1 (control plane), Tech Lead review per BUILD_PLAN §1

## Context

The canonical DDL (`specs/nexuspanel-schema-v2.0.sql`) is the single source of
truth for the database schema (ADR-0004). During M0 real-database bring-up
(applying the DDL verbatim to a fresh PostgreSQL 16 instance), four statements
failed to parse:

```sql
-- inside CREATE TABLE (user_hosting_account_access, subdomains, mailboxes, databases)
UNIQUE (a, b) WHERE deleted_at IS NULL
```

PostgreSQL does **not** support partial (filtered) UNIQUE *constraints* — a
`UNIQUE` constraint inside `CREATE TABLE` applies to the whole table and
accepts no `WHERE` clause. Partial uniqueness exists only as a partial unique
*index*. As written, the schema could never be applied to the database it was
designed for; the flaw surfaced in week 2, exactly as the M0 milestone intends
("if the schema has a flaw, it surfaces before 50 features are built on it").

## Decision

The four inline constraints are rewritten as named partial unique indexes with
identical semantics:

| Table | Index | Predicate |
|---|---|---|
| `user_hosting_account_access` | `uq_user_account_access_active` | `WHERE revoked_at IS NULL` |
| `subdomains` | `uq_subdomains_active` | `WHERE deleted_at IS NULL` |
| `mailboxes` | `uq_mailboxes_active` | `WHERE deleted_at IS NULL` |
| `databases` | `uq_databases_active` | `WHERE deleted_at IS NULL` |

Semantics preserved: at most one active/access-granted, live subdomain name
per domain, live mailbox per domain, live database name per engine. Deleted
(soft-deleted) rows may reuse names.

The Prisma generator (ADR-0004) already treats partial unique constraints as
"DDL-enforced, not expressible in Prisma" and skips them; the generated schema
is unchanged, and the CI drift gate stays green.

## Consequences

- The canonical DDL now applies verbatim to a clean PostgreSQL 16 database
  (verified in the M0 bring-up; re-run on every schema change).
- Enforcement lives at the index level, not the constraint level — functionally
  identical for integrity, and `information_schema`-level constraint
  introspection tools must use `pg_indexes` for these four instead.
- Any future DDL change gets the same real-database smoke test before merge
  (recorded here as the standing rule this ADR establishes).
