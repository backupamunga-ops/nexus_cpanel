> Companion notes for `nexuspanel-schema-v2.0.sql`.

## DDL Source of Truth


**Companion notes for schema:** The full notes file (separate document) explains non-obvious decisions. Key ones inline above:
- `uuid_generate_v7()` as a function, not extension — avoids dependency on a specific PG extension version.
- `hosting_accounts.reseller_id` is a self-FK because a reseller *is* a hosting account with reseller capability, per §3.6.
- `account_smtp_relay_config` ships in schema now (Q2 decision) — UI in v1.2.
- `resellers.custom_domain` ships in schema now (Q3 decision) — UI can ship in v1.0 or v1.1.
- `audit_chain_heads` is a singleton (enforced by `CHECK (id)`) — one row tracks the current chain head for O(1) append and verification start.
- `jobs_metadata` mirrors BullMQ state for queryability, not as the source of truth.
- MariaDB is the only customer DB engine in v1.0; the `databases.engine` column already supports `mysql` and `postgres` for future use.

---
