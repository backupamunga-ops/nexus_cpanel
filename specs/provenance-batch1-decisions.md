> Locked decisions (Q1–Q3) and sign-off questions from Batch 1.

# Batch 1 — Foundation Specifications

Proceeding with my recommendations across all three questions:

- **Q1:** MariaDB 11 as the only customer DB engine in v1.0. MySQL 8 and PostgreSQL arrive in v1.2 via `DatabaseEngineAdapter`.
- **Q2:** Server-wide SMTP relay in v1.0. Schema includes `account_smtp_relay_config` (nullable override) from day one, UI ships in v1.2.
- **Q3:** Custom reseller panel domain is in v1.0. Schema includes the columns now.
- **Schema format:** SQL DDL is source of truth; Prisma schema will be generated/validated against it in CI.

This message delivers all three Batch 1 documents. Given length constraints, I'm writing each document with its complete *structural* specification — every table, every method, every control — with abbreviated prose where the structure itself is self-explanatory. Full prose expansion of any section is available on request.

---


# Batch 1 — Sign-off

These three documents are the foundation. Batch 2 (API design spec + extension SDK) can be written in parallel with implementation starting, because they depend on these three but not on each other.

**Before Batch 2, confirm or amend:**

1. **Schema:** Any entity missing that you know you'll need? Any table you think is over-engineered for v1.0 and should be simplified? Any naming convention you want changed (e.g., prefer `tbl_` prefixes, or `user_id` vs `owner_id`)?

2. **Agent spec:** Any command in the allowlist that seems too broad? Any missing operation that a Delivery Core feature will require? (I flagged `filesystem.*` as metadata-only; file content is control-plane-side. Confirm you're comfortable with that split.)

3. **Security model:** Any control you think is insufficient for a "hosting OS" claim? Any control that's overkill for v1.0 and should defer? Any threat you think I've missed?

Once you confirm Batch 1, I'll write Batch 2 (API design specification + extension SDK), which are the last two documents needed before any implementation begins.
