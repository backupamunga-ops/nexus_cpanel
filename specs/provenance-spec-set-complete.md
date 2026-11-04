> Specification-set completion record and M0 recommendation from Batch 2.

# Specification Set — Complete

With these five documents, the specification phase is complete:

| # | Document | Status |
|---|---|---|
| 1 | `nexuspanel-schema-v2.0.sql` | ✅ Delivered (Batch 1) |
| 2 | `nexuspanel-agent-spec-v1.0.md` | ✅ Delivered (Batch 1) |
| 3 | `nexuspanel-security-model-v1.0.md` | ✅ Delivered (Batch 1) |
| 4 | `nexuspanel-api-design-v2.0.md` | ✅ Delivered (Batch 2) |
| 5 | `nexuspanel-extension-sdk-v1.0.md` | ✅ Delivered (Batch 2) |
| 6 | `nexuspanel-installer-spec-v1.0.md` | **Deferred to v0.1 implementation** |
| 7 | `nexuspanel-migration-spec-v1.0.md` | **Deferred to v0.5 implementation** |

**Why the last two are deferred:** They specify operational procedures that depend on implementation choices that don't exist yet. Writing them now means guessing. Writing them when the first installation path is proven (v0.1) and when the first migration runs (v0.5) means writing them correctly. This is not skipping — it's sequencing honestly. Both are on the delivery plan and cannot be skipped before the features they specify ship.

---

# Where We Are and What Comes Next

The specification phase is complete for the foundation and interfaces. What remains before a line of code is written:

1. **You review Batches 1 and 2.** Anything to amend? Any table, endpoint, or scope that needs to change?

2. **Sign-off on the specification set.** Once signed off, it becomes the authority. Changes require amendment per §P.6.

3. **Set up the repository.** Monorepo layout (per §5.1 of v2.0), CI pipeline skeleton, Prisma schema validated against the SQL, OpenAPI generation wired up, one test that passes end-to-end. This is the "v0.1 kickoff" — small, and it proves the specification is implementable.

**What I recommend for the first implementation milestone** (the one that proves the spec works):

> **M0 — "Hello, privileged agent."** A minimal end-to-end slice: user logs in → clicks "create test account" → NestJS calls Go agent via signed mTLS → agent creates a Linux user + cgroup slice → audit entry written and hash-chained → frontend shows the account with live usage from the agent. No sites, no mail, no DNS. Just this one thread through every layer.

If M0 works cleanly, every subsequent feature is a variation on that thread. If M0 reveals a flaw in the schema, the agent protocol, or the security model, we find it before building 50 features on top of it. **This is the highest-leverage week in the project.**

Confirm the specification set, tell me any amendments, and I'll write the M0 scope document — the smallest possible vertical slice that validates the entire architecture before we commit to the full build.
