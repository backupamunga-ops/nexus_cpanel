# NexusPanel Specification Set (normative)

The documents below govern all implementation. Code that contradicts them is a bug.
Changes require an ADR per the Engineering Constitution (§P.6 of the master spec).

| # | Document | Role |
|---|---|---|
| 0 | nexuspanel-master-architecture-v2.0.md | Master architecture & product spec (§1–18) |
| 1 | nexuspanel-schema-v2.0.sql (+ .notes.md) | Control-plane DDL — source of truth for Prisma |
| 2 | nexuspanel-agent-spec-v1.0.md | Privileged Go agent — typed command allowlist |
| 3 | nexuspanel-security-model-v1.0.md | Threat model + controls C1–C20 |
| 4 | nexuspanel-api-design-v2.0.md | REST API design contract |
| 5 | nexuspanel-extension-sdk-v1.0.md | Out-of-process extension protocol & SDK |
| — | m0-scope-v1.0.md | First implementation milestone (vertical slice) |
| — | provenance-*.md | Locked decisions & batch sign-off records |

Deferred by design: `nexuspanel-installer-spec-v1.0.md` (written during P0/P1),
`nexuspanel-migration-spec-v1.0.md` (written at P4). See docs/plan/BUILD_PLAN.md.
