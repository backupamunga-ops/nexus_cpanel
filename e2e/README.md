# e2e/ — End-to-end suites

Playwright-driven smoke and full suites (build plan §5). The M0 happy path
(login → create account → audit chain verified → live usage) is the first suite,
added in P1 against the demo environment with deterministic seed data.

Layout plan:

| Path | Suite |
|---|---|
| `m0/` | login, account create, audit verify, usage polling |
| `smoke/` | per-phase smoke: one green path per shipped feature |
| `full/` | nightly regression |
