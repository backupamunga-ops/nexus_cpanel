# Contributing

## Ground rules

1. `specs/` is law. Read the relevant spec before writing code. Code that contradicts
   a spec is a bug — fix the code, or propose an ADR if the spec must change.
2. Conventional Commits (`feat(agent): ...`, `fix(api): ...`). Every PR references a
   phase ID (P0–P7) and workstream (WS1–WS8) from `docs/plan/BUILD_PLAN.md`.
3. Protected `main`. Short-lived branches, squash merges, required CI checks green.

## Definition of Done (every feature)

- [ ] Unit + integration tests (agent: `go test`; control plane: Jest)
- [ ] OpenAPI artifact updated if the API surface changed (CI diff check)
- [ ] Permission decorator on every new controller method (C6)
- [ ] Audit events emitted and hash-chained for privileged actions (C11)
- [ ] Path confinement / isolation tests where relevant (C7, C13)
- [ ] Docs page + regenerated screenshots for user-visible features
- [ ] No secrets in code, config, or logs (C9 scan green)

## Local development

See the Quick Start in [README.md](README.md). CI mirrors:
`make typecheck && make test && make build`.

## Security

Never paste credentials into issues, PRs, or chat. Report vulnerabilities privately
to the maintainers. All releases are cosign-signed (C19); verify before deploying.
