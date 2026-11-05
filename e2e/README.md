# E2E & screenshot rig

## Playwright screenshots (WS6 — gaps G-07/G-08)

`screenshots.mjs` walks the running stack and regenerates the docs-portal
screenshots on every UI-affecting merge (Definition of Done):

```bash
# 1. stack: PostgreSQL + agent + control plane (port 3000) + web dev (port 5173)
npm run dev --workspace apps/web
# 2. browsers (once)
npx playwright install chromium
# 3. shoot — credentials come from the environment, never the repo
DEV_ADMIN_EMAIL=admin@example.test DEV_ADMIN_PASSWORD='…' node e2e/screenshots.mjs
```

Output: `docs/portal/static/screenshots/m0/*.png` (committed with the docs).

## Suites

| Suite | When | Status |
|---|---|---|
| Screenshot rig | every UI-affecting merge | live |
| Smoke (login → create account → audit) | every PR | P2 |
| Full regression + axe a11y | nightly | P2 |
