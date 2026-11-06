# e2e/load — performance SLO harness (P7)

SLOs from `docs/plan/BUILD_PLAN.md` §"P7": **API p95 ≤ 300 ms**, **agent op
p95 ≤ 1 s**. These are latency contracts, not capacity plans — they prove
the panel is responsive on reference hardware; they do not certify user
counts.

| Script | Proves | Needs |
|---|---|---|
| `k6-api-slo.js` | API p95 ≤ 300 ms (public + authenticated reads) | booted control plane (runbook steps 1–4) |
| `k6-agent-op.js` | agent op p95 ≤ 1 s, end-to-end through the signed-command path | FULL stack incl. root agent (runbook steps 1–6) + one account |

## Run locally

```bash
# booted stack per docs/runbooks/m0-fresh-vm.md, then:
BASE_URL=http://localhost:3000/api/v1 k6 run e2e/load/k6-api-slo.js

BASE_URL=http://localhost:3000/api/v1 \
ADMIN_EMAIL=... ADMIN_PASSWORD=... ACCOUNT_ID=<uuid> \
k6 run e2e/load/k6-agent-op.js
```

Install k6: <https://grafana.com/docs/k6/latest/set-up/install-k6/>.

## Nightly

`.github/workflows/nightly.yml` boots a fresh stack (postgres service +
canonical DDL + control plane) on GitHub Actions and runs the public
portion of `k6-api-slo.js` with the SLO thresholds enforced — a regression
in API latency fails the nightly, not a release. The authenticated and
agent-op suites run on the live-VM acceptance rig where credentials and a
root agent exist (AS-BUILT §3).
