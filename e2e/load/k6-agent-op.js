/**
 * k6 — agent operation latency SLO (P7, BUILD_PLAN §"P7").
 *
 * SLO (BUILD_PLAN P7): agent op p95 ≤ 1 s, measured END TO END through the
 * control plane: an authenticated panel request that the control plane
 * forwards to the agent as a signed command, whose reply comes back to the
 * caller. The agent does the real OS work (usage sampling reads the live
 * cgroup slice), so this is the honest number — no mocking.
 *
 * Prerequisites: the FULL stack from docs/runbooks/m0-fresh-vm.md steps 1–6
 * (postgres + control plane + root agent with signatures ON) and at least
 * one hosting account. The scenario samples `GET /accounts/{id}/usage`,
 * which triggers `account.usage` on the agent every call.
 *
 *   BASE_URL=http://localhost:3000/api/v1 \
 *   ADMIN_EMAIL=... ADMIN_PASSWORD=... ACCOUNT_ID=<uuid> \
 *   k6 run e2e/load/k6-agent-op.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL || 'http://localhost:3000/api/v1';
const ADMIN_EMAIL = __ENV.ADMIN_EMAIL || '';
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD || '';
const ACCOUNT_ID = __ENV.ACCOUNT_ID || '';

export const options = {
  vus: Number(__ENV.VUS || 5),
  duration: __ENV.DURATION || '90s',
  thresholds: {
    // the SLO: the whole panel→agent round trip stays under 1 s at p95
    http_req_duration: ['p(95)<1000'],
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
  },
};

let token = null;

export default function () {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !ACCOUNT_ID) {
    sleep(5);
    return; // not configured — idles; CI nightly runs the api-slo suite instead
  }
  if (!token) {
    const res = http.post(
      `${BASE}/auth/login`,
      JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
      { headers: { 'Content-Type': 'application/json' } },
    );
    check(res, { 'login ok': (r) => r.status === 200 || r.status === 201 });
    try {
      const body = res.json();
      token = body.access_token || body.accessToken || (body.data && body.data.access_token) || null;
    } catch {
      token = null;
    }
    if (!token) {
      sleep(5);
      return;
    }
  }
  const res = http.get(`${BASE}/accounts/${ACCOUNT_ID}/usage`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  check(res, { 'usage 200': (r) => r.status === 200 });
  sleep(1);
}
