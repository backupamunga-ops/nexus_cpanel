/**
 * k6 — API performance SLO suite (P7, BUILD_PLAN §"P7").
 *
 * SLO (BUILD_PLAN P7): API p95 ≤ 300 ms.
 *
 * Run against a BOOTED stack (docs/runbooks/m0-fresh-vm.md steps 1–4; the
 * agent is not needed for these endpoints):
 *
 *   BASE_URL=http://localhost:3000/api/v1 \
 *   ADMIN_EMAIL=you@panel.test ADMIN_PASSWORD=... \
 *   k6 run e2e/load/k6-api-slo.js
 *
 * Scenarios are deliberately modest: they prove the SLO on reference
 * hardware without pretending to be a capacity plan. The nightly workflow
 * (.github/workflows/nightly.yml) runs the public-endpoint portion against
 * a fresh stack on every scheduled run.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL || 'http://localhost:3000/api/v1';
const ADMIN_EMAIL = __ENV.ADMIN_EMAIL || '';
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD || '';

export const options = {
  scenarios: {
    // 1. public liveness/meta reads — always runnable (no credentials needed)
    public: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 10 },
        { duration: '60s', target: 10 },
        { duration: '10s', target: 0 },
      ],
      exec: 'publicScenario',
    },
    // 2. authenticated reads — only wired when ADMIN credentials are provided
    authed: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: Number(__ENV.AUTH_VUS || 10) },
        { duration: '60s', target: Number(__ENV.AUTH_VUS || 10) },
        { duration: '10s', target: 0 },
      ],
      exec: 'authedScenario',
      startTime: '5s',
    },
  },
  thresholds: {
    // the SLO: 95% of every request in the suite completes under 300 ms
    'http_req_duration{scenario:public}': ['p(95)<300'],
    'http_req_duration{scenario:authed}': ['p(95)<300'],
    http_req_failed: ['rate<0.01'],
  },
};

export function publicScenario() {
  const health = http.get(`${BASE}/health`);
  check(health, { 'health 200': (r) => r.status === 200 });
  const version = http.get(`${BASE}/version`);
  check(version, { 'version 200': (r) => r.status === 200 });
  sleep(1);
}

let token = null;

export function authedScenario() {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    sleep(5);
    return; // credentials absent — scenario idles, threshold unexercised
  }
  if (!token) {
    const res = http.post(
      `${BASE}/auth/login`,
      JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
      { headers: { 'Content-Type': 'application/json' } },
    );
    check(res, { 'login 200/201': (r) => r.status === 200 || r.status === 201 });
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
  const authed = {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  };
  const accounts = http.get(`${BASE}/accounts`, authed);
  check(accounts, { 'accounts ok': (r) => r.status === 200 || r.status === 401 });
  const notifications = http.get(`${BASE}/notifications`, authed);
  check(notifications, { 'notifications ok': (r) => r.status === 200 || r.status === 401 });
  sleep(1);
}
