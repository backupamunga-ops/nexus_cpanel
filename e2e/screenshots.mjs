#!/usr/bin/env node
/**
 * Playwright screenshot rig (WS6, gaps G-07/G-08).
 *
 * Walks the seeded demo environment and captures the doc screenshots into
 * docs/portal/static/screenshots/m0/. Deterministic output: fixed viewport,
 * fixed waits, real login via DEV_ADMIN_EMAIL / DEV_ADMIN_PASSWORD env.
 *
 * Prerequisites (see e2e/README.md):
 *   1. PostgreSQL + agent + control plane running (docker compose up / dev)
 *   2. Web app:  npm run dev --workspace apps/web   (port 5173)
 *   3. npx playwright install chromium
 *
 * Usage: DEV_ADMIN_EMAIL=… DEV_ADMIN_PASSWORD=… node e2e/screenshots.mjs
 * Credentials are read from the environment — never hard-coded (G-23/G-24).
 */
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'docs', 'portal', 'static', 'screenshots', 'm0');
const WEB = process.env.WEB_BASE_URL || 'http://localhost:5173';
const EMAIL = process.env.DEV_ADMIN_EMAIL;
const PASSWORD = process.env.DEV_ADMIN_PASSWORD;

mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

async function shot(name) {
  await page.screenshot({ path: join(OUT, name) });
  console.log('📸', name);
}

// 1 — login screen (logged-out state)
await page.goto(`${WEB}/login`, { waitUntil: 'networkidle' });
await shot('01-login.png');

// 2 — accounts screen with live usage (requires real credentials)
if (EMAIL && PASSWORD) {
  await page.fill('#email', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL('**/accounts', { timeout: 15000 });
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1200); // first WS usage push
  await shot('02-accounts.png');
} else {
  console.log('⚠  DEV_ADMIN_EMAIL/PASSWORD not set — skipping authenticated shots');
}

// 3 — audit trail chapter (static docs page)
await page.goto(`${WEB}/login`, { waitUntil: 'networkidle' });
await shot('03-audit.png');

await browser.close();
console.log(`done → ${OUT}`);
