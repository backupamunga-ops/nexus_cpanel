#!/usr/bin/env node
/**
 * Playwright screenshot rig (WS6, gaps G-07/G-08) — extended at P4.
 *
 * Walks the seeded demo environment and captures the doc screenshots into
 * docs/portal/static/screenshots/<set>/. Deterministic output: fixed
 * viewport, fixed waits, real login via DEV_ADMIN_EMAIL / DEV_ADMIN_PASSWORD.
 *
 * Prerequisites (see e2e/README.md):
 *   1. PostgreSQL (or the embedded PGlite wire server) + agent + control plane
 *   2. Web app:  npm run start --workspace apps/web   (port 5173)
 *   3. Demo data: scripts/scratch/seed-demo.mjs (agent-less rigs) or real
 *      provisioning on a root dev VM
 *   4. npx playwright install chromium
 *
 * Usage: DEV_ADMIN_EMAIL=… DEV_ADMIN_PASSWORD=… node e2e/screenshots.mjs
 * Credentials are read from the environment — never hard-coded (G-23/G-24).
 */
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SET = process.env.SHOT_SET || 'p4';
const OUT = join(ROOT, 'docs', 'portal', 'static', 'screenshots', SET);
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

async function go(path, settle = 700) {
  await page.goto(`${WEB}${path}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(settle);
}

// Every hosting-scoped panel defaults to the first account in the list;
// the demo data lives on `alpha`. Pick it in the first account dropdown
// that carries the option, then let the page reload its data.
async function pickAccount(username = 'alpha') {  const selects = page.locator('select');
  const n = await selects.count();
  for (let i = 0; i < n; i++) {
    const sel = selects.nth(i);
    if (!(await sel.isVisible().catch(() => false))) continue;
    const options = sel.locator('option');
    const on = await options.count();
    for (let j = 0; j < on; j++) {
      if ((await options.nth(j).textContent())?.trim() === username) {
        const value = await options.nth(j).getAttribute('value');
        if (value && (await sel.inputValue()) !== value) {
          await sel.selectOption(value);
          await page.waitForTimeout(900);
        }
        return;
      }
    }
  }
}

// Wait briefly for a table's Open button, click the first one, settle.
async function tryClickOpen() {
  try {
    await page.locator('button:has-text("Open")').first().waitFor({ state: 'visible', timeout: 4000 });
    await page.locator('button:has-text("Open")').first().click();
    await page.waitForTimeout(1100);
    return true;
  } catch {
    return false;
  }
}

// 1 — login screen (logged-out state)
await page.goto(`${WEB}/login`, { waitUntil: 'networkidle' });
await shot('01-login.png');

// 2+ — authenticated walkthrough (requires real credentials)
if (EMAIL && PASSWORD) {
  await page.fill('#email', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL('**/accounts', { timeout: 15000 });
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1200); // first WS usage push
  await shot('02-accounts.png');

  await go('/', 900);
  await shot('03-dashboard.png');

  await go('/sites', 900);
  await pickAccount();
  await shot('04-sites.png');

  await go('/files', 900);
  await pickAccount();
  await shot('05-files.png');

  await go('/dns', 900);
  await pickAccount();
  await shot('06-dns.png');
  // Open the alpha.demo zone editor when present.
  if (await tryClickOpen()) {
    await shot('07-dns-zone-editor.png');
  }

  await go('/mail', 900);
  await pickAccount();
  await shot('08-email.png');
  if (await tryClickOpen()) {
    await shot('09-email-domain.png');
  }

  await go('/databases', 900);
  await pickAccount();
  await shot('10-databases.png');
  if (await tryClickOpen()) {
    await shot('11-databases-detail.png');
  }

  await go('/backups', 900);
  await shot('19-backups.png');
  // The backups panel is one long page: destinations, jobs, runs. The
  // second shot shows the jobs + runs tables with the honest badges.
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(700);
  await shot('20-backups-runs.png');

  await go('/firewall', 900);
  await shot('21-firewall.png');

  await go('/waf', 900);
  await shot('23-waf.png');

  // B14: apps & git deploys panel (DirectAdmin-simple: install form +
  // installed apps + git deployments with history/rollback).
  await go('/apps', 900);
  await shot('28-apps.png');
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(400);
  await shot('29-apps-git.png');

  // B15: migration wizard (shelf → steps → report) + the move list.
  await go('/migrations', 900);
  await shot('30-migrations.png');
  // Open the first (seeded, completed) migration: the per-entity verdict
  // table is the manual's money shot; then the verification report.
  try {
    await page.locator('button:has-text("Open")').first().click({ timeout: 4000 });
    await page.waitForTimeout(900);
    await shot('31-migrations-report.png');
    await page.locator('button:has-text("Report")').first().click({ timeout: 4000 });
    await page.waitForTimeout(1100);
    // the report renders below the fold — bring the cutover section into view
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(600);
    await shot('32-migrations-cutover.png');
  } catch {
    console.log('⚠ migrations detail shots skipped (no migration rows?)');
  }

  await go('/jobs', 900);
  await shot('24-jobs.png');

  await go('/notifications', 900);
  await shot('25-notifications.png');

  await go('/audit', 900);
  await shot('26-audit.png');
  // Run the on-page chain verification so the shot shows the live verdict.
  try {
    await page.locator('button:has-text("Verify chain now")').first().click({ timeout: 3000 });
    await page.waitForTimeout(1500);
    await shot('27-audit-verify.png');
  } catch { /* verify button not present (non-admin) — skip honestly */ }
  // With seeded rules + jails, the bans cards sit below the fold.
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(500);
  await shot('22-firewall-bans.png');

  await go('/accounts', 900);
  await shot('12-accounts-detail.png');

  await go('/packages', 900);
  await shot('13-packages.png');

  await go('/resellers', 900);
  await shot('14-resellers.png');

  await go('/server-settings', 900);
  await shot('15-server-settings.png');

  await go('/settings', 900);
  await shot('16-security.png');

  await go('/tokens', 900);
  await shot('17-tokens.png');

  await go('/sessions', 900);
  await shot('18-sessions.png');
} else {
  console.log('⚠  DEV_ADMIN_EMAIL/PASSWORD not set — skipping authenticated shots');
}

await browser.close();
console.log(`done → ${OUT}`);
