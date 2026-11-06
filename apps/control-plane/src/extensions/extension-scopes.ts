/**
 * Extension permission scopes (extension SDK spec §6) — P7.
 *
 * A CLOSED list: extensions may only request from this set, unknown scopes
 * are rejected at registration (fail-closed), and adding a scope requires a
 * panel contract bump + re-review (spec §6/§12). This list is deliberately
 * separate from the panel's C6 vocabulary (common/permissions.ts): C6 governs
 * what PANEL users may do; this governs what third-party code may request.
 *
 * Forbidden forever (spec §6): password:read, 2fa:read, anything that grants
 * direct access to secrets — the panel never exports secrets, so no scope
 * exists for them.
 */

/** The panel/SDK contract version this runtime implements (SDK spec §12). */
export const PANEL_CONTRACT_VERSION = '1.0.0';

export const EXTENSION_SCOPES: Readonly<Record<string, string>> = {
  'account:read': 'List and read hosting accounts',
  'site:read': 'Read domains, subdomains, PHP config',
  'site:write': 'Create/update/delete domains (admin-confirmed per call)',
  'mail:read': 'Read mail domains and mailboxes',
  'mail:write': 'Create/update mailboxes (admin-confirmed per call)',
  'dns:read': 'Read zones and records',
  'dns:write': 'Modify DNS (admin-confirmed per call)',
  'db:read': 'Read databases',
  'ssl:read': 'Read certificates',
  'backup:read': 'Read backup jobs and runs',
  'backup:write': 'Trigger backups/restores (admin-confirmed per call)',
  'audit:read': 'Read audit entries',
  'notification:write': 'Create in-panel notifications',
  'user:read': 'Read user accounts (never passwords/2FA)',
  'events:subscribe': 'Subscribe to webhook-style events',
};

/** Write scopes that demand per-call admin confirmation in v1.0 (spec §6). */
export const EXTENSION_WRITE_SCOPES: ReadonlySet<string> = new Set([
  'site:write',
  'mail:write',
  'dns:write',
  'backup:write',
]);

export const EXTENSION_TYPES: readonly string[] = [
  'widget',
  'action',
  'integration',
  'provider',
  'reporter',
];

/** SemVer (MAJOR.MINOR.PATCH with optional prerelease/build). */
export const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** Compare two semver strings numerically; -1 | 0 | 1. Prerelease sorts before release. */
export function compareSemver(a: string, b: string): number {
  const pa = a.split(/[-+]/, 1)[0].split('.').map(Number);
  const pb = b.split(/[-+]/, 1)[0].split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  const preA = a.includes('-') ? a.split('-')[1]?.split('+')[0] ?? '' : null;
  const preB = b.includes('-') ? b.split('-')[1]?.split('+')[0] ?? '' : null;
  if (preA === preB) return 0;
  if (preA === null) return 1; // release > prerelease
  if (preB === null) return -1;
  return preA < preB ? -1 : preA > preB ? 1 : 0;
}

/**
 * Is `panelVersion` inside the manifest's declared compat window (spec §4)?
 * `nexuspanel_compat: { min, max }` — inclusive on both ends.
 */
export function isCompatible(
  panelVersion: string,
  compat: { min?: unknown; max?: unknown },
): boolean {
  if (typeof compat.min !== 'string' || typeof compat.max !== 'string') return false;
  if (!SEMVER_RE.test(compat.min) || !SEMVER_RE.test(compat.max)) return false;
  return compareSemver(panelVersion, compat.min) >= 0 && compareSemver(panelVersion, compat.max) <= 0;
}

/**
 * The `/api/v1/ext/*` surface (spec §5.3): the only endpoints an extension
 * token can reach, each bound to exactly one scope. Extension-scoped calls
 * are namespaced AWAY from the main `/api/v1/*` API and enforced at this
 * routing layer — an extension can never call a panel endpoint that is not
 * listed here, regardless of what scopes it holds.
 */
export const EXT_PROXY_ROUTES: ReadonlyArray<{ method: 'GET' | 'POST'; path: string; scope: string }> = [
  { method: 'GET', path: '/accounts', scope: 'account:read' },
  { method: 'GET', path: '/sites', scope: 'site:read' },
  { method: 'GET', path: '/mail/domains', scope: 'mail:read' },
  { method: 'GET', path: '/dns/zones', scope: 'dns:read' },
  { method: 'GET', path: '/databases', scope: 'db:read' },
  { method: 'GET', path: '/ssl/certificates', scope: 'ssl:read' },
  { method: 'GET', path: '/backups/jobs', scope: 'backup:read' },
  { method: 'GET', path: '/backups/runs', scope: 'backup:read' },
  { method: 'GET', path: '/audit', scope: 'audit:read' },
  { method: 'GET', path: '/users', scope: 'user:read' },
  { method: 'POST', path: '/notifications', scope: 'notification:write' },
  // Write scopes are DECLARED (so a granted scope maps to a real, named
  // endpoint) but REFUSED in v1.0 — every extension write requires per-call
  // admin confirmation (spec §6), and the confirmation queue is the v1.x
  // trust-level work. authorize() rejects these with write_requires_confirmation
  // before any resolver is consulted: fail-closed, nothing mutates.
  { method: 'POST', path: '/sites', scope: 'site:write' },
  { method: 'POST', path: '/mail/mailboxes', scope: 'mail:write' },
  { method: 'POST', path: '/dns/records', scope: 'dns:write' },
  { method: 'POST', path: '/backups/jobs', scope: 'backup:write' },
];

/**
 * Canonical hook names (SDK spec §4/§11) → panel audit `operation`s that
 * trigger them. The manifest declares hook keys from the left column; the
 * dispatcher maps them onto the operations the audit chain actually emits.
 */
export const HOOK_EVENT_ALIASES: Readonly<Record<string, readonly string[]>> = {
  'backup.completed': ['backup.run.success'],
  'backup.failed': ['backup.run.failure'],
  'backup.started': ['backup.run.start'],
  'site.created': ['site.create'],
  'domain.created': ['domain.create'],
  'account.created': ['account.create'],
  'account.suspended': ['account.suspend'],
};
