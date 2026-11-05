/**
 * Web mirror of the control-plane permission vocabulary
 * (apps/control-plane/src/common/permissions.ts KNOWN_PERMISSIONS).
 *
 * Used ONLY to render scope checkboxes on the API-tokens screen. The server
 * re-validates every scope at creation (fail-closed), so a stale entry here
 * degrades to a clear 400 — never to a silently inert token.
 *
 * `npm run permissions:check` (control plane) compares this list against
 * KNOWN_PERMISSIONS and fails CI on drift — keep them in lockstep.
 */
export const WEB_KNOWN_PERMISSIONS: readonly string[] = [
  'account:create',
  'account:delete',
  'account:list',
  'account:read',
  'account:resume',
  'account:share',
  'account:suspend',
  'account:update',
  'audit:list',
  'audit:read',
  'audit:verify',
  'auth:2fa',
  'auth:logout',
  'auth:sessions',
  'auth:tokens',
  'package:create',
  'package:delete',
  'package:list',
  'package:read',
  'package:update',
  'reseller:create',
  'reseller:delete',
  'reseller:list',
  'reseller:read',
  'reseller:update',
  'settings:read',
  'settings:write',
];
