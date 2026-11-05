import { SetMetadata } from '@nestjs/common';

/**
 * Permission model (security control C6, master spec §11.3):
 *
 * A permission is a `resource:action` string. Every controller method
 * declares the permission it requires via @RequirePermission; the global
 * PermissionsGuard rejects before the service layer, and a CI rule
 * (`npm run permissions:check`) fails the build if any controller method
 * lacks the decorator or @Public().
 *
 * Server-wide roles (spec §11.3 defaults):
 *   - Server Admin   — `users.is_super_admin`; passes every permission.
 *   - Reseller       — lands with the resellers feature (later P2).
 *   - Account-scoped — `user_hosting_account_access.role` grants account
 *     permissions on the specific hosting account only.
 */
export const PERMISSION_KEY = 'nexuspanel:permission';
export const RequirePermission = (permission: string) =>
  SetMetadata(PERMISSION_KEY, permission);

/**
 * Routes marked @SessionOnly() accept browser/JWT sessions only: API tokens
 * (C4) are rejected even when they carry the required scope. Applied to
 * credential-management surfaces (token CRUD, 2FA, sessions) where a stolen
 * automation token must not be able to mint or disable other credentials.
 */
export const SESSION_ONLY_KEY = 'nexuspanel:sessionOnly';
export const SessionOnly = () => SetMetadata(SESSION_ONLY_KEY, true);

/**
 * Permission vocabulary — the complete set of permission strings this build
 * can enforce. Two things keep it honest:
 *
 *   - API-token scopes (C4) are validated against this set at creation, so a
 *     typo'd scope can never silently match nothing (or everything).
 *   - `npm run permissions:check` extracts every @RequirePermission literal
 *     from every controller and fails the build if one is absent here — the
 *     vocabulary and the routes cannot drift apart.
 *
 * Entries may exist before their endpoints do (a token scoped to a permission
 * whose endpoint lands later is simply inert until then).
 */
export const KNOWN_PERMISSIONS: readonly string[] = [
  'account:create',
  'account:delete',
  'account:list',
  'account:read',
  'account:resume',
  'account:suspend',
  'account:update',
  'audit:list',
  'audit:read',
  'audit:verify',
  'auth:logout',
  'auth:tokens',
];

/**
 * Permissions granted by each per-account role (user_hosting_account_access,
 * spec §11.3: owner = full control; admin = owner minus deletion; member =
 * configurable, minimal by default; readonly = view only).
 *
 * `account:list` is intentionally absent: the guard admits every
 * authenticated user to the collection route and the service filters rows
 * to accounts the caller has an active access row for (C7 direction).
 */
export const ACCOUNT_ROLE_PERMISSIONS: Record<string, readonly string[]> = {
  owner: [
    'account:read',
    'account:update',
    'account:suspend',
    'account:resume',
    'account:delete',
  ],
  admin: ['account:read', 'account:update', 'account:suspend', 'account:resume'],
  member: ['account:read'],
  readonly: ['account:read'],
};

/**
 * Self-service permissions: any authenticated, active user holds these on
 * themself. No more than strictly necessary.
 */
export const SELF_PERMISSIONS: ReadonlySet<string> = new Set([
  'auth:logout',
  'auth:tokens',
]);
