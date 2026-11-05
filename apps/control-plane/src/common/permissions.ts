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
export const SELF_PERMISSIONS: ReadonlySet<string> = new Set(['auth:logout']);
