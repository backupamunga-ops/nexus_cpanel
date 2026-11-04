import { SetMetadata } from '@nestjs/common';

/**
 * Permission decorator (security control C6): every controller method declares
 * the permission it requires; PermissionGuard (P1, with auth) enforces it and a
 * CI rule fails the build if any controller method lacks the decorator.
 */
export const PERMISSION_KEY = 'nexuspanel:permission';
export const RequirePermission = (permission: string) =>
  SetMetadata(PERMISSION_KEY, permission);
