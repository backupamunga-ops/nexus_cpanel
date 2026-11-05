import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  ACCOUNT_ROLE_PERMISSIONS,
  PERMISSION_KEY,
  SELF_PERMISSIONS,
  SESSION_ONLY_KEY,
} from '../common/permissions';
import { PrismaService } from '../prisma/prisma.service';
import { IS_PUBLIC_KEY } from './public.decorator';
import { AuthenticatedRequest } from './request-context';

/**
 * Global permission gate (security control C6, master spec §11.3).
 *
 * Runs AFTER JwtAuthGuard (APP_GUARD order) and enforces the permission
 * declared with @RequirePermission BEFORE any business logic:
 *
 *   - @Public() routes bypass (health, login, refresh).
 *   - A route without a permission declaration is FAIL-CLOSED — this guard
 *     rejects it, and `npm run permissions:check` rejects the build.
 *   - Server Admins (users.is_super_admin) pass everything.
 *   - `auth:logout`-style self-service permissions pass for any active user.
 *   - `account:*` permissions resolve against the caller's active row in
 *     user_hosting_account_access for the `:id` in the route; the role maps
 *     to a fixed permission set (ACCOUNT_ROLE_PERMISSIONS).
 *   - Collection-level `account:list` passes here; the service narrows rows
 *     to granted accounts (C7 direction).
 *   - API tokens (C4): the required permission must be in the token's scopes
 *     AND the owner's own session-level authorization must also pass — a
 *     token never grants more than its owner holds. @SessionOnly() routes
 *     reject tokens outright (credential management is interactive-only).
 *   - Everything else (audit:*, future resources) requires elevated roles —
 *     non-super-admins are rejected until reseller roles land in P2.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const permission = this.reflector.getAllAndOverride<string>(PERMISSION_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!permission) {
      // Fail closed: an undecorated endpoint must never open. The C6 CI
      // check catches this at build time too — this is defense in depth.
      throw new ForbiddenException('endpoint lacks a permission declaration');
    }
    const sessionOnly = this.reflector.getAllAndOverride<boolean>(SESSION_ONLY_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const req = context.switchToHttp().getRequest<AuthenticatedRequest>();
    if (!req.auth?.userId) {
      throw new UnauthorizedException('authentication required');
    }

    const user = await this.prisma.user.findFirst({
      where: { id: req.auth.userId, deleted_at: null, is_active: true },
      select: { id: true, is_super_admin: true },
    });
    if (!user) {
      throw new ForbiddenException('account is disabled or no longer exists');
    }
    req.auth.isSuperAdmin = user.is_super_admin;

    const auth = req.auth;
    if (auth.viaApiToken) {
      // C4 gate 1: session-only surfaces reject tokens outright.
      if (sessionOnly) {
        throw new ForbiddenException('this endpoint requires an interactive session');
      }
      // C4 gate 2: the scope must cover the required permission — even for
      // super-admins (a token is bounded by its scopes, not by its owner).
      if (!auth.tokenScopes?.includes(permission)) {
        throw new ForbiddenException(`api token lacks the '${permission}' scope`);
      }
      // C4 gate 3 (below): the owner's own authorization must also pass.
    }

    if (user.is_super_admin || SELF_PERMISSIONS.has(permission)) {
      return true;
    }

    if (permission.startsWith('account:')) {
      return this.authorizeAccountPermission(permission, req);
    }

    if (permission.startsWith('package:')) {
      // Server-Admin-only until reseller-owned packages land (API spec §4.5);
      // tokens already passed the scope gate above, so an admin's scoped
      // token reaches here legitimately.
      if (!user.is_super_admin) {
        throw new ForbiddenException(`permission '${permission}' requires a server administrator`);
      }
      return true;
    }

    throw new ForbiddenException(`permission '${permission}' requires an elevated role`);
  }

  private async authorizeAccountPermission(
    permission: string,
    req: AuthenticatedRequest,
  ): Promise<boolean> {
    // Reseller account creation lands later in P2; until then only Server
    // Admins create hosting accounts.
    if (permission === 'account:create') {
      throw new ForbiddenException('account creation requires a server administrator');
    }

    const accountId = req.params?.id;
    if (!accountId) {
      if (permission === 'account:list') {
        return true; // service scopes rows to the caller's grants (C7)
      }
      throw new ForbiddenException(`permission '${permission}' requires an elevated role`);
    }

    const auth = req.auth;
    if (!auth) {
      throw new UnauthorizedException('authentication required');
    }
    const access = await this.prisma.userHostingAccountAccess.findFirst({
      where: {
        user_id: auth.userId,
        hosting_account_id: accountId,
        revoked_at: null,
      },
      select: { role: true },
    });
    if (!access) {
      throw new ForbiddenException('no access to this hosting account');
    }

    const granted = ACCOUNT_ROLE_PERMISSIONS[access.role] ?? [];
    if (!granted.includes(permission)) {
      throw new ForbiddenException(`role '${access.role}' does not grant '${permission}'`);
    }
    auth.accountRole = access.role;
    return true;
  }
}
