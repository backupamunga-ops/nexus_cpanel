import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionsGuard } from './permissions.guard';
import { AuthContext } from './request-context';

/**
 * Authorization matrix for the C6 global guard. The Prisma seam is a plain
 * object keyed by what the guard queries (user lookup, account access row).
 */

type TestUser = { id: string; is_super_admin: boolean };

const ADMIN: TestUser = { id: '01900000-0000-7000-8000-000000000001', is_super_admin: true };
const PLAIN: TestUser = { id: '01900000-0000-7000-8000-000000000002', is_super_admin: false };

function harness(opts: {
  user?: TestUser | null;
  accessRole?: string | null;
  permission?: string;
  isPublic?: boolean;
  params?: Record<string, string>;
  auth?: AuthContext | null;
}) {
  const prisma = {
    user: {
      findFirst: jest.fn().mockResolvedValue(
        opts.user === undefined ? PLAIN : opts.user, // default: PLAIN user
      ),
    },
    userHostingAccountAccess: {
      findFirst: jest
        .fn()
        .mockResolvedValue(opts.accessRole ? { role: opts.accessRole } : null),
    },
  };
  const reflector = {
    getAllAndOverride: jest.fn((_key: string) => {
      if (_key === 'nexuspanel:isPublic') return opts.isPublic ?? false;
      return opts.permission; // undefined = undecorated route
    }),
  } as unknown as Reflector;

  const req = {
    headers: {},
    params: opts.params,
    auth: opts.auth === undefined ? { userId: PLAIN.id, sessionId: 's1' } : opts.auth,
  };
  const ctx: ExecutionContext = {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;

  const guard = new PermissionsGuard(reflector, prisma as never);
  return { guard, req, prisma, ctx };
}

describe('PermissionsGuard (C6)', () => {
  it('allows @Public() routes without touching the database', async () => {
    const { guard, prisma, ctx } = harness({ isPublic: true, permission: undefined });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it('fail-closes undecorated routes', async () => {
    const { guard, ctx } = harness({ permission: undefined });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('rejects when JwtAuthGuard context is missing (guard-order safety)', async () => {
    const { guard, ctx } = harness({ permission: 'account:list', auth: null });
    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });

  it('rejects disabled, deleted or missing users', async () => {
    const { guard, ctx } = harness({ user: null, permission: 'account:list' });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('super admin passes any permission without access-row lookups', async () => {
    const { guard, prisma, ctx } = harness({ user: ADMIN, permission: 'audit:verify' });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(prisma.userHostingAccountAccess.findFirst).not.toHaveBeenCalled();
  });

  it('grants self-service permissions (auth:logout) to any active user', async () => {
    const { guard, ctx } = harness({ permission: 'auth:logout' });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it('denies non-super-admins on non-account resources (audit:*)', async () => {
    const { guard, ctx } = harness({ permission: 'audit:verify' });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('package:* is server-admin-only until resellers land (§4.5)', async () => {
    const denied = harness({ permission: 'package:list' });
    await expect(denied.guard.canActivate(denied.ctx)).rejects.toThrow(/server administrator/);
    const allowed = harness({ user: ADMIN, permission: 'package:create' });
    await expect(allowed.guard.canActivate(allowed.ctx)).resolves.toBe(true);
  });

  it('denies account:create to non-super-admins (resellers land later in P2)', async () => {
    const { guard, ctx } = harness({ permission: 'account:create' });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('admits account:list for non-super-admins (service scopes rows)', async () => {
    const { guard, ctx } = harness({ permission: 'account:list' });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it('denies account-scoped mutations without an access row (C7)', async () => {
    const { guard, ctx } = harness({
      permission: 'account:suspend',
      params: { id: 'acc-1' },
      accessRole: null,
    });
    await expect(guard.canActivate(ctx)).rejects.toThrow(
      /no access to this hosting account/,
    );
  });

  it('owner role: read, update, suspend, resume, delete — all granted', async () => {
    for (const p of ['account:read', 'account:update', 'account:suspend', 'account:resume', 'account:delete']) {
      const { guard, ctx } = harness({ permission: p, params: { id: 'acc-1' }, accessRole: 'owner' });
      await expect(guard.canActivate(ctx)).resolves.toBe(true);
    }
  });

  it('admin role: update/suspend/resume yes, delete no (spec §11.3)', async () => {
    const { guard, ctx } = harness({ permission: 'account:update', params: { id: 'acc-1' }, accessRole: 'admin' });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    const deny = harness({ permission: 'account:delete', params: { id: 'acc-1' }, accessRole: 'admin' });
    await expect(deny.guard.canActivate(ctx)).rejects.toThrow(
      /role 'admin' does not grant/,
    );
  });

  it('account:share — owner and admin may delegate; member/readonly may not (no transitive trust)', async () => {
    for (const role of ['owner', 'admin']) {
      const allow = harness({ permission: 'account:share', params: { id: 'acc-1' }, accessRole: role });
      await expect(allow.guard.canActivate(allow.ctx)).resolves.toBe(true);
    }
    for (const role of ['member', 'readonly']) {
      const deny = harness({ permission: 'account:share', params: { id: 'acc-1' }, accessRole: role });
      await expect(deny.guard.canActivate(deny.ctx)).rejects.toThrow(
        /does not grant 'account:share'/,
      );
    }
  });

  it('readonly role: read yes, suspend no', async () => {
    const { guard, ctx } = harness({ permission: 'account:read', params: { id: 'acc-1' }, accessRole: 'readonly' });
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    const deny = harness({ permission: 'account:suspend', params: { id: 'acc-1' }, accessRole: 'readonly' });
    await expect(deny.guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('unknown access role grants nothing (fail-closed)', async () => {
    const { guard, ctx } = harness({ permission: 'account:read', params: { id: 'acc-1' }, accessRole: 'ghost' });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('non-list account permission on a collection route is denied', async () => {
    const { guard, ctx } = harness({ permission: 'account:suspend', params: {} });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('attaches the resolved role to the request context for audit attribution', async () => {
    const { guard, req, ctx } = harness({ permission: 'account:suspend', params: { id: 'acc-1' }, accessRole: 'owner' });
    await guard.canActivate(ctx);
    expect(req.auth!.accountRole).toBe('owner');
  });
});
