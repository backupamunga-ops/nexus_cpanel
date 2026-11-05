import { BadRequestException, ForbiddenException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiTokensService, API_TOKEN_PREFIX, hashApiToken } from './api-tokens.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { PermissionsGuard } from './permissions.guard';
import { JwtService } from './jwt.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { AuthContext } from './request-context';
import { KNOWN_PERMISSIONS, SELF_PERMISSIONS } from '../common/permissions';

/**
 * C4 API tokens — lifecycle service, bearer-gate integration and the
 * PermissionsGuard scope/SessionOnly matrix. The Prisma seam is a plain
 * object; the audit seam is the real in-memory chain so tests also assert
 * the audit trail.
 */

type TokenRow = {
  id: string;
  user_id: string;
  name: string;
  scopes: string[];
  ip_allowlist: string[];
  expires_at: Date | null;
  last_used_at: Date | null;
  created_at: Date;
  revoked_at: Date | null;
  token_hash: Uint8Array;
  /** Relation included by authenticate(); overridable in tests. */
  user?: { id: string; is_active: boolean; deleted_at: Date | null };
};

const USER = '01900000-0000-7000-8000-000000000001';
const OTHER = '01900000-0000-7000-8000-000000000002';
const now = () => new Date();

function makeRow(overrides: Partial<TokenRow> = {}): TokenRow {
  const secret = 'npt_seed';
  return {
    id: 'tok-1',
    user_id: USER,
    name: 'ci',
    scopes: ['account:list'],
    ip_allowlist: [],
    expires_at: null,
    last_used_at: null,
    created_at: now(),
    revoked_at: null,
    token_hash: new Uint8Array(hashApiToken(secret)),
    ...overrides,
  };
}

function serviceHarness(rows: TokenRow[] = []) {
  const audit = new InMemoryAuditService();
  const apiToken = {
    findUnique: jest.fn(async ({ where }: { where: { token_hash: Uint8Array } }) => {
      const row = rows.find((r) =>
        Buffer.from(r.token_hash).equals(Buffer.from(where.token_hash)),
      );
      if (!row) return null;
      return {
        ...row,
        user: row.user ?? { id: row.user_id, is_active: true, deleted_at: null },
      };
    }),
    findFirst: jest.fn(async ({ where }: { where: { id: string; user_id: string } }) =>
      rows.find((r) => r.id === where.id && r.user_id === where.user_id) ?? null,
    ),
    findMany: jest.fn(async ({ where }: { where: { user_id: string } }) =>
      rows.filter((r) => r.user_id === where.user_id),
    ),
    create: jest.fn(async ({ data }: { data: Record<string, unknown> }): Promise<TokenRow> => {
      const row: TokenRow = {
        id: `tok-${rows.length + 1}`,
        user_id: String(data.user_id),
        name: String(data.name),
        scopes: data.scopes as string[],
        ip_allowlist: (data.ip_allowlist as string[]) ?? [],
        expires_at: (data.expires_at as Date | null) ?? null,
        last_used_at: null,
        created_at: now(),
        revoked_at: null,
        token_hash: data.token_hash as Uint8Array,
      };
      rows.push(row);
      return row;
    }),
    update: jest.fn(async ({ where, data }: { where: { id: string }; data: Partial<TokenRow> }) => {
      const row = rows.find((r) => r.id === where.id);
      if (!row) throw new Error('not found');
      Object.assign(row, data);
      return row;
    }),
  };
  const tx = { apiToken };
  const prisma = {
    apiToken,
    $transaction: jest.fn(async (fn: (t: typeof tx) => Promise<TokenRow>): Promise<TokenRow> =>
      fn(tx),
    ),
  };
  const svc = new ApiTokensService(prisma as never, audit);
  return { svc, prisma, audit, rows };
}

describe('ApiTokensService (C4)', () => {
  it('create mints a prefixed opaque token, stores only its hash, returns the DTO', async () => {
    const { svc, prisma, rows } = serviceHarness();
    const { token, record } = await svc.create(USER, { name: 'deploy', scopes: ['account:list'] });

    expect(token.startsWith(API_TOKEN_PREFIX)).toBe(true);
    expect(token.length).toBeGreaterThan(API_TOKEN_PREFIX.length + 30);
    expect(prisma.apiToken.create).toHaveBeenCalledTimes(1);
    const stored = (prisma.apiToken.create as jest.Mock).mock.calls[0][0].data as Record<string, unknown>;
    // The plaintext never reaches the database — only the SHA-256.
    expect(Buffer.from(stored.token_hash as Uint8Array).toString('hex')).toBe(
      hashApiToken(token).toString('hex'),
    );
    expect(JSON.stringify(stored)).not.toContain(token);
    expect('token_hash' in record).toBe(false);
    expect(record.scopes).toEqual(['account:list']);
    expect(rows).toHaveLength(1);
  });

  it('create validates name, scopes, expiry and ip allowlist', async () => {
    const { svc } = serviceHarness();
    await expect(svc.create(USER, { name: '', scopes: ['account:list'] })).rejects.toThrow(BadRequestException);
    await expect(svc.create(USER, { name: 'x', scopes: [] })).rejects.toThrow(BadRequestException);
    await expect(svc.create(USER, { name: 'x', scopes: 'account:list' })).rejects.toThrow(BadRequestException);
    await expect(svc.create(USER, { name: 'x', scopes: ['account:typo'] })).rejects.toThrow(/unknown scope/);
    await expect(svc.create(USER, { name: 'x', scopes: ['account:list'], expires_at: '2020-01-01' })).rejects.toThrow(
      /future/,
    );
    await expect(svc.create(USER, { name: 'x', scopes: ['account:list'], expires_at: 'not-a-date' })).rejects.toThrow(
      /valid date/,
    );
    await expect(svc.create(USER, { name: 'x', scopes: ['account:list'], ip_allowlist: ['999.1.1.1'] })).rejects.toThrow(
      /valid IP/,
    );
  });

  it('create normalizes scopes (dedupe + sort) against the vocabulary', async () => {
    const { svc } = serviceHarness();
    const { record } = await svc.create(USER, {
      name: 'x',
      scopes: ['audit:verify', 'account:list', 'audit:verify'],
    });
    expect(record.scopes).toEqual(['account:list', 'audit:verify']);
  });

  it('every KNOWN_PERMISSIONS entry is a well-formed resource:action string', () => {
    for (const p of KNOWN_PERMISSIONS) {
      expect(p).toMatch(/^[a-z]+:[a-z]+$/);
    }
    // The self-service set and the account-role matrix must stay inside the
    // vocabulary — the CI vocabulary check enforces the controller direction.
    for (const p of SELF_PERMISSIONS) expect(KNOWN_PERMISSIONS).toContain(p);
  });

  it('list returns own tokens only, mapped without hash material', async () => {
    const { svc } = serviceHarness([
      makeRow(),
      makeRow({ id: 'tok-2', user_id: OTHER, token_hash: new Uint8Array(hashApiToken('npt_other')) }),
    ]);
    const { data } = await svc.list(USER);
    expect(data).toHaveLength(1);
    expect(data[0].id).toBe('tok-1');
    expect(JSON.stringify(data)).not.toContain('token_hash');
  });

  it('authenticate: happy path attaches scopes; unknown hash is uniform and unaudited', async () => {
    const { svc, audit } = serviceHarness([makeRow()]);
    const secret = 'npt_seed';
    const ok = await svc.authenticate(secret, null);
    expect(ok).toEqual({ ok: true, userId: USER, tokenId: 'tok-1', scopes: ['account:list'] });

    const miss = await svc.authenticate('npt_garbage', null);
    expect(miss.ok).toBe(false);
    if (!miss.ok) expect(miss.reason).toBe('unknown');
    expect(audit.list()).toHaveLength(0); // unknown hashes: no audit noise
  });

  it('authenticate: revoked / expired / ip-denied / disabled-owner are rejected AND audited', async () => {
    for (const [overrides, reason] of [
      [{ revoked_at: now() }, 'revoked'],
      [{ expires_at: new Date(Date.now() - 1000) }, 'expired'],
      [{ ip_allowlist: ['10.0.0.9'] }, 'ip_denied'],
      [{ user: { id: USER, is_active: false, deleted_at: null } }, 'user_inactive'],
    ] as Array<[Partial<TokenRow>, string]>) {
      const { svc, audit } = serviceHarness([makeRow({ ...overrides })]);
      const res = await svc.authenticate('npt_seed', '10.0.0.1');
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.reason).toBe(reason);
      const entry = audit.list().find((e) => e.operation === 'api_token.auth_rejected');
      expect(entry?.outcome).toBe('failure');
    }
  });

  it('authenticate: ip allowlist accepts the listed address', async () => {
    const { svc } = serviceHarness([makeRow({ ip_allowlist: ['10.0.0.1'] })]);
    await expect(svc.authenticate('npt_seed', '10.0.0.1')).resolves.toEqual({
      ok: true,
      userId: USER,
      tokenId: 'tok-1',
      scopes: ['account:list'],
    });
  });

  it('authenticate updates last_used_at at most once per minute (throttle)', async () => {
    const fresh = makeRow({ last_used_at: new Date() });
    const { svc, prisma } = serviceHarness([fresh]);
    await svc.authenticate('npt_seed', null);
    expect(prisma.apiToken.update).not.toHaveBeenCalled();

    const stale = makeRow({ id: 'tok-old', last_used_at: new Date(Date.now() - 120_000) });
    const h2 = serviceHarness([stale]);
    await h2.svc.authenticate('npt_seed', null);
    expect(h2.prisma.apiToken.update).toHaveBeenCalledTimes(1);
  });

  it('revoke: own active token → revoked + audited; foreign → 404 + failure audit; already-revoked → idempotent no-op', async () => {
    const h = serviceHarness([makeRow()]);
    await h.svc.revoke(USER, 'tok-1');
    expect(h.rows[0].revoked_at).not.toBeNull();
    expect(h.audit.list().some((e) => e.operation === 'api_token.revoke' && e.outcome === 'success')).toBe(true);

    const foreign = serviceHarness([makeRow()]);
    await expect(foreign.svc.revoke(OTHER, 'tok-1')).rejects.toThrow(NotFoundException);
    expect(
      foreign.audit.list().some((e) => e.operation === 'api_token.revoke' && e.outcome === 'failure'),
    ).toBe(true);

    const dup = serviceHarness([makeRow({ revoked_at: now() })]);
    await expect(dup.svc.revoke(USER, 'tok-1')).resolves.toBeUndefined();
  });

  it('rotate: old revoked, new secret works, scopes/name/expiry preserved, lifetime not extended', async () => {
    const expires = new Date(Date.now() + 86_400_000);
    const { svc, rows, audit } = serviceHarness([
      makeRow({ expires_at: expires, scopes: ['audit:verify'] }),
    ]);
    const { token, record } = await svc.rotate(USER, 'tok-1');

    expect(token.startsWith(API_TOKEN_PREFIX)).toBe(true);
    // The new row's hash matches the returned secret; the old row is revoked.
    const newRow = rows.find((r) => r.id !== 'tok-1');
    expect(newRow).toBeDefined();
    expect(Buffer.from(newRow!.token_hash).equals(Buffer.from(hashApiToken(token)))).toBe(true);
    expect(rows.find((r) => r.id === 'tok-1')!.revoked_at).not.toBeNull();
    expect(record.expires_at).toBe(expires.toISOString());
    expect(record.scopes).toEqual(['audit:verify']);
    expect(record.name).toBe('ci');
    expect(audit.list().some((e) => e.operation === 'api_token.rotate' && e.outcome === 'success')).toBe(true);
  });

  it('rotate refuses foreign or already-revoked tokens (404 + failure audit)', async () => {
    const foreign = serviceHarness([makeRow()]);
    await expect(foreign.svc.rotate(OTHER, 'tok-1')).rejects.toThrow(NotFoundException);

    const dead = serviceHarness([makeRow({ revoked_at: now() })]);
    await expect(dead.svc.rotate(USER, 'tok-1')).rejects.toThrow(NotFoundException);
    expect(dead.audit.list().some((e) => e.operation === 'api_token.rotate' && e.outcome === 'failure')).toBe(true);
  });
});

/**
 * JwtAuthGuard: `npt_…` credentials route to the token authenticator; JWTs
 * keep the session path. Failure shape is uniform (401) for both.
 */
describe('JwtAuthGuard API-token path', () => {
  function guardHarness(opts: {
    header?: string;
    tokenResult?: Awaited<ReturnType<ApiTokensService['authenticate']>>;
  }) {
    const jwt = new JwtService('x'.repeat(40));
    const reflector = {
      getAllAndOverride: jest.fn(() => false),
    } as unknown as Reflector;
    const apiTokens = {
      authenticate: jest.fn(async () => opts.tokenResult ?? { ok: false, reason: 'unknown' }),
    };
    const req = { headers: opts.header ? { authorization: opts.header } : {}, auth: undefined };
    const ctx = {
      switchToHttp: () => ({ getRequest: () => req }),
      getHandler: () => ({}),
      getClass: () => ({}),
    } as unknown as ExecutionContextLike;
    return { guard: new JwtAuthGuard(jwt, reflector, apiTokens as never), req, apiTokens, ctx };
  }

  type ExecutionContextLike = Parameters<JwtAuthGuard['canActivate']>[0];

  it('attaches token context (userId, tokenId, scopes, viaApiToken) on success', async () => {
    const h = guardHarness({
      header: 'Bearer npt_abc',
      tokenResult: { ok: true, userId: USER, tokenId: 'tok-9', scopes: ['account:list'] },
    });
    await expect(h.guard.canActivate(h.ctx as never)).resolves.toBe(true);
    expect(h.req.auth).toMatchObject({
      userId: USER,
      tokenId: 'tok-9',
      tokenScopes: ['account:list'],
      viaApiToken: true,
      sessionId: 'api-token:tok-9',
    });
  });

  it('rejects any failed token authentication with the uniform 401', async () => {
    for (const reason of ['unknown', 'revoked', 'expired', 'ip_denied', 'user_inactive'] as const) {
      const h = guardHarness({ header: 'Bearer npt_abc', tokenResult: { ok: false, reason } });
      await expect(h.guard.canActivate(h.ctx as never)).rejects.toThrow(UnauthorizedException);
    }
  });

  it('JWT credentials keep the session path; missing header still 401', async () => {
    const jwt = new JwtService('x'.repeat(40));
    const access = jwt.sign({ sub: USER, sid: 'sess-1' }, 60);
    const h = guardHarness({ header: `Bearer ${access}` });
    (h.apiTokens.authenticate as jest.Mock).mockClear();
    await expect(h.guard.canActivate(h.ctx as never)).resolves.toBe(true);
    expect(h.apiTokens.authenticate).not.toHaveBeenCalled();
    const auth = h.req.auth as AuthContext | undefined;
    expect(auth?.sessionId).toBe('sess-1');

    const none = guardHarness({});
    await expect(none.guard.canActivate(none.ctx as never)).rejects.toThrow(/missing bearer/);
  });
});

/**
 * PermissionsGuard × API tokens: scope required even for super-admins,
 * session-only surfaces closed, owner authorization still applies (gates 1-3).
 */
describe('PermissionsGuard × API tokens (C4)', () => {
  function pHarness(opts: {
    permission?: string;
    sessionOnly?: boolean;
    isSuperAdmin?: boolean;
    auth: AuthContext;
    accessRole?: string | null;
    params?: Record<string, string>;
  }) {
    const prisma = {
      user: {
        findFirst: jest.fn().mockResolvedValue({ id: USER, is_super_admin: opts.isSuperAdmin ?? false }),
      },
      userHostingAccountAccess: {
        findFirst: jest.fn().mockResolvedValue(opts.accessRole ? { role: opts.accessRole } : null),
      },
    };
    const reflector = {
      getAllAndOverride: jest.fn((_key: string) => {
        if (_key === 'nexuspanel:isPublic') return false;
        if (_key === 'nexuspanel:sessionOnly') return opts.sessionOnly ?? false;
        return opts.permission;
      }),
    } as unknown as Reflector;
    const req = { headers: {}, params: opts.params, auth: opts.auth };
    const ctx = {
      switchToHttp: () => ({ getRequest: () => req }),
      getHandler: () => ({}),
      getClass: () => ({}),
    } as unknown as Parameters<PermissionsGuard['canActivate']>[0];
    return { guard: new PermissionsGuard(reflector, prisma as never), req, ctx };
  }

  const tokenAuth = (scopes: string[]): AuthContext => ({
    userId: USER,
    sessionId: 'api-token:tok-1',
    tokenId: 'tok-1',
    tokenScopes: scopes,
    viaApiToken: true,
  });

  it('gate 1: @SessionOnly routes reject scoped tokens outright', async () => {
    const h = pHarness({
      permission: 'auth:tokens',
      sessionOnly: true,
      auth: tokenAuth(['auth:tokens']),
    });
    await expect(h.guard.canActivate(h.ctx)).rejects.toThrow(/interactive session/);
  });

  it('gate 2: missing scope → 403 even for a super-admin owner', async () => {
    const h = pHarness({
      permission: 'account:suspend',
      isSuperAdmin: true,
      auth: tokenAuth(['account:list']),
    });
    await expect(h.guard.canActivate(h.ctx)).rejects.toThrow(/lacks the 'account:suspend' scope/);
  });

  it('gate 2+3 pass: scoped token, super-admin owner → allowed', async () => {
    const h = pHarness({
      permission: 'account:suspend',
      isSuperAdmin: true,
      auth: tokenAuth(['account:suspend']),
    });
    await expect(h.guard.canActivate(h.ctx)).resolves.toBe(true);
  });

  it('gate 3: scoped token but plain user without grants → still denied', async () => {
    const h = pHarness({
      permission: 'audit:verify',
      auth: tokenAuth(['audit:verify']),
      accessRole: null,
    });
    await expect(h.guard.canActivate(h.ctx)).rejects.toThrow(ForbiddenException);
  });

  it('gate 3 via roles: scoped account:read token + owner access row → allowed', async () => {
    const h = pHarness({
      permission: 'account:read',
      auth: tokenAuth(['account:read']),
      accessRole: 'owner',
      params: { id: 'acc-1' },
    });
    await expect(h.guard.canActivate(h.ctx)).resolves.toBe(true);
  });

  it('session requests are unaffected by token gates (scope check skipped)', async () => {
    const h = pHarness({ permission: 'auth:logout', auth: { userId: USER, sessionId: 's1' } });
    await expect(h.guard.canActivate(h.ctx)).resolves.toBe(true);
  });
});
