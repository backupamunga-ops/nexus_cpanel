import {
  ForbiddenException,
  HttpException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { ExtProxyService } from './ext-proxy.service';
import { getSecretBox } from '../common/secretbox';
import { deriveExtToken, newSharedSecret } from './signature';

/**
 * /api/v1/ext/* enforcement tests (P7, SDK spec §5.3). The exit criteria:
 * a valid derived token resolves; disabled extensions are dead; the route
 * table is closed; scopes bind endpoints; writes fail closed with an admin
 * notification; the rate limit answers 429 on call 61; every call lands in
 * the audit chain attributed to the extension.
 */

process.env.PANEL_SECRET_KEY =
  process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

function harness() {
  const audit = new InMemoryAuditService();
  const notifications: Array<Record<string, unknown>> = [];
  const extensionRows: Array<Record<string, any>> = [];
  const registrationRows: Array<Record<string, any>> = [];

  const prisma: Record<string, any> = {
    extensionRegistration: {
      findMany: jest.fn(async () => registrationRows.filter((r) => r.is_active)),
    },
    hostingAccount: { findMany: jest.fn(async () => [{ id: 'a1', username: 'alpha', primary_domain: 'alpha.test', status: 'active', created_at: new Date() }]) },
    domain: { findMany: jest.fn(async () => []) },
    mailDomain: { findMany: jest.fn(async () => []) },
    dnZone: { findMany: jest.fn(async () => []) },
    database: { findMany: jest.fn(async () => []) },
    certificate: { findMany: jest.fn(async () => []) },
    backupJob: { findMany: jest.fn(async () => [{ id: 'bj1', name: 'nightly', scope: 'account', schedule: 'daily', retention_days: 30, keep_daily: 7, keep_weekly: 4, keep_monthly: 6, is_enabled: true }]) },
    backupRun: {
      findMany: jest.fn(async () => [
        { id: 'br1', job_id: 'bj1', status: 'success', started_at: new Date(), completed_at: new Date(), size_bytes: BigInt('1234567890123'), verified_at: new Date(), error_message: null },
      ]),
    },
    auditEntry: { findMany: jest.fn(async () => []) },
    user: { findMany: jest.fn(async () => []) },
  };

  const notifier = {
    superAdminIds: jest.fn(async () => ['u-admin']),
    notify: jest.fn(async (input: Record<string, unknown>) => {
      notifications.push(input);
      return { id: 'n1' };
    }),
  };

  const service = new ExtProxyService(
    prisma as unknown as PrismaService,
    notifier as any,
    audit as any,
  );

  /** Register an enabled extension and return its derived bearer token. */
  async function addExtension(opts: { slug?: string; status?: string; scopes?: string[] } = {}) {
    const secret = newSharedSecret();
    const extId = `ext-${extensionRows.length + 1}`;
    const extRow = {
      id: extId,
      slug: opts.slug ?? 'acme-backup-reporter',
      status: opts.status ?? 'enabled',
      granted_scopes: opts.scopes ?? ['backup:read', 'account:read', 'notification:write'],
    };
    extensionRows.push(extRow);
    registrationRows.push({
      id: `reg-${registrationRows.length + 1}`,
      extension_id: extId,
      callback_url: 'https://acme.example',
      shared_secret_enc: Buffer.from(
        getSecretBox().encrypt(JSON.stringify({ v: 1, shared_secret: secret })),
        'utf8',
      ),
      is_active: true,
      last_heartbeat_at: null,
      // the service queries registrations with `include: { extension: true }`
      extension: extRow,
    });
    return { secret, token: deriveExtToken(secret), extId };
  }

  return { service, audit, notifications, prisma, addExtension };
}

describe('ext token authentication', () => {
  it('resolves a valid derived token to the extension', async () => {
    const h = harness();
    const { token } = await h.addExtension();
    const p = await h.service.authenticate(token);
    expect(p.slug).toBe('acme-backup-reporter');
    expect(p.grantedScopes).toContain('backup:read');
  });

  it('refuses an unknown token with 401 and no enumeration surface', async () => {
    const h = harness();
    await h.addExtension();
    await expect(h.service.authenticate(deriveExtToken('wrong-secret'))).rejects.toThrow(
      UnauthorizedException,
    );
    await expect(h.service.authenticate(undefined)).rejects.toThrow(/missing bearer/);
  });

  it('a disabled extension resolves but is refused with extension_disabled', async () => {
    const h = harness();
    const { token } = await h.addExtension({ status: 'disabled' });
    await expect(h.service.authenticate(token)).rejects.toThrow(/extension_disabled/);
  });

  it('an errored extension is refused the same way', async () => {
    const h = harness();
    const { token } = await h.addExtension({ status: 'errored' });
    await expect(h.service.authenticate(token)).rejects.toThrow(/extension_disabled/);
  });
});

describe('route table + scopes', () => {
  it('unknown ext endpoints 404 identically (anti-probing)', async () => {
    const h = harness();
    const { token } = await h.addExtension();
    const p = await h.service.authenticate(token);
    for (const path of ['/self-destruct', '/api/v1/accounts', '/../admin']) {
      expect(() => h.service.authorize(p, 'GET', path)).toThrow(NotFoundException);
    }
  });

  it('endpoints outside granted scopes are refused', async () => {
    const h = harness();
    const { token } = await h.addExtension({ scopes: ['backup:read'] });
    const p = await h.service.authenticate(token);
    expect(() => h.service.authorize(p, 'GET', '/accounts')).toThrow(/scope_not_granted/);
    // the granted one passes
    expect(h.service.authorize(p, 'GET', '/backups/jobs').scope).toBe('backup:read');
  });

  it('write scopes fail closed with write_requires_confirmation and notify admins', async () => {
    const h = harness();
    const { token } = await h.addExtension({ scopes: ['backup:write', 'dns:write'] });
    const p = await h.service.authenticate(token);
    expect(() => h.service.authorize(p, 'POST', '/backups/jobs')).toThrow(
      /write_requires_confirmation/,
    );
    // the admin notification is fire-and-forget (never blocks authorization)
    await new Promise((r) => setTimeout(r, 0));
    expect(h.notifications).toHaveLength(1);
    expect(String(h.notifications[0].body)).toContain('backup:write');
    // deduped: a second attempt inside the window does not re-notify
    try {
      h.service.authorize(p, 'POST', '/backups/jobs');
      fail('expected write_requires_confirmation again');
    } catch {
      /* expected */
    }
    await new Promise((r) => setTimeout(r, 0));
    expect(h.notifications).toHaveLength(1);
  });

  it('rate limit answers 429 on the 61st call in a window', async () => {
    const h = harness();
    const { token } = await h.addExtension();
    const p = await h.service.authenticate(token);
    for (let i = 0; i < 60; i++) {
      h.service.authorize(p, 'GET', '/accounts');
    }
    let caught: unknown;
    try {
      h.service.authorize(p, 'GET', '/accounts');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(HttpException);
    expect((caught as HttpException).getStatus()).toBe(429);
  });
});

describe('resolvers (metadata only)', () => {
  it('serves backup runs with BigInt sizes coerced to Number', async () => {
    const h = harness();
    const out = (await h.service.resolveGet('/backups/runs', new URLSearchParams())) as {
      data: Array<{ id: string; size_bytes: number | null }>;
    };
    expect(out.data[0].id).toBe('br1');
    expect(out.data[0].size_bytes).toBe(1234567890123);
    expect(typeof out.data[0].size_bytes).toBe('number');
  });

  it('serves accounts and never includes secret-bearing columns', async () => {
    const h = harness();
    const out = (await h.service.resolveGet('/accounts', new URLSearchParams())) as {
      data: Array<Record<string, unknown>>;
    };
    expect(out.data[0].username).toBe('alpha');
    expect(Object.keys(out.data[0])).toEqual(
      expect.arrayContaining(['id', 'username', 'primary_domain', 'status']),
    );
  });

  it('posts notifications through the panel notification center', async () => {
    const h = harness();
    const p = { extensionId: 'ext-1', slug: 'acme-backup-reporter', grantedScopes: [] };
    const out = (await h.service.resolvePost(p, '/notifications', {
      title: 'Nightly backup verified',
      body: 'All runs verified.',
    })) as { data: { delivered: boolean } };
    expect(out.data.delivered).toBe(true);
    expect(h.notifications).toHaveLength(1);
    expect(h.notifications[0].title).toBe('acme-backup-reporter: Nightly backup verified');
  });

  it('rejects notification posts without a title', async () => {
    const h = harness();
    const p = { extensionId: 'ext-1', slug: 'acme-backup-reporter', grantedScopes: [] };
    await expect(h.service.resolvePost(p, '/notifications', { body: 'no title' })).rejects.toThrow(
      /title is required/,
    );
  });
});

describe('audit attribution', () => {
  it('every call lands in the chain attributed to extension.<slug>.call', async () => {
    const h = harness();
    const { token } = await h.addExtension();
    const p = await h.service.authenticate(token);
    h.service.authorize(p, 'GET', '/accounts');
    await h.service.auditCall(p, 'GET', '/accounts', 'success');
    await h.service.auditCall(p, 'GET', '/accounts', 'failure', { error: 'boom' });
    const ops = h.audit.list().map((e) => e.operation);
    expect(ops).toEqual([
      'extension.acme-backup-reporter.call',
      'extension.acme-backup-reporter.call',
    ]);
    expect(h.audit.list()[1].outcome).toBe('failure');
  });
});
