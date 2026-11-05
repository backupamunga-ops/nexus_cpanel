import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { DatabasesService } from './databases.service';

// SecretBox is fail-closed on a missing key; the suite pins a deterministic
// test key before the service resolves the box.
process.env.PANEL_SECRET_KEY = process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

/**
 * Databases (B09, ADR-0001/0015): engine lock, agent-first provisioning,
 * package limits, SecretBox credentials at rest (never in audit payloads),
 * session-only credential surfaces tested at the service level, C7 404s.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true } as const;
const VIEWER = { userId: 'u-viewer', isSuperAdmin: false } as const;

const ACCOUNT_ID = '01900000-0000-7000-8000-00000000a001';
const DB_ID = '01900000-0000-7000-8000-00000000b001';

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

interface Row {
  id: string;
  kind?: string;
  deleted_at: Date | null;
  [k: string]: unknown;
}

function harness(opts: {
  accessRows?: Array<{ user_id: string; hosting_account_id: string }>;
  packageRow?: { quotas: Record<string, unknown> } | null;
} = {}) {
  const audit = new InMemoryAuditService();
  const rows: Row[] = [];
  const accessRows = opts.accessRows ?? [];
  const packageRow = opts.packageRow ?? null;

  const prisma = {
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = rows.find((r) => r.kind === 'account' && r.id === where['id'] && r.deleted_at === null);
        return row ? { ...row, hosting_account: undefined } : null;
      }),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        accessRows.find((a) => a.user_id === where['user_id'] && a.hosting_account_id === where['hosting_account_id']) ?? null,
      ),
    },
    package: {
      findFirst: jest.fn(async () => packageRow),
    },
    database: {
      findFirst: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const row = rows.find(
          (r) =>
            r.kind === 'db' &&
            (where['id'] === undefined || r.id === where['id']) &&
            (where['engine'] === undefined || r['engine'] === where['engine']) &&
            (where['name'] === undefined || r['name'] === where['name']) &&
            r.deleted_at === null,
        );
        return row ? decorate(row, include) : null;
      }),
      findMany: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) =>
        rows
          .filter((r) => r.kind === 'db' && r['hosting_account_id'] === where['hosting_account_id'] && r.deleted_at === null)
          .map((r) => decorate(r, include)),
      ),
      count: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.filter((r) => r.kind === 'db' && r['hosting_account_id'] === where['hosting_account_id'] && r.deleted_at === null).length,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = { id: uid(rows.length + 400), kind: 'db', ...data, created_at: new Date(), deleted_at: null };
        rows.push(row);
        return decorate(row);
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rows.find((r) => r.id === where.id)!;
        Object.assign(row, data);
        return decorate(row);
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };

  function decorate(row: Row, include?: Record<string, unknown>): Row {
    const out: Row = { ...row };
    if (include?.['hosting_account'] || out.kind === 'account' || out.kind === 'db') {
      out['hosting_account'] = {
        id: ACCOUNT_ID,
        username: 'alice',
        homedir: '/home/alice',
        package_id: packageRow ? '01900000-0000-7000-8000-00000000p001' : null,
      };
    }
    return out;
  }

  const agent = {
    databaseCreate: jest.fn(async (input: { engine: string; name: string; user: string }) => ({
      status: 'created',
      engine: input.engine,
      name: input.name,
      user: input.user,
      host: 'localhost',
    })),
    databaseDelete: jest.fn(async () => ({ status: 'removed' })),
    databaseSize: jest.fn(async () => ({ engine: 'mariadb', name: 'x', size_bytes: 5242880, size_mb: 5 })),
    databaseDump: jest.fn(async (_engine: string, _name: string, outputPath: string) => ({
      status: 'dumped',
      output: `/home/alice/${outputPath}`,
    })),
    databaseRestore: jest.fn(async () => ({ status: 'restored' })),
  };

  const svc = new DatabasesService(prisma as unknown as PrismaService, agent as never, audit);
  rows.push({ id: ACCOUNT_ID, kind: 'account', username: 'alice', homedir: '/home/alice', package_id: packageRow ? 'pkg' : null, deleted_at: null });
  return { svc, agent, audit, rows };
}

async function seedDb(h: ReturnType<typeof harness>, name = 'app_production') {
  return h.svc.create(SUPER, { account_id: ACCOUNT_ID, engine: 'mariadb', name });
}

describe('databases (B09, ADR-0015)', () => {
  it('creates agent-first with the engine locked to mariadb; mysql/postgres rejected honestly', async () => {
    const h = harness();
    const dto = await seedDb(h);
    expect(dto.engine).toBe('mariadb');
    expect(dto.name).toBe('app_production');
    expect(h.agent.databaseCreate).toHaveBeenCalledWith(
      expect.objectContaining({ engine: 'mariadb', name: 'app_production', host: 'localhost' }),
    );

    for (const engine of ['mysql', 'postgres', '']) {
      await expect(h.svc.create(SUPER, { account_id: ACCOUNT_ID, engine, name: 'other' })).rejects.toThrow(BadRequestException);
    }
    expect(h.agent.databaseCreate).toHaveBeenCalledTimes(1);
  });

  it('stores the credential as a SecretBox envelope, never plaintext, never in audit', async () => {
    const h = harness();
    const dto = await seedDb(h);
    const row = h.rows.find((r) => r.kind === 'db')!;
    const stored = Buffer.from(row['db_password_hash'] as Uint8Array).toString('utf8');
    expect(stored.startsWith('v1:')).toBe(true);
    expect(stored).not.toContain('s3cret');

    const ops = h.audit.list().filter((e) => e.operation === 'database.create');
    expect(JSON.stringify(ops)).not.toContain('s3cret');
    expect(JSON.stringify(ops[0]['parameters'])).toContain('credential_fingerprint');

    // Decrypt at point of use: the connection string carries it; audit does not.
    const cs = await h.svc.connectionString(SUPER, dto.id);
    expect(cs.connection_string).toContain(`mysql://${dto.db_user}:`);
    expect(cs.connection_string).toContain('@localhost:3306/app_production');
    expect(JSON.stringify(h.audit.list())).not.toContain(cs.connection_string);
  });

  it('generates a server-side password when none is provided', async () => {
    const h = harness();
    const dto = await seedDb(h);
    expect(dto.db_user).toBe('alice_app_production'.slice(0, 32));
    const row = h.rows.find((r) => r.kind === 'db')!;
    const stored = Buffer.from(row['db_password_hash'] as Uint8Array).toString('utf8');
    expect(stored.startsWith('v1:')).toBe(true);
  });

  it('enforces package limits (db_count) and duplicate names', async () => {
    const h = harness({ packageRow: { quotas: { db_count: 1 } } });
    await seedDb(h);
    await expect(h.svc.create(SUPER, { account_id: ACCOUNT_ID, engine: 'mariadb', name: 'second_db' })).rejects.toThrow(
      /caps the account at 1 databases/,
    );
    expect(h.agent.databaseCreate).toHaveBeenCalledTimes(1);

    const h2 = harness();
    await seedDb(h2, 'dup_name');
    await expect(h2.svc.create(SUPER, { account_id: ACCOUNT_ID, engine: 'mariadb', name: 'dup_name' })).rejects.toThrow(
      ConflictException,
    );
  });

  it('rejects bad names/users/hosts before the agent call', async () => {
    const h = harness();
    await expect(h.svc.create(SUPER, { account_id: ACCOUNT_ID, engine: 'mariadb', name: '9bad' })).rejects.toThrow(BadRequestException);
    await expect(h.svc.create(SUPER, { account_id: ACCOUNT_ID, engine: 'mariadb', name: 'ok', db_user: 'Bad!' })).rejects.toThrow(
      BadRequestException,
    );
    await expect(h.svc.create(SUPER, { account_id: ACCOUNT_ID, engine: 'mariadb', name: 'ok', host: 'bad host;' })).rejects.toThrow(
      BadRequestException,
    );
    expect(h.agent.databaseCreate).not.toHaveBeenCalled();
  });

  it('leaves no row when the agent fails and audits the failure', async () => {
    const h = harness();
    h.agent.databaseCreate.mockRejectedValueOnce(new Error('agent unreachable'));
    await expect(h.svc.create(SUPER, { account_id: ACCOUNT_ID, engine: 'mariadb', name: 'doomed' })).rejects.toThrow('agent unreachable');
    expect(h.rows.filter((r) => r.kind === 'db')).toHaveLength(0);
    const ops = h.audit.list().filter((e) => e.operation === 'database.create');
    expect(ops[0]['outcome']).toBe('failure');
  });

  it('removes through the agent then soft-deletes', async () => {
    const h = harness();
    const dto = await seedDb(h);
    await h.svc.remove(SUPER, dto.id, {});
    expect(h.agent.databaseDelete).toHaveBeenCalledWith('mariadb', 'app_production', dto.db_user, 'localhost');
    const row = h.rows.find((r) => r.kind === 'db') as Record<string, unknown>;
    expect(row['deleted_at']).not.toBeNull();
  });

  it('protects the primary user from user-level delete', async () => {
    const h = harness();
    const dto = await seedDb(h);
    await expect(h.svc.deleteUser(SUPER, dto.id, dto.db_user, 'localhost')).rejects.toThrow(ConflictException);
  });

  it('refreshes size live and caches it on the row', async () => {
    const h = harness();
    const dto = await seedDb(h);
    const out = await h.svc.refreshSize(SUPER, dto.id);
    expect(out.size_mb).toBe(5);
    const row = h.rows.find((r) => r.kind === 'db') as Record<string, unknown>;
    expect(row['size_mb']).toBe(5);
  });

  it('dump/restore confine to the account home and audit', async () => {
    const h = harness();
    const dto = await seedDb(h);
    const out = await h.svc.dump(SUPER, dto.id, { output_path: 'backups/dump.sql' });
    expect(out.output_path).toContain('/home/alice/backups/dump.sql');
    await h.svc.restore(SUPER, dto.id, { input_path: 'backups/dump.sql' });
    await expect(h.svc.dump(SUPER, dto.id, { output_path: '../escape.sql' })).rejects.toThrow(BadRequestException);
    const ops = h.audit.list().filter((e) => e.operation === 'database.dump');
    expect(ops).toHaveLength(1);
  });

  it('issues an SSO token that is signed, short-TTL, and honestly annotated', async () => {
    const h = harness();
    const dto = await seedDb(h);
    const out = await h.svc.phpmyadminSso(SUPER, dto.id);
    expect(out.token).toContain('.');
    expect(new Date(out.expires_at).getTime() - Date.now()).toBeLessThanOrEqual(61_000);
    expect(out.consumer).toContain('B14');
  });

  it('404s invisible databases for non-admin users (C7)', async () => {
    const h = harness({ accessRows: [] });
    const dto = await seedDb(h);
    await expect(h.svc.list(VIEWER, ACCOUNT_ID)).rejects.toThrow(NotFoundException);
    await expect(h.svc.refreshSize(VIEWER, dto.id)).rejects.toThrow(NotFoundException);
  });
});
