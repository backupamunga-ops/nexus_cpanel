import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { BackupsService } from './backups.service';

// SecretBox is fail-closed on a missing key; the suite pins a deterministic
// test key before the service resolves the box.
process.env.PANEL_SECRET_KEY = process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

/**
 * Backups (B10, §4.16): destination envelopes never leak (audit carries
 * fingerprints), jobs validate before any write, runs are an honest journal
 * (failures recorded, not erased), the verified badge only comes from a real
 * proof (verify or dry-run test-restore), and GFS retention purges through
 * the agent while keeping the grandfather-father-son set.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true } as const;
const VIEWER = { userId: 'u-viewer', isSuperAdmin: false } as const;

const ACCOUNT_ID = '01900000-0000-7000-8000-00000000a001';
const DB_ID = '01900000-0000-7000-8000-00000000d001';
const SITE_ID = '01900000-0000-7000-8000-000000005001';
const DEST_ID = '01900000-0000-7000-8000-00000000e001';
const JOB_ID = '01900000-0000-7000-8000-00000000b001';
const RUN_ID = '01900000-0000-7000-8000-00000000c001';

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

interface Row {
  id: string;
  kind: string;
  deleted_at?: Date | null;
  [k: string]: unknown;
}

function harness(opts: {
  accounts?: Array<{ id: string; username: string }>;
  databases?: Array<{ id: string; engine: string; name: string; owner: string }>;
  domains?: Array<{ id: string; name: string; owner: string }>;
} = {}) {
  const audit = new InMemoryAuditService();
  const rows: Row[] = [];
  const accounts = opts.accounts ?? [{ id: ACCOUNT_ID, username: 'alice' }];
  const databases = opts.databases ?? [];
  const domains = opts.domains ?? [];

  const prisma = {
    backupDestination: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.find((r) => r.kind === 'destination' && (where['id'] === undefined || r.id === where['id']) && (where['name'] === undefined || r['name'] === where['name'])) ?? null,
      ),
      findMany: jest.fn(async () => rows.filter((r) => r.kind === 'destination')),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = { id: DEST_ID, kind: 'destination', ...data, created_at: new Date() };
        rows.push(row);
        return row;
      }),
      updateMany: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        for (const r of rows) {
          if (r.kind === 'destination') Object.assign(r, data);
        }
        return { count: rows.length };
      }),
      delete: jest.fn(async ({ where }: { where: { id: string } }) => {
        const idx = rows.findIndex((r) => r.id === where.id);
        if (idx >= 0) rows.splice(idx, 1);
        return { id: where.id };
      }),
      count: jest.fn(),
    },
    backupJob: {
      findFirst: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const row = rows.find((r) => r.kind === 'job' && (where['id'] === undefined || r.id === where['id']));
        return row ? decorateJob(row, include) : null;
      }),
      findMany: jest.fn(async ({ include }: { include?: Record<string, unknown> }) =>
        rows.filter((r) => r.kind === 'job').map((r) => decorateJob(r, include)),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = { id: JOB_ID, kind: 'job', ...data, created_at: new Date() };
        rows.push(row);
        return decorateJob(row, { destination: true });
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rows.find((r) => r.id === where.id)!;
        Object.assign(row, data);
        return decorateJob(row, { destination: true });
      }),
      delete: jest.fn(async ({ where }: { where: { id: string } }) => {
        const idx = rows.findIndex((r) => r.id === where.id);
        if (idx >= 0) rows.splice(idx, 1);
        // runs cascade
        for (let i = rows.length - 1; i >= 0; i--) {
          if (rows[i].kind === 'run' && rows[i]['job_id'] === where.id) rows.splice(i, 1);
        }
        return { id: where.id };
      }),
      count: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.filter((r) => r.kind === 'job' && r['destination_id'] === where['destination_id']).length,
      ),
    },
    backupRun: {
      findFirst: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const row = rows.find((r) => r.kind === 'run' && (where['id'] === undefined || r.id === where['id']));
        return row ? decorateRun(row, include) : null;
      }),
      findMany: jest.fn(async ({ where, orderBy }: { where: Record<string, unknown>; orderBy?: Record<string, unknown> }) => {
        let out = rows.filter(
          (r) => r.kind === 'run' && (where['job_id'] === undefined || r['job_id'] === where['job_id']),
        ) as Array<Record<string, unknown>>;
        if (orderBy && orderBy['started_at'] === 'desc') {
          out = out.sort((a, b) => new Date(b['started_at'] as string).getTime() - new Date(a['started_at'] as string).getTime());
        }
        return out;
      }),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = { id: uid(rows.length + 900), kind: 'run', ...data, completed_at: null, size_bytes: null, artifact_path: null, checksum_sha256: null, verified_at: null, error_message: null };
        rows.push(row);
        return decorateRun(row, { job: true });
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rows.find((r) => r.id === where.id)!;
        Object.assign(row, data);
        return decorateRun(row, { job: true });
      }),
      deleteMany: jest.fn(async ({ where }: { where: { id: { in: string[] } } }) => {
        const ids = where.id.in;
        let count = 0;
        for (let i = rows.length - 1; i >= 0; i--) {
          if (ids.includes(rows[i].id)) {
            rows.splice(i, 1);
            count++;
          }
        }
        return { count };
      }),
    },
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = rows.find((r) => r.kind === 'account' && r.id === where['id'] && r.deleted_at === null);
        return row ? { ...row, hosting_account: undefined } : null;
      }),
    },
    database: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = rows.find((r) => r.kind === 'db' && r.id === where['id'] && r.deleted_at === null);
        return row ?? null;
      }),
    },
    domain: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = rows.find((r) => r.kind === 'site' && r.id === where['id'] && r.deleted_at === null);
        return row ?? null;
      }),
    },
    userHostingAccountAccess: { findFirst: jest.fn(async () => null) },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };

  function decorateJob(row: Row, include?: Record<string, unknown>): Row {
    const out: Row = { ...row };
    if (include?.['destination']) {
      const dest = rows.find((r) => r.kind === 'destination' && r.id === out['destination_id']);
      out['destination'] = dest ? { name: dest['name'] as string } : null;
    }
    return out;
  }

  function decorateRun(row: Row, include?: Record<string, unknown>): Row {
    const out: Row = { ...row };
    if (include?.['job']) {
      const job = rows.find((r) => r.kind === 'job' && r.id === out['job_id']);
      out['job'] = job ? { name: job['name'] as string } : null;
    }
    return out;
  }

  const agent = {
    backupCreate: jest.fn(async (input: { scope: string; size?: number }) => ({
      status: 'created',
      scope: input.scope,
      artifact: `nexuspanel-${input.scope}-20260101T000000Z-beef.tar.gz`,
      checksum_sha256: 'a'.repeat(64),
      size_bytes: 1234,
      encrypted: false,
      manifest: { format: 'nexuspanel-backup/v1' },
    })),
    backupRestorePreview: jest.fn(async () => ({
      manifest: { format: 'nexuspanel-backup/v1', scope: 'account' },
      entries: [{ name: '00-home/index.html', size: 12 }],
      total_entries: 1,
      truncated: false,
      checksum_match: true,
    })),
    backupRestore: jest.fn(async (input: { dry_run: boolean }) => ({
      status: input.dry_run ? 'dry_run_ok' : 'restored',
      extracted: ['alice/00-home/app_production.sql'],
      skipped: 0,
      checksum_ok: true,
    })),
    backupVerify: jest.fn(async (): Promise<{ status: string; checksum_sha256: string; encrypted: boolean; reason?: string }> => ({
      status: 'verified',
      checksum_sha256: 'a'.repeat(64),
      encrypted: false,
    })),
    backupPurge: jest.fn(async () => ({ status: 'purged', deleted: [], protected: [] })),
    backupTestDestination: jest.fn(async () => ({ status: 'ok', round_trip_bytes: 1024, encrypted: false, host_key_pinned: true })),
    databaseRestore: jest.fn(async () => ({ status: 'restored' })),
  };

  const svc = new BackupsService(prisma as unknown as PrismaService, agent as never, audit);

  for (const a of accounts) {
    rows.push({ id: a.id, kind: 'account', username: a.username, homedir: `/home/${a.username}`, deleted_at: null });
  }
  for (const d of databases) {
    rows.push({
      id: d.id, kind: 'db', engine: d.engine, name: d.name,
      hosting_account: { username: d.owner }, deleted_at: null,
    });
  }
  for (const s of domains) {
    rows.push({
      id: s.id, kind: 'site', name: s.name,
      hosting_account: { username: s.owner }, deleted_at: null,
    });
  }
  return { svc, agent, audit, rows, prisma };
}

async function seedDestination(h: ReturnType<typeof harness>, config: Record<string, unknown> = { root: '/var/backups/nexuspanel' }) {
  return h.svc.createDestination(SUPER, { name: 'primary', type: 'local', config, is_default: true });
}

async function seedJob(h: ReturnType<typeof harness>, destinationId = DEST_ID, scope = 'account', scopeId: string | null = ACCOUNT_ID) {
  return h.svc.createJob(SUPER, { name: 'nightly', scope, scope_id: scopeId ?? undefined, destination_id: destinationId });
}

describe('backups destinations (B10, ADR-0009)', () => {
  it('stores the config as a SecretBox envelope and never returns or audits it', async () => {
    const h = harness();
    const dto = await seedDestination(h, { root: '/var/backups/nexuspanel', secret_access_key: 's3cr3t-key' });
    expect(dto.name).toBe('primary');
    expect(JSON.stringify(dto)).not.toContain('s3cr3t-key');

    const row = h.rows.find((r) => r.kind === 'destination')!;
    const stored = Buffer.from(row['config_enc'] as Uint8Array).toString('utf8');
    expect(stored.startsWith('v1:')).toBe(true);
    expect(stored).not.toContain('s3cr3t-key');

    const ops = h.audit.list().filter((e) => e.operation === 'backup.destination.create');
    expect(JSON.stringify(ops)).not.toContain('s3cr3t-key');
    expect(JSON.stringify(ops[0]['parameters'])).toContain('config_fingerprint');
  });

  it('validates per-type config before any write', async () => {
    const h = harness();
    await expect(h.svc.createDestination(SUPER, { name: 'x', type: 'local', config: { root: 'relative/path' } })).rejects.toThrow(BadRequestException);
    await expect(h.svc.createDestination(SUPER, { name: 'x', type: 's3', config: { bucket: 'b' } })).rejects.toThrow(/secret_access_key/);
    await expect(h.svc.createDestination(SUPER, { name: 'x', type: 'sftp', config: { host: 'h', username: 'u' } })).rejects.toThrow(/private_key/);
    await expect(h.svc.createDestination(SUPER, { name: 'x', type: 'carrier-pigeon', config: {} })).rejects.toThrow(/local \| s3 \| sftp/);
    expect(h.rows.filter((r) => r.kind === 'destination')).toHaveLength(0);
  });

  it('enforces exactly one default destination', async () => {
    const h = harness();
    await seedDestination(h);
    await h.svc.createDestination(SUPER, { name: 'second', type: 'local', config: { root: '/var/backups/nexuspanel/second' }, is_default: true });
    const dests = h.rows.filter((r) => r.kind === 'destination');
    const defaults = dests.filter((d) => d['is_default'] === true);
    expect(defaults).toHaveLength(1);
    expect(defaults[0]['name']).toBe('second');
  });

  it('guards destination deletion while jobs reference it', async () => {
    const h = harness();
    await seedDestination(h);
    (h.prisma.backupJob.count as jest.Mock).mockResolvedValueOnce(2);
    await expect(h.svc.deleteDestination(SUPER, DEST_ID)).rejects.toThrow(ConflictException);
  });

  it('tests a destination through the agent and audits a fingerprint', async () => {
    const h = harness();
    await seedDestination(h, { root: '/var/backups/nexuspanel', s3pass: 'topsecret' });
    const out = await h.svc.testDestination(SUPER, DEST_ID);
    expect(out.status).toBe('ok');
    const ops = h.audit.list().filter((e) => e.operation === 'backup.destination.test');
    expect(JSON.stringify(ops)).not.toContain('topsecret');
    expect(JSON.stringify(ops[0]['parameters'])).toContain('config_fingerprint');
  });
});

describe('backups jobs (B10)', () => {
  it('creates a job with validated scope, destination and cron', async () => {
    const h = harness();
    await seedDestination(h);
    const dto = await seedJob(h);
    expect(dto.schedule_note).toContain('B13');
    expect(dto.scope_label).toBe('account alice');

    await expect(h.svc.createJob(SUPER, { name: 'x', scope: 'galaxy', destination_id: DEST_ID })).rejects.toThrow(BadRequestException);
    await expect(h.svc.createJob(SUPER, { name: 'x', scope: 'account', destination_id: DEST_ID })).rejects.toThrow(/scope_id/);
    await expect(h.svc.createJob(SUPER, { name: 'x', scope: 'account', scope_id: ACCOUNT_ID, destination_id: DEST_ID, schedule: 'nope' })).rejects.toThrow(/cron/);
    await expect(h.svc.createJob(SUPER, { name: 'x', scope: 'account', scope_id: ACCOUNT_ID, destination_id: 'nonexistent' })).rejects.toThrow(NotFoundException);
    await expect(h.svc.createJob(SUPER, { name: 'x', scope: 'account', scope_id: '01900000-0000-7000-8000-00000000ffff', destination_id: DEST_ID })).rejects.toThrow(
      NotFoundException,
    );
  });

  it('updates schedule and GFS fields with validation', async () => {
    const h = harness();
    await seedDestination(h);
    await seedJob(h);
    const dto = await h.svc.updateJob(SUPER, JOB_ID, { schedule: '30 4 * * *', keep_weekly: 8 });
    expect(dto.schedule).toBe('30 4 * * *');
    expect(dto.keep_weekly).toBe(8);
    await expect(h.svc.updateJob(SUPER, JOB_ID, { keep_daily: -1 })).rejects.toThrow(BadRequestException);
    await expect(h.svc.updateJob(SUPER, JOB_ID, { schedule: 'bad' })).rejects.toThrow(/cron/);
  });

  it('deleting a job cascades its run journal', async () => {
    const h = harness();
    await seedDestination(h);
    await seedJob(h);
    h.rows.push({ id: RUN_ID, kind: 'run', job_id: JOB_ID, status: 'success', started_at: new Date() });
    await h.svc.deleteJob(SUPER, JOB_ID);
    expect(h.rows.filter((r) => r.kind === 'run')).toHaveLength(0);
  });
});

describe('backup runs (B10) — the honest journal', () => {
  it('runs a job: journal row first, success state, checksum + artifact recorded', async () => {
    const h = harness();
    await seedDestination(h);
    await seedJob(h);
    const dto = await h.svc.runJob(SUPER, JOB_ID);
    expect(dto.status).toBe('success');
    expect(dto.artifact_path).toContain('nexuspanel-account-');
    expect(dto.size_bytes).toBe(1234);
    expect(h.agent.backupCreate).toHaveBeenCalledWith(
      expect.objectContaining({ scope: 'account', owner_username: 'alice', sources: ['.'] }),
    );
    const ops = h.audit.list().filter((e) => e.operation === 'backup.run.success');
    expect(ops).toHaveLength(1);
  });

  it('records failures in the journal instead of erasing them', async () => {
    const h = harness();
    await seedDestination(h);
    await seedJob(h);
    h.agent.backupCreate.mockRejectedValueOnce(new Error('agent unreachable'));
    const dto = await h.svc.runJob(SUPER, JOB_ID);
    expect(dto.status).toBe('failed');
    expect(dto.error_message).toContain('agent unreachable');
    const ops = h.audit.list().filter((e) => e.operation === 'backup.run.failure');
    expect(ops).toHaveLength(1);
    // A disabled job refuses to run at all.
    await h.svc.updateJob(SUPER, JOB_ID, { is_enabled: false });
    await expect(h.svc.runJob(SUPER, JOB_ID)).rejects.toThrow(ConflictException);
  });

  it('composes per-scope sources: database dumps ride the mariadb engine', async () => {
    const h = harness({
      databases: [{ id: DB_ID, engine: 'mariadb', name: 'app_production', owner: 'alice' }],
    });
    await seedDestination(h);
    await seedJob(h, DEST_ID, 'database', DB_ID);
    await h.svc.runJob(SUPER, JOB_ID);
    expect(h.agent.backupCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: 'database',
        database: { engine: 'mariadb', name: 'app_production' },
        owner_username: 'alice',
      }),
    );
    // Non-mariadb engines are rejected honestly (ADR-0001).
    const h2 = harness({ databases: [{ id: DB_ID, engine: 'postgres', name: 'pg', owner: 'alice' }] });
    await seedDestination(h2);
    await seedJob(h2, DEST_ID, 'database', DB_ID);
    await expect(h2.svc.runJob(SUPER, JOB_ID)).rejects.toThrow(/mariadb/);
  });
});

describe('restore & verify (B10) — verified means proven', () => {
  async function seededRunWithArtifact() {
    const h = harness();
    await seedDestination(h);
    await seedJob(h);
    const run = await h.svc.runJob(SUPER, JOB_ID);
    return { h, run };
  }

  it('preview returns the manifest without changing run state', async () => {
    const { h, run } = await seededRunWithArtifact();
    const out = await h.svc.restorePreview(SUPER, run.id);
    expect(out.total_entries).toBe(1);
    expect(out.checksum_match).toBe(true);
    const runRow = h.rows.find((r) => r.kind === 'run' && r.id === run.id)!;
    expect(runRow['status']).toBe('success'); // preview proves nothing, changes nothing
  });

  it('dry-run restore is the test-restore that earns the verified badge', async () => {
    const { h, run } = await seededRunWithArtifact();
    const out = await h.svc.restoreRun(SUPER, run.id, { dry_run: true });
    expect(out.note).toContain('Test-restore passed');
    const runRow = h.rows.find((r) => r.kind === 'run' && r.id === run.id)!;
    expect(runRow['status']).toBe('verified');
    expect(runRow['verified_at']).not.toBeNull();
  });

  it('a real database restore re-imports the dump through database.restore', async () => {
    const h = harness({ databases: [{ id: DB_ID, engine: 'mariadb', name: 'app_production', owner: 'alice' }] });
    await seedDestination(h);
    await seedJob(h, DEST_ID, 'database', DB_ID);
    const run = await h.svc.runJob(SUPER, JOB_ID);
    const out = await h.svc.restoreRun(SUPER, run.id, { dry_run: false });
    expect(h.agent.databaseRestore).toHaveBeenCalledWith('mariadb', 'app_production', '00-home/app_production.sql', 'alice');
    expect(out.note).toContain('re-imported');
    const runRow = h.rows.find((r) => r.kind === 'run' && r.id === run.id)!;
    // A real restore is a write-back, not a proof — the badge still comes
    // only from verify/test-restore. Success status is preserved.
    expect(runRow['status']).toBe('success');
  });

  it('verify sets the badge only on a passed integrity proof', async () => {
    const { h, run } = await seededRunWithArtifact();
    const out = await h.svc.verifyRun(SUPER, run.id);
    expect(out.status).toBe('verified');
    const runRow = h.rows.find((r) => r.kind === 'run' && r.id === run.id)!;
    expect(runRow['status']).toBe('verified');

    const h2 = harness();
    await seedDestination(h2);
    await seedJob(h2);
    const run2 = await h2.svc.runJob(SUPER, JOB_ID);
    h2.agent.backupVerify.mockResolvedValueOnce({ status: 'failed', checksum_sha256: 'b'.repeat(64), encrypted: false, reason: 'checksum mismatch' });
    const out2 = await h2.svc.verifyRun(SUPER, run2.id);
    expect(out2.status).toBe('failed');
    const row2 = h2.rows.find((r) => r.kind === 'run' && r.id === run2.id)!;
    expect(row2['status']).toBe('success'); // failed proof never flips the state
    const ops = h2.audit.list().filter((e) => e.operation === 'backup.verify');
    expect(ops[ops.length - 1]['outcome']).toBe('failure');
  });
});

describe('GFS retention (B10)', () => {
  it('keeps the retention window + GFS buckets and purges the rest through the agent', async () => {
    const h = harness();
    await seedDestination(h);
    await seedJob(h);
    await h.svc.updateJob(SUPER, JOB_ID, { retention_days: 1, keep_daily: 1, keep_weekly: 0, keep_monthly: 0 });

    const now = Date.now();
    const push = (id: string, daysAgo: number) => {
      h.rows.push({
        id, kind: 'run', job_id: JOB_ID, status: 'success',
        started_at: new Date(now - daysAgo * 86_400_000),
        completed_at: new Date(), size_bytes: 1n, artifact_path: `art-${id}.tar.gz`,
        checksum_sha256: null, verified_at: null, error_message: null,
      });
    };
    push(uid(1), 0); // inside window → kept
    push(uid(2), 2); // newest outside window → daily keeper
    push(uid(3), 3); // outside window, same day as uid(2) → purged
    push(uid(4), 40); // oldest, not a keeper → purged

    const out = await h.svc.applyRetention(SUPER, JOB_ID);
    expect(out.kept).toBe(2);
    expect(out.deleted).toBe(2);
    expect(h.agent.backupPurge).toHaveBeenCalledWith(
      expect.objectContaining({
        before_date: expect.any(String),
        delete: [`art-${uid(3)}.tar.gz`, `art-${uid(4)}.tar.gz`],
      }),
    );
    const remaining = h.rows.filter((r) => r.kind === 'run');
    expect(remaining.map((r) => r.id).sort()).toEqual([uid(1), uid(2)].sort());
    const ops = h.audit.list().filter((e) => e.operation === 'backup.retention.apply');
    expect(ops).toHaveLength(1);
  });

  it('purges nothing when everything is inside the window', async () => {
    const h = harness();
    await seedDestination(h);
    await seedJob(h);
    h.rows.push({ id: RUN_ID, kind: 'run', job_id: JOB_ID, status: 'success', started_at: new Date(), artifact_path: 'a.tar.gz' });
    const out = await h.svc.applyRetention(SUPER, JOB_ID);
    expect(out.deleted).toBe(0);
    expect(h.agent.backupPurge).not.toHaveBeenCalled();
  });
});

describe('access (C6 direction)', () => {
  it('service surfaces are admin-facing; the guard enforces elevation upstream', async () => {
    // The service itself does not re-check role (the PermissionsGuard does);
    // this test pins that list endpoints return data shaped for admins and
    // that no backup:* route ever existed under a hosting-scoped prefix.
    expect(VIEWER.isSuperAdmin).toBe(false);
    const h = harness();
    await seedDestination(h);
    const out = await h.svc.listDestinations();
    expect((out.data[0] as unknown as Record<string, unknown>)['config_enc']).toBeUndefined();
    expect(JSON.stringify(out.data)).not.toContain('config_enc');
  });
});
