import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { MigrationsService } from './migrations.service';
import { parseZoneFile } from './zonefile';

// SecretBox is fail-closed on a missing key; the suite pins a deterministic
// test key before the service resolves the box.
process.env.PANEL_SECRET_KEY = process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

/**
 * Migration Center (B15, §4.21 / M15): the phase machine never lies —
 * analyze is read-only, the dry-run performs zero writes, execute is
 * resumable and journals every entity, ANY failed verification fails the
 * job overall (no partial-success dressing), skips are always explicit and
 * reason-coded, and artifact password hashes are never imported (mailboxes
 * and DB users get fresh secrets).
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true } as const;
const ACCOUNT_ID = '01900000-0000-7000-8000-00000000a001';
const JOB_ID = '01900000-0000-7000-8000-00000000b001';
const ARTIFACT = 'cpmove-olduser.tar.gz';
const PREFIX = 'cpmove-olduser';
const ART_SHA = 'b'.repeat(64);

const ANALYSIS = {
  artifact: ARTIFACT,
  size_bytes: 4096,
  sha256: ART_SHA,
  prefix: PREFIX,
  entry_count: 9,
  entities: [
    { type: 'files', source_id: 'homedir/public_html', size_bytes: 28, count: 2 },
    { type: 'dns_zone', source_id: 'olduser.com', size_bytes: 32, sha256: 'c'.repeat(64) },
    { type: 'mail_domain', source_id: 'olduser.com' },
    { type: 'mailbox', source_id: 'olduser.com/alice' },
    { type: 'database', source_id: 'olduser_wp.sql', size_bytes: 59, sha256: 'd'.repeat(64) },
    { type: 'ssl', source_id: 'olduser.com.crt', size_bytes: 64, sha256: 'e'.repeat(64) },
    { type: 'cron', source_id: 'olduser.cron', size_bytes: 26, sha256: 'f'.repeat(64) },
  ],
};

const ZONE_FILE = [
  '; cPanel firstzone',
  '$TTL 86400',
  'olduser.com. 86400 IN SOA ns1.olduser.com. root.olduser.com. (',
  '  2026110501 7200 3600 1209600 86400 )',
  'olduser.com. 86400 IN NS ns1.olduser.com.',
  'olduser.com. 14400 IN A 203.0.113.10',
  'www 14400 IN CNAME olduser.com.',
  'olduser.com. 14400 IN MX 10 mail.olduser.com.',
  'olduser.com. 14400 IN TXT "v=spf1 a mx ~all"',
  'olduser.com. 14400 IN TYPE65 \\# 12 000102030405060708090A0B',
].join('\n');

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

interface MapRow {
  id: string;
  migration_job_id: string;
  entity_type: string;
  source_id: string;
  target_id: string | null;
  status: string;
  checksum_source: Uint8Array | null;
  checksum_target: Uint8Array | null;
  notes: string | null;
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

function harness(opts: { accounts?: Array<{ id: string; username: string; status?: string }>; zones?: string[]; mailDomains?: string[]; databases?: string[] } = {}) {
  const audit = new InMemoryAuditService();
  const accounts = opts.accounts ?? [{ id: ACCOUNT_ID, username: 'olduser', status: 'active' }];
  const mappings: MapRow[] = [];
  const jobs: Array<Record<string, unknown>> = [];
  const dbRows: Array<Record<string, unknown>> = [];
  const zoneRows: Array<Record<string, unknown>> = (opts.zones ?? []).map((name, i) => ({
    id: uid(500 + i),
    hosting_account_id: ACCOUNT_ID,
    name,
    deleted_at: null,
    dns_records__zone_id: [],
  }));
  const mailDomainRows: Array<Record<string, unknown>> = (opts.mailDomains ?? []).map((name, i) => ({ id: uid(600 + i), name, deleted_at: null }));
  const mailboxRows: Array<Record<string, unknown>> = [];

  let mapSeq = 1;
  let jobSeq = 1;

  const prisma = {
    migrationJob: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: JOB_ID, started_at: new Date(), completed_at: null, error_message: null, ...data };
        jobs.push(row);
        return row;
      }),
      findUnique: jest.fn(async ({ where }: { where: { id: string } }) => jobs.find((j) => j.id === where.id) ?? null),
      findMany: jest.fn(async () => jobs.map((j) => ({ ...j, target_account: accounts.find((a) => a.id === j['target_account_id']) ?? null }))),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = jobs.find((j) => j.id === where.id)!;
        Object.assign(row, data);
        return row;
      }),
      delete: jest.fn(async ({ where }: { where: { id: string } }) => {
        const idx = jobs.findIndex((j) => j.id === where.id);
        if (idx >= 0) jobs.splice(idx, 1);
        for (let i = mappings.length - 1; i >= 0; i--) {
          if (mappings[i].migration_job_id === where.id) mappings.splice(i, 1);
        }
        return { id: where.id };
      }),
      count: jest.fn(async () => jobs.length),
    },
    migrationEntityMapping: {
      createMany: jest.fn(async ({ data }: { data: Array<Partial<MapRow>> }) => {
        for (const d of data) {
          mappings.push({
            id: uid(mapSeq++),
            migration_job_id: (d.migration_job_id as string) ?? '',
            entity_type: (d.entity_type as string) ?? '',
            source_id: (d.source_id as string) ?? '',
            target_id: (d.target_id as string | null) ?? null,
            status: (d.status as string) ?? 'pending',
            checksum_source: (d.checksum_source as Uint8Array | null) ?? null,
            checksum_target: (d.checksum_target as Uint8Array | null) ?? null,
            notes: (d.notes as string | null) ?? null,
          });
        }
        return { count: data.length };
      }),
      findMany: jest.fn(async ({ where, orderBy }: { where?: Record<string, unknown>; orderBy?: unknown } = {}) => {
        let out = mappings.filter((m) => {
          if (where?.['migration_job_id'] !== undefined && m.migration_job_id !== where['migration_job_id']) return false;
          if (where?.['status'] !== undefined) {
            const w = where['status'] as string | { notIn?: string[]; in?: string[]; equals?: string };
            if (typeof w === 'string') {
              if (m.status !== w) return false;
            } else {
              if (w.notIn && w.notIn.includes(m.status)) return false;
              if (w.in && !w.in.includes(m.status)) return false;
              if (typeof w.equals === 'string' && m.status !== w.equals) return false;
            }
          }
          return true;
        });
        if (orderBy) {
          out = [...out].sort((a, b) =>
            a.entity_type === b.entity_type ? a.source_id.localeCompare(b.source_id) : a.entity_type.localeCompare(b.entity_type),
          );
        }
        return out.map((m) => ({ ...m }));
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Partial<MapRow> }) => {
        const row = mappings.find((m) => m.id === where.id)!;
        Object.assign(row, data);
        return { ...row };
      }),
      deleteMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const notIn = ((where as { status?: { notIn?: string[] } }).status?.notIn ?? []) as string[];
        let count = 0;
        for (let i = mappings.length - 1; i >= 0; i--) {
          if (mappings[i].migration_job_id === (where as { migration_job_id?: string }).migration_job_id && !notIn.includes(mappings[i].status)) {
            mappings.splice(i, 1);
            count++;
          }
        }
        return { count };
      }),
      count: jest.fn(async ({ where }: { where?: Record<string, unknown> } = {}) => {
        const status = (where?.['status'] as string | undefined) ?? undefined;
        return mappings.filter((m) => (status ? m.status === status : true) && (where?.['migration_job_id'] ? m.migration_job_id === where['migration_job_id'] : true)).length;
      }),
    },
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        if (where['username'] !== undefined) {
          return accounts.find((a) => a.username === where['username'] && a.status !== 'terminated') ?? null;
        }
        return accounts.find((a) => a.id === where['id'] && a.status !== 'terminated') ?? null;
      }),
    },
    dnZone: {
      findMany: jest.fn(async () => zoneRows),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => zoneRows.find((z) => z.name === where['name'] && z.deleted_at === null) ?? null),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(700 + zoneRows.length), dns_records__zone_id: [], deleted_at: null, ...data };
        zoneRows.push(row);
        return row;
      }),
    },
    mailDomain: {
      findMany: jest.fn(async () => mailDomainRows),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        mailDomainRows.find((m) => m.name === where['name'] && m.deleted_at === null) ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(800 + mailDomainRows.length), deleted_at: null, ...data };
        mailDomainRows.push(row);
        return row;
      }),
    },
    mailbox: {
      findFirst: jest.fn(async () => null),
      findMany: jest.fn(async () => mailboxRows),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(900 + mailboxRows.length), ...data };
        mailboxRows.push(row);
        return row;
      }),
    },
    database: {
      findMany: jest.fn(async () => dbRows),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => dbRows.find((d) => d.name === where['name'] && d.deleted_at === null) ?? null),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(950 + dbRows.length), deleted_at: null, created_at: new Date(), ...data };
        dbRows.push(row);
        return row;
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };

  const dns = {
    createZone: jest.fn(async (_actor: unknown, input: { name: string; records: unknown[] }) => {
      const row = { id: uid(750 + zoneRows.length), hosting_account_id: ACCOUNT_ID, name: input.name, deleted_at: null, dns_records__zone_id: [] };
      zoneRows.push(row);
      return { id: row.id, name: input.name, record_count: input.records.length };
    }),
  };
  const mail = {
    createDomain: jest.fn(async (_actor: unknown, input: { name: string }) => {
      const row = { id: uid(850 + mailDomainRows.length), name: input.name, deleted_at: null, hosting_account_id: ACCOUNT_ID };
      mailDomainRows.push(row);
      return row;
    }),
    createMailbox: jest.fn(async (_actor: unknown, domainId: string, input: { local_part: string; password?: string; quota_mb?: number }) => {
      const row = { id: uid(910 + mailboxRows.length), mail_domain_id: domainId, local_part: input.local_part, quota_mb: input.quota_mb ?? null };
      mailboxRows.push(row);
      return row;
    }),
  };

  const agent = {
    migrationAnalyze: jest.fn(async () => JSON.parse(JSON.stringify(ANALYSIS))),
    migrationExtractTree: jest.fn(async (input: { prefix: string; target_rel: string }) => ({
      target: `/home/olduser/${input.target_rel}`,
      files: 2,
      bytes: 28,
      tree_sha256: '1'.repeat(64),
      entries: [
        { path: 'index.html', size_bytes: 15, sha256: 'a'.repeat(64) },
        { path: 'blog/post.html', size_bytes: 13, sha256: '9'.repeat(64) },
      ],
      truncated: false,
    })),
    migrationExtractMember: jest.fn(async (input: { member: string }) => {
      if (input.member.endsWith('.db')) {
        return { member: input.member, sha256: 'c'.repeat(64), size_bytes: ZONE_FILE.length, content_b64: Buffer.from(ZONE_FILE).toString('base64') };
      }
      if (input.member.endsWith('.cron')) {
        return { member: input.member, sha256: 'f'.repeat(64), size_bytes: 26, content_b64: Buffer.from('15 3 * * * /usr/bin/backup\n').toString('base64') };
      }
      throw new Error(`member not found: ${input.member}`);
    }),
    migrationHashTree: jest.fn(async () => ({
      target: '/home/olduser/public_html',
      files: 2,
      bytes: 28,
      tree_sha256: '1'.repeat(64),
      entries: [],
      truncated: false,
    })),
    migrationImportDatabase: jest.fn(async () => ({
      db_name: 'olduser_wp',
      dump_sha256: 'd'.repeat(64),
      dump_bytes: 59,
      table_rows: { wp_posts: 7 },
      log: 'ok',
    })),
  };

  const svc = new MigrationsService(
    prisma as unknown as PrismaService,
    agent as never,
    dns as never,
    mail as never,
    audit,
  );
  return { svc, audit, prisma, agent, dns, mail, mappings, jobs, dbRows, zoneRows, mailDomainRows, mailboxRows };
}

async function seedJob(h: ReturnType<typeof harness>): Promise<Record<string, unknown>> {
  await h.svc.create(SUPER, { artifact: ARTIFACT, target_account_id: ACCOUNT_ID });
  return h.jobs[0];
}

describe('migrations service (B15)', () => {
  it('create pins the artifact identity and seeds the ledger', async () => {
    const h = harness();
    const dto = (await h.svc.create(SUPER, { artifact: ARTIFACT, target_account_id: ACCOUNT_ID })) as Record<string, unknown>;
    expect(dto['status']).toBe('analyzed');
    expect(dto['artifact_sha256']).toBe(ART_SHA);
    expect(dto['source_username']).toBe(PREFIX);
    expect(h.prisma.migrationEntityMapping.createMany).toHaveBeenCalledTimes(1);
    expect(h.mappings).toHaveLength(ANALYSIS.entities.length);
    // the dns zone checksum rides on the mapping row (bytes)
    const zone = h.mappings.find((m) => m.entity_type === 'dns_zone')!;
    expect(Buffer.from(zone.checksum_source!).toString('hex')).toBe('c'.repeat(64));
    const ops = h.audit.list().map((e: { operation: string }) => e.operation);
    expect(ops).toContain('migration.create');
  });

  it('create refuses a source username that already belongs to another account', async () => {
    const h = harness({ accounts: [{ id: ACCOUNT_ID, username: 'targetacc', status: 'active' }, { id: uid(1), username: 'olduser', status: 'active' }] });
    await expect(h.svc.create(SUPER, { artifact: ARTIFACT, target_account_id: ACCOUNT_ID })).rejects.toThrow(ConflictException);
  });

  it('create validates the artifact reference and the target account', async () => {
    const h = harness();
    await expect(h.svc.create(SUPER, { artifact: '../escape.tar.gz', target_account_id: ACCOUNT_ID })).rejects.toThrow(BadRequestException);
    await expect(h.svc.create(SUPER, { artifact: ARTIFACT, target_account_id: 'not-a-uuid' })).rejects.toThrow(BadRequestException);
    const h2 = harness({ accounts: [{ id: ACCOUNT_ID, username: 'olduser', status: 'suspended' }] });
    await expect(h2.svc.create(SUPER, { artifact: ARTIFACT, target_account_id: ACCOUNT_ID })).rejects.toThrow(ConflictException);
  });

  it('v1.0 policy skips SSL cert-store import explicitly, at analyze time', async () => {
    const h = harness();
    await seedJob(h);
    const ssl = h.mappings.find((m) => m.entity_type === 'ssl')!;
    expect(ssl.status).toBe('skipped');
    expect(ssl.notes).toMatch(/unsupported-feature/);
  });

  it('dry-run renders the ordered plan with zero agent writes', async () => {
    const h = harness();
    await seedJob(h);
    const res = (await h.svc.dryRun(SUPER, JOB_ID)) as { plan: { steps: Array<{ entity_type: string }>; skipped: unknown[] } };
    // files → dns → mail → db (ssl skipped stays out of the steps)
    const types = res.plan.steps.map((s) => s.entity_type);
    expect(types.indexOf('files')).toBeLessThan(types.indexOf('dns_zone'));
    expect(types.indexOf('dns_zone')).toBeLessThan(types.indexOf('mail_domain'));
    expect(types.indexOf('mail_domain')).toBeLessThan(types.indexOf('database'));
    expect(types).not.toContain('ssl');
    expect(res.plan.skipped).toHaveLength(1);
    expect(h.agent.migrationExtractTree).not.toHaveBeenCalled();
    expect(h.agent.migrationImportDatabase).not.toHaveBeenCalled();
    const job = h.jobs[0] as { status: string };
    expect(job.status).toBe('planned');
  });

  it('execute imports every entity through the real panel paths and verifies parity', async () => {
    const h = harness();
    await seedJob(h);
    const res = (await h.svc.execute(SUPER, JOB_ID)) as { status: string; entities: Array<{ entity_type: string; status: string; checksum_parity: boolean | null }> };

    // files went through extract_tree into the account home
    expect(h.agent.migrationExtractTree).toHaveBeenCalledWith(expect.objectContaining({ username: 'olduser', target_rel: 'public_html', prefix: `${PREFIX}/homedir/public_html` }));
    // the zone was created through DnsService with parsed records (SOA skipped, TYPE65 refused)
    expect(h.dns.createZone).toHaveBeenCalledTimes(1);
    const zoneCall = h.dns.createZone.mock.calls[0][1] as { name: string; records: Array<{ type: string; name: string }> };
    expect(zoneCall.name).toBe('olduser.com');
    const zoneTypes = zoneCall.records.map((r) => r.type);
    expect(zoneTypes).toEqual(expect.arrayContaining(['A', 'CNAME', 'MX', 'TXT', 'NS']));
    expect(zoneTypes).not.toContain('SOA');
    // the mailbox got a fresh secret (never the artifact's), quota set
    expect(h.mail.createMailbox).toHaveBeenCalledWith(expect.anything(), expect.any(String), expect.objectContaining({ local_part: 'alice', quota_mb: 1024 }));
    const pw = (h.mail.createMailbox.mock.calls[0][2] as { password: string }).password;
    expect(pw).toMatch(/^[A-Za-z0-9]{24}$/);
    // the database landed with a SecretBox credential + row
    expect(h.dbRows).toHaveLength(1);
    expect(h.dbRows[0]['name']).toBe('olduser_wp');
    expect((h.dbRows[0]['db_password_hash'] as Buffer).length).toBeGreaterThan(30);

    // job completed; every non-skipped entity verified
    expect(res.status).toBe('completed');
    const byType = Object.fromEntries(res.entities.map((e) => [e.entity_type, e]));
    expect(byType['files'].status).toBe('verified');
    expect(byType['dns_zone'].status).toBe('verified');
    expect(byType['database'].status).toBe('verified');
    expect(byType['database'].checksum_parity).toBe(true);
    expect(byType['ssl'].status).toBe('skipped');
    const ops = h.audit.list().map((e: { operation: string }) => e.operation);
    expect(ops).toContain('migration.execute');
  });

  it('a failed entity fails the job overall and the report carries the checksum pair (M15/D-11)', async () => {
    const h = harness();
    await seedJob(h);
    h.agent.migrationExtractTree.mockRejectedValueOnce(new Error('tarball member missing'));
    const res = (await h.svc.execute(SUPER, JOB_ID)) as { status: string; error_message: string };
    expect(res.status).toBe('failed');
    expect(res.error_message).toMatch(/failed/);
    const files = (res as unknown as { entities: Array<{ entity_type: string; status: string; notes: string }> }).entities.find((e) => e.entity_type === 'files');
    expect(files!.status).toBe('failed');
    expect(files!.notes).toMatch(/tarball member missing/);
  });

  it('execute is resumable: an interrupted run continues, a finished run touches nothing', async () => {
    const h = harness();
    await seedJob(h);
    // simulate a previous run killed right after files flipped to importing:
    // the ledger is the truth, so resume picks up exactly the non-terminal rows
    const files = h.mappings.find((m) => m.entity_type === 'files')!;
    files.status = 'importing';
    await h.svc.execute(SUPER, JOB_ID);
    expect(h.agent.migrationExtractTree).toHaveBeenCalledTimes(1);
    expect(h.agent.migrationImportDatabase).toHaveBeenCalledTimes(1);
    const res = (await h.svc.get(JOB_ID)) as { status: string; entities: Array<{ entity_type: string; status: string }> };
    expect(res.status).toBe('completed');
    expect(res.entities.find((e) => e.entity_type === 'files')!.status).toBe('verified');

    // re-running a finished job imports nothing twice
    h.agent.migrationExtractTree.mockClear();
    h.agent.migrationImportDatabase.mockClear();
    await h.svc.execute(SUPER, JOB_ID);
    expect(h.agent.migrationExtractTree).not.toHaveBeenCalled();
    expect(h.agent.migrationImportDatabase).not.toHaveBeenCalled();
  });

  it('the report aggregates statuses, byte totals and the DNS cutover plan', async () => {
    const h = harness();
    await seedJob(h);
    await h.svc.execute(SUPER, JOB_ID);
    const rep = (await h.svc.report(SUPER, JOB_ID)) as {
      totals: Record<string, number>;
      entities: Array<{ entity_type: string; checksum_parity: boolean | null }>;
      cutover: { zones: Array<{ zone: string; records: unknown[] }> };
    };
    expect(rep.totals['entities']).toBe(ANALYSIS.entities.length);
    expect(rep.totals['verified']).toBe(6);
    expect(rep.totals['skipped']).toBe(1);
    expect(rep.entities.find((e) => e.entity_type === 'dns_zone')!.checksum_parity).toBe(true);
    expect(rep.cutover.zones).toHaveLength(1);
    expect(rep.cutover.zones[0].zone).toBe('olduser.com');
    const ops = h.audit.list().map((e: { operation: string }) => e.operation);
    expect(ops).toContain('migration.report');
  });

  it('cancel and delete follow the ledger rules', async () => {
    const h = harness();
    await seedJob(h);
    await h.svc.cancel(SUPER, JOB_ID);
    expect((h.jobs[0] as { status: string }).status).toBe('canceled');
    await expect(h.svc.execute(SUPER, JOB_ID)).rejects.toThrow(ConflictException);
    await h.svc.remove(SUPER, JOB_ID);
    await expect(h.svc.get(JOB_ID)).rejects.toThrow(NotFoundException);
  });

  it('analyze marks preflight collisions so the plan shows them', async () => {
    const h = harness({ zones: ['olduser.com'] });
    await seedJob(h);
    // simulate a fresh ledger (create seeded it as pending; re-analyze applies collisions)
    await h.svc.analyze(SUPER, JOB_ID);
    const zone = h.mappings.find((m) => m.entity_type === 'dns_zone' && m.source_id === 'olduser.com');
    expect(zone!.status).toBe('skipped');
    expect(zone!.notes).toMatch(/collision/);
  });
});

describe('zonefile parser (B15)', () => {
  it('parses cPanel zone lines, joins SOA continuations, skips the unrepresentable', () => {
    const p = parseZoneFile(ZONE_FILE);
    expect(p.defaultTtl).toBe(86400);
    const types = p.records.map((r) => r.type);
    expect(types).toEqual(expect.arrayContaining(['NS', 'A', 'CNAME', 'MX', 'TXT']));
    expect(types).not.toContain('SOA');
    expect(p.skipped.some((s) => s.includes('SOA'))).toBe(true);
    expect(p.skipped.some((s) => s.includes('TYPE65'))).toBe(true);
    const mx = p.records.find((r) => r.type === 'MX')!;
    expect(mx.priority).toBe(10);
    expect(mx.content).toBe('mail.olduser.com.');
    const cn = p.records.find((r) => r.type === 'CNAME')!;
    expect(cn.name).toBe('www');
    expect(cn.ttl).toBe(14400);
  });

  it('handles owner inheritance and $ORIGIN honestly', () => {
    const p = parseZoneFile('example.com. IN A 1.2.3.4\n\tIN AAAA ::1\n$ORIGIN elsewhere.\n');
    expect(p.records.filter((r) => r.type === 'A')).toHaveLength(1);
    expect(p.records.filter((r) => r.type === 'AAAA')).toHaveLength(1);
    expect(p.skipped.some((s) => s.includes('$ORIGIN'))).toBe(true);
  });
});
