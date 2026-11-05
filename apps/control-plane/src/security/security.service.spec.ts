import { BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { WafService } from './waf.service';
import { MalwareService } from './malware.service';

/**
 * WAF & malware service tests (B12). Harness: in-memory domain/policy/
 * config-version/scan tables, the real in-memory audit chain, and fake
 * agent clients (including one whose health gate fails — the rollback path).
 */

const SUPER = { userId: 'u1', isSuperAdmin: true };

function harness() {
  const audit = new InMemoryAuditService();
  const domains = [
    {
      id: 'dom-1', hosting_account_id: 'acct-1', name: 'alpha.demo',
      deleted_at: null, updated_at: new Date(),
      hosting_account: { username: 'alpha' },
    },
  ];
  const policies: Array<Record<string, unknown>> = [];
  const configVersions: Array<Record<string, unknown>> = [];
  const scans: Array<Record<string, unknown>> = [];
  const findings: Array<Record<string, unknown>> = [];
  let cvId = 1;

  const prisma: Record<string, any> = {
    jobMetadata: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => ({ id: 'jobrow-1', ...data })),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => ({ id: where.id, ...data })),
    },
    domain: {
      findMany: jest.fn(async () => domains),
      findFirst: jest.fn(async ({ where }: { where: { id: string; deleted_at: null } }) =>
        domains.find((d) => d.id === where.id) ?? null,
      ),
    },
    modsecurityPolicy: {
      findMany: jest.fn(async ({ where }: { where: { domain_id: { in: string[] } } }) =>
        policies.filter((p) => (where.domain_id.in as string[]).includes(p.domain_id as string)),
      ),
      findFirst: jest.fn(async ({ where }: { where: { domain_id: string } }) =>
        policies.find((p) => p.domain_id === where.domain_id) ?? null,
      ),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = policies.find((p) => p.id === where.id) ?? {};
        return Object.assign(row, data, { updated_at: new Date() });
      }),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `pol-${policies.length + 1}`, created_at: new Date(), updated_at: new Date(), ...data };
        policies.push(row);
        return row;
      }),
    },
    configVersion: {
      findFirst: jest.fn(async ({ where }: { where: { target_type: string; target_id: string } }) =>
        configVersions
          .filter((c) => c.target_type === where.target_type && c.target_id === where.target_id)
          .sort((a, b) => (b.version as number) - (a.version as number))[0] ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `cv-${cvId++}`, ...data };
        configVersions.push(row);
        return row;
      }),
    },
    malwareScan: {
      findMany: jest.fn(async () => scans),
      findUnique: jest.fn(async ({ where }: { where: { id: string } }) =>
        scans.find((s) => s.id === where.id) ?? null,
      ),
      findUniqueOrThrow: jest.fn(async ({ where }: { where: { id: string } }) =>
        scans.find((s) => s.id === where.id) ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `scan-${scans.length + 1}`, malware_findings__scan_id: [], ...data };
        scans.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = scans.find((s) => s.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
    },
    malwareFinding: {
      createMany: jest.fn(async ({ data }: { data: Array<Record<string, unknown>> }) => {
        for (const f of data) {
          const row = { id: `f-${findings.length + 1}`, deleted_at: null, restored_at: null, ...f };
          findings.push(row);
          const scan = scans.find((s) => s.id === f.scan_id) as { malware_findings__scan_id: unknown[] } | undefined;
          (scan?.malware_findings__scan_id as unknown[] | undefined)?.push(row);
        }
        return { count: data.length };
      }),
      findFirst: jest.fn(async ({ where }: { where: { id: string; quarantined?: boolean; deleted_at?: null; restored_at?: null } }) => {
        const f = findings.find(
          (x) =>
            x.id === where.id &&
            (where.quarantined === undefined || x.quarantined === where.quarantined) &&
            (where.restored_at === undefined || x.restored_at === null) &&
            (where.deleted_at === undefined || x.deleted_at === null),
        );
        if (!f) return null;
        const scan = scans.find((s) => s.id === f.scan_id);
        return { ...f, scan: { hosting_account_id: scan?.hosting_account_id ?? null } };
      }),
      findMany: jest.fn(async () => findings),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = findings.find((f) => f.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
    },
    hostingAccount: {
      findUnique: jest.fn(async ({ where }: { where: { id: string } }) =>
        where.id === 'acct-1' ? { homedir: '/home/alpha' } : null,
      ),
    },
    userHostingAccountAccess: { findFirst: jest.fn(async () => null) },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma)),
  };

  const agent = {
    wafApplyPolicy: jest.fn(async () => ({
      status: 'applied', domain: 'alpha.demo', mode: 'block',
      conf_path: '/etc/nginx/conf.d/alpha.demo.waf.conf', health_check: 'passed',
    })),
    malwareScan: jest.fn(async (p: { path: string }) => ({
      status: 'success', scope: 'account', path: p.path, files_scanned: 120,
      infected_count: 1,
      findings: [{ path: p.path + '/shell.php', signature: 'Php.Trojan.Shell', quarantine_path: p.path + '/q/shell.php.quarantined' }],
      engine: 'clamscan',
    })),
    malwareQuarantineDelete: jest.fn(async () => ({ status: 'deleted', path: 'x' })),
    malwareQuarantineRestore: jest.fn(async (_p: string, _u: string, rel: string) => ({
      status: 'restored', path: '/home/alpha/' + rel,
    })),
  };

  const waf = new WafService(prisma as unknown as PrismaService, agent as never, audit);
  const malware = new MalwareService(prisma as unknown as PrismaService, agent as never, audit);
  return { waf, malware, agent, audit, prisma, policies, configVersions, scans, findings };
}

describe('waf service (B12)', () => {
  it('applies a block policy agent-first, records it and versions the include', async () => {
    const { waf, agent, policies, configVersions, audit } = harness();
    const dto = await waf.updatePolicy(SUPER, 'dom-1', { mode: 'block', paranoia_level: 2, exclusions: ['942100'] });
    expect(dto.mode).toBe('block');
    expect(agent.wafApplyPolicy).toHaveBeenCalledWith('alpha.demo', 'block', 2, ['942100']);
    expect(policies).toHaveLength(1);
    expect(configVersions).toHaveLength(1);
    expect((configVersions[0].target_type as string)).toBe('waf_include');
    const ops = audit.list().map((e) => e.operation);
    expect(ops).toContain('waf.policy.update');
  });

  it('leaves the policy untouched when the health gate rolls the include back', async () => {
    const { waf, agent, policies, audit } = harness();
    agent.wafApplyPolicy = jest.fn(async () => {
      throw new Error('health check failed; WAF include rolled back');
    });
    await expect(waf.updatePolicy(SUPER, 'dom-1', { mode: 'block' })).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(policies).toHaveLength(0);
    const entry = audit.list().find((e) => e.operation === 'waf.policy.update');
    expect(entry?.outcome).toBe('failure');
  });

  it('rejects bad modes, paranoia levels and exclusion ids', async () => {
    const { waf } = harness();
    await expect(waf.updatePolicy(SUPER, 'dom-1', { mode: 'yolo' })).rejects.toBeInstanceOf(BadRequestException);
    await expect(waf.updatePolicy(SUPER, 'dom-1', { mode: 'block', paranoia_level: 5 })).rejects.toBeInstanceOf(BadRequestException);
    await expect(waf.updatePolicy(SUPER, 'dom-1', { mode: 'block', exclusions: ['drop tables'] })).rejects.toBeInstanceOf(BadRequestException);
  });

  it('404s domains the caller cannot see', async () => {
    const { waf } = harness();
    await expect(waf.getPolicy({ userId: 'u2', isSuperAdmin: false }, 'dom-1')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('malware service (B12)', () => {
  it('runs a scan, stores findings with quarantine state and audits', async () => {
    const { malware, agent, scans, audit } = harness();
    const dto = await malware.startScan(SUPER, { scope: 'account', account_id: 'acct-1' });
    expect(dto.status).toBe('success');
    expect(dto.infected_count).toBe(1);
    expect(dto.findings[0].quarantined).toBe(true);
    expect(agent.malwareScan).toHaveBeenCalledWith({ scope: 'account', path: '/home/alpha', move_infected: true });
    expect(scans[0].quarantined_count).toBe(1);
    const ops = audit.list().map((e) => e.operation);
    expect(ops).toContain('malware.scan');
  });

  it('quarantine delete and restore are audited and confined to the registry', async () => {
    const { malware, findings, audit } = harness();
    await malware.startScan(SUPER, { scope: 'account', account_id: 'acct-1' });
    const f = findings[0] as { id: string; quarantined: boolean };
    expect(f.quarantined).toBe(true);

    await malware.restoreFinding(SUPER, f.id, { username: 'alpha', rel_path: 'uploads/restored.php' });
    expect((findings[0] as { restored_at: Date | null }).restored_at).not.toBeNull();

    // restore again on the same finding → gone from the eligible set
    await expect(
      malware.restoreFinding(SUPER, f.id, { username: 'alpha', rel_path: 'x.php' }),
    ).rejects.toBeInstanceOf(NotFoundException);

    await malware.startScan(SUPER, { scope: 'account', account_id: 'acct-1' });
    const f2 = (findings.find((x) => !(x as { restored_at: Date | null }).restored_at) ?? findings[0]) as { id: string };
    await malware.deleteFinding(SUPER, f2.id);
    const ops = audit.list().map((e) => e.operation);
    expect(ops).toContain('malware.quarantine.restore');
    expect(ops).toContain('malware.quarantine.delete');
  });

  it('server-scope scans are super-admin only', async () => {
    const { malware } = harness();
    await expect(
      malware.startScan({ userId: 'u2', isSuperAdmin: false }, { scope: 'server' }),
    ).rejects.toMatchObject({ status: 403 });
  });
});
