import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import {
  PackagesService,
  mergeQuotas,
  validateFeatureSet,
  validateQuotaSet,
} from './packages.service';

/**
 * Packages CRUD (API spec §4.5): fail-closed quota/feature validation,
 * soft-delete with in-use refusal, audit trail. The prisma seam is a plain
 * object; the audit seam is the real in-memory chain.
 */

function rowHarness(rows: Record<string, unknown>[] = [], accounts: { package_id: string }[] = []) {
  const audit = new InMemoryAuditService();
  const pkgTable = [...rows];
  const prisma = {
    package: {
      findMany: jest.fn(async ({ where }: { where: { deleted_at: null } }) => pkgTable),
      findFirst: jest.fn(async ({ where }: { where: { id: string; deleted_at: null } }) =>
        pkgTable.find((r) => r['id'] === where['id']) ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const n = pkgTable.length + 1;
        const row = {
          id: `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`,
          php_versions: [] as string[],
          is_active: true,
          created_at: new Date(),
          updated_at: new Date(),
          deleted_at: null,
          ...data,
        };
        pkgTable.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = pkgTable.find((r) => r['id'] === where['id']);
        if (!row) throw new Error('not found');
        Object.assign(row, data);
        return row;
      }),
    },
    hostingAccount: {
      count: jest.fn(async ({ where }: { where: { package_id: string } }) =>
        accounts.filter((a) => a.package_id === where.package_id).length,
      ),
    },
  };
  const svc = new PackagesService(prisma as unknown as PrismaService, audit);
  return { svc, prisma, audit, pkgTable };
}

const ADMIN = '01900000-0000-7000-8000-000000000001';

describe('quota validation (packages.service)', () => {
  it('accepts the canonical keys and normalizes cpu granularity', () => {
    expect(validateQuotaSet({ cpu: 2, mem_mb: 512, disk_mb: 10240, inodes: 100000, processes: 64 }, 'q')).toEqual({
      cpu: 2,
      mem_mb: 512,
      disk_mb: 10240,
      inodes: 100000,
      processes: 64,
    });
    expect(validateQuotaSet({ cpu: 0.3 }, 'q').cpu).toBe(0.3);
    expect(validateQuotaSet(null, 'q')).toEqual({});
  });

  it('rejects unknown keys, non-positives, non-integers and ceilings', () => {
    expect(() => validateQuotaSet({ net_mbps: 100 }, 'q')).toThrow(/unknown quota key/);
    expect(() => validateQuotaSet({ cpu: -1 }, 'q')).toThrow(/positive/);
    expect(() => validateQuotaSet({ cpu: 0 }, 'q')).toThrow(/positive/);
    expect(() => validateQuotaSet({ cpu: 1.05 }, 'q')).toThrow(/multiple of 0.1/);
    expect(() => validateQuotaSet({ cpu: 65 }, 'q')).toThrow(/at most 64/);
    expect(() => validateQuotaSet({ mem_mb: 1.5 }, 'q')).toThrow(/integer/);
    expect(() => validateQuotaSet({ mem_mb: (1 << 20) + 1 }, 'q')).toThrow(/ceiling/);
    expect(() => validateQuotaSet({ processes: 5000 }, 'q')).toThrow(/ceiling/);
    expect(() => validateQuotaSet([1, 2], 'q')).toThrow(/must be an object/);
  });

  it('feature sets allow any [a-z0-9_] keys but boolean values only', () => {
    expect(validateFeatureSet({ mail_enabled: true, dns_enabled: false }, 'f')).toEqual({
      mail_enabled: true,
      dns_enabled: false,
    });
    expect(() => validateFeatureSet({ mail_enabled: 'yes' }, 'f')).toThrow(/boolean/);
    expect(() => validateFeatureSet({ 'Bad Key!': true }, 'f')).toThrow(/\[a-z0-9_\]/);
  });

  it('mergeQuotas lets the override win', () => {
    expect(mergeQuotas({ cpu: 2, mem_mb: 512 }, { cpu: 4 })).toEqual({ cpu: 4, mem_mb: 512 });
  });
});

describe('PackagesService (§4.5)', () => {
  const good = {
    name: 'Standard',
    quotas: { cpu: 2, mem_mb: 1024, processes: 128 },
    features: { mail_enabled: true },
  };

  it('creates with defaults, audits, and lists live rows', async () => {
    const { svc, audit } = rowHarness();
    const created = await svc.create(good, ADMIN);
    expect(created.isolation_profile).toBe('standard');
    expect(created.over_quota_policy).toBe('alert');
    expect(created.php_versions).toEqual([]);
    expect(audit.list().at(-1)?.operation).toBe('package.create');

    await svc.create({ name: 'Second' }, ADMIN);
    const { data } = await svc.list();
    expect(data).toHaveLength(2);
  });

  it('validates create input (name, quotas, features, profile, policy, php)', async () => {
    const { svc } = rowHarness();
    await expect(svc.create({ name: '' }, ADMIN)).rejects.toThrow(BadRequestException);
    await expect(svc.create({ name: 'x', quotas: { bogus: 1 } }, ADMIN)).rejects.toThrow(/unknown quota key/);
    await expect(svc.create({ name: 'x', features: { mail: 'yes' } }, ADMIN)).rejects.toThrow(/boolean/);
    await expect(svc.create({ name: 'x', isolation_profile: 'paranoid' }, ADMIN)).rejects.toThrow(/standard/);
    await expect(svc.create({ name: 'x', over_quota_policy: 'nuke' }, ADMIN)).rejects.toThrow(
      /alert \| throttle \| suspend/,
    );
    await expect(svc.create({ name: 'x', php_versions: ['eight'] }, ADMIN)).rejects.toThrow(/version string/);
  });

  it('get/update operate on live rows only; unknown and malformed ids 404', async () => {
    const { svc } = rowHarness([]);
    await expect(svc.get('not-a-uuid')).rejects.toThrow(NotFoundException);
    await expect(svc.get('00000000-0000-0000-0000-0000000000ff')).rejects.toThrow(NotFoundException);

    const created = await svc.create(good, ADMIN);
    const updated = await svc.update(created.id, { name: 'Standard v2', quotas: { cpu: 4 } }, ADMIN);
    expect(updated.name).toBe('Standard v2');
    expect(updated.quotas).toEqual({ cpu: 4 }); // full replacement, not merge
    expect(updated.quotas).not.toEqual({ cpu: 4, mem_mb: 1024, processes: 128 });
  });

  it('delete is refused while accounts reference the package (409), else soft-deletes', async () => {
    const pkg = {
      id: '00000000-0000-0000-0000-0000000000aa',
      name: 'Busy',
      quotas: {},
      features: {},
      php_versions: [],
      is_active: true,
      created_at: new Date(),
      updated_at: new Date(),
    };
    const inUse = rowHarness([pkg], [{ package_id: pkg.id }]);
    await expect(inUse.svc.remove(pkg.id, ADMIN)).rejects.toThrow(ConflictException);

    const free = rowHarness([pkg], []);
    await free.svc.remove(pkg.id, ADMIN);
    expect(free.pkgTable[0]!['deleted_at']).toBeInstanceOf(Date);
    expect(free.pkgTable[0]!['is_active']).toBe(false);
    expect(free.audit.list().at(-1)?.operation).toBe('package.delete');
  });
});
