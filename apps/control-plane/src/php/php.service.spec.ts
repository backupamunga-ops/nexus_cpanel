import { BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { DEFAULT_POOL, PhpService, validatePoolConfig } from './php.service';

/**
 * PHP pool management: version/pool validation mirrors the agent exactly
 * (unknown keys rejected, ranges enforced), the agent is authoritative
 * (agent-first), and the active config_version records the applied bytes.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true };

const ACCOUNT = { id: '01900000-0000-7000-8000-00000000a001', username: 'alice', package: { php_versions: ['8.2', '8.3'] } };
const DOMAIN = {
  id: '01900000-0000-7000-8000-00000000d001',
  hosting_account_id: ACCOUNT.id,
  name: 'example.com',
  document_root: '/home/alice/domains/example.com/public_html',
  php_version: null as string | null,
  deleted_at: null,
};

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

function harness() {
  const audit = new InMemoryAuditService();
  const versions: Record<string, unknown>[] = [];
  const prisma = {
    domain: {
      findFirst: jest.fn(async ({ where }: { where: { id: string } }) =>
        where.id === DOMAIN.id ? { ...DOMAIN } : null,
      ),
      update: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        Object.assign(DOMAIN, data);
        return { ...DOMAIN };
      }),
    },
    hostingAccount: {
      findFirst: jest.fn(async () => ({ ...ACCOUNT })),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async () => null),
    },
    configVersion: {
      findFirst: jest.fn(
        async ({ where, orderBy }: { where: Record<string, unknown>; orderBy?: Record<string, string> }) => {
          if (where['is_active'] === true) {
            return versions.find((v) => v['is_active'] === true && v['target_id'] === where['target_id']) ?? null;
          }
          const rows = versions
            .filter((v) => v['target_id'] === where['target_id'])
            .sort((a, b) => Number(b['version']) - Number(a['version']));
          return rows[0] ?? null;
        },
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(versions.length + 90), ...data, created_at: new Date() };
        versions.push(row);
        return row;
      }),
      updateMany: jest.fn(
        async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
          for (const v of versions) {
            if (v['target_id'] === where['target_id'] && v['is_active'] === true) {
              Object.assign(v, data);
            }
          }
          return { count: 0 };
        },
      ),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };
  const agent = {
    phpCreatePool: jest.fn(async (_u: string, _d: string, version: string) => ({
      status: 'applied',
      version,
      pool_file: `/etc/php/${version}/pools/example.com.conf`,
      conf_content: `; rendered for ${version}\n[example.com]\n`,
    })),
    phpModifyPool: jest.fn(async (_u: string, _d: string, version: string) => ({
      status: 'applied',
      version,
      pool_file: `/etc/php/${version}/pools/example.com.conf`,
      conf_content: `; modified for ${version}\n[example.com]\n`,
    })),
    phpDeletePool: jest.fn(async () => ({ status: 'removed' })),
    phpListVersions: jest.fn(async () => ({ installed: ['8.2', '8.3'] })),
  };
  const svc = new PhpService(
    prisma as unknown as PrismaService,
    agent as unknown as ConstructorParameters<typeof PhpService>[1],
    audit,
  );
  return { svc, agent, versions, audit };
}

describe('validatePoolConfig (mirror of the agent policy)', () => {
  it('accepts known keys and rejects unknown ones', () => {
    expect(validatePoolConfig({ pm: 'dynamic', 'pm.max_children': 10, memory_limit: '128M' })).toEqual({
      pm: 'dynamic',
      'pm.max_children': 10,
      memory_limit: '128M',
    });
    expect(() => validatePoolConfig({ evil_key: true })).toThrow(/unknown key/);
    expect(() => validatePoolConfig({ 'pm.max_children': 1000 })).toThrow(/1\.\.500/);
    expect(() => validatePoolConfig({ memory_limit: 'tons' })).toThrow(/128M/);
    expect(() => validatePoolConfig({ pm: 'sometimes' })).toThrow(/dynamic \| static \| ondemand/);
  });
});

describe('php.update lifecycle', () => {
  it('creates a pool agent-first and versions it', async () => {
    const h = harness();
    const view = await h.svc.update(DOMAIN.id, { php_version: '8.2', pool: { 'pm.max_children': 12 } }, SUPER);
    expect(h.agent.phpCreatePool).toHaveBeenCalledWith('alice', 'example.com', '8.2', expect.any(Object));
    expect(view.php_version).toBe('8.2');
    expect(view.pool?.version).toBe('8.2');
    expect(h.versions).toHaveLength(1);
    const stored = JSON.parse(h.versions[0]['content'] as string);
    expect(stored.config['pm.max_children']).toBe(12);
    expect(stored.conf_content).toContain('8.2');
  });

  it('modifies in place on a config change, recreates on a version change', async () => {
    const h = harness();
    await h.svc.update(DOMAIN.id, { php_version: '8.2' }, SUPER);
    // Same version + new config → modify only.
    await h.svc.update(DOMAIN.id, { pool: { 'pm.max_children': 30 } }, SUPER);
    expect(h.agent.phpModifyPool).toHaveBeenCalledTimes(1);
    expect(h.agent.phpCreatePool).toHaveBeenCalledTimes(1);

    // Version change → delete old + create new.
    await h.svc.update(DOMAIN.id, { php_version: '8.3' }, SUPER);
    expect(h.agent.phpDeletePool).toHaveBeenCalledWith('alice', 'example.com', '8.2');
    expect(h.agent.phpCreatePool).toHaveBeenLastCalledWith('alice', 'example.com', '8.3', expect.anything());
  });

  it('removes the pool and clears the version', async () => {
    const h = harness();
    await h.svc.update(DOMAIN.id, { php_version: '8.2' }, SUPER);
    await h.svc.update(DOMAIN.id, { php_version: null }, SUPER);
    expect(h.agent.phpDeletePool).toHaveBeenCalledWith('alice', 'example.com', '8.2');
    expect(DOMAIN.php_version).toBeNull();
    expect(h.versions[0]['is_active']).toBe(false);
  });

  it('refuses versions outside the package allowlist and unknown versions', async () => {
    const h = harness();
    await expect(h.svc.update(DOMAIN.id, { php_version: '8.1' }, SUPER)).rejects.toThrow(/not offered/);
    await expect(h.svc.update(DOMAIN.id, { php_version: '7.4' }, SUPER)).rejects.toThrow(/8\.1 \| 8\.2 \| 8\.3 \| 8\.4/);
  });

  it('refuses removal when no pool exists and 404s invisible domains', async () => {
    const h = harness();
    await expect(h.svc.update(DOMAIN.id, { php_version: null }, SUPER)).rejects.toThrow(/no PHP pool/);
    await expect(
      h.svc.update(DOMAIN.id, { php_version: '8.2' }, { userId: 'u2', isSuperAdmin: false }),
    ).rejects.toThrow(NotFoundException);
  });
});

describe('php.getForDomain', () => {
  it('reports the pool with the rendered bytes', async () => {
    const h = harness();
    await h.svc.update(DOMAIN.id, { php_version: '8.2', pool: DEFAULT_POOL }, SUPER);
    const view = await h.svc.getForDomain(DOMAIN.id, SUPER);
    expect(view.php_version).toBe('8.2');
    expect(view.pool?.conf_content).toContain('[example.com]');
    expect(view.offered_by_package).toEqual(['8.2', '8.3']);
  });
});
