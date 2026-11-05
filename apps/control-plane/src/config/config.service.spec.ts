import { BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { ConfigService } from './config.service';

/**
 * Config engine v1: rollback writes FORWARD (append-only history + a
 * config_transactions record), drift is recorded and never auto-reconciled
 * (§P.7), and every listing is visibility-scoped.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true };

const ACCOUNT = { id: '01900000-0000-7000-8000-00000000a001', username: 'alice' };
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
  const versions: Record<string, unknown>[] = [
    {
      id: uid(11),
      target_type: 'nginx_vhost',
      target_id: DOMAIN.id,
      version: 1,
      content: 'server { v1 }',
      is_active: false,
      rendered_by: null,
      created_at: new Date('2026-11-01'),
    },
    {
      id: uid(12),
      target_type: 'nginx_vhost',
      target_id: DOMAIN.id,
      version: 2,
      content: 'server { v2 }',
      is_active: true,
      rendered_by: null,
      created_at: new Date('2026-11-02'),
    },
  ];
  const transactions: Record<string, unknown>[] = [];
  const driftEvents: Record<string, unknown>[] = [];
  const prisma = {
    domain: {
      findFirst: jest.fn(async ({ where }: { where: { id: string } }) =>
        where.id === DOMAIN.id ? { ...DOMAIN } : null,
      ),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async () => null),
    },
    node: {
      findFirst: jest.fn(async () => ({ id: uid(1) })),
    },
    configVersion: {
      findFirst: jest.fn(
        async ({
          where,
          orderBy,
        }: {
          where: Record<string, unknown>;
          orderBy?: Record<string, string>;
        }) => {
          const rows = versions.filter(
            (v) =>
              v['target_type'] === where['target_type'] &&
              v['target_id'] === where['target_id'] &&
              (where['id'] === undefined || v['id'] === where['id']) &&
              (where['is_active'] === undefined || v['is_active'] === where['is_active']),
          );
          if (orderBy?.version === 'desc') {
            rows.sort((a, b) => Number(b['version']) - Number(a['version']));
          }
          return rows[0] ?? null;
        },
      ),
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        versions
          .filter((v) => v['target_type'] === where['target_type'] && v['target_id'] === where['target_id'])
          .sort((a, b) => Number(b['version']) - Number(a['version'])),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(versions.length + 20), ...data, created_at: new Date() };
        versions.push(row);
        return row;
      }),
      updateMany: jest.fn(
        async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
          for (const v of versions) {
            if (
              v['target_type'] === where['target_type'] &&
              v['target_id'] === where['target_id'] &&
              v['is_active'] === true
            ) {
              Object.assign(v, data);
            }
          }
          return { count: 0 };
        },
      ),
    },
    configTransaction: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = {
          id: uid(transactions.length + 40),
          started_at: new Date(),
          completed_at: null,
          error_message: null,
          ...data,
        };
        transactions.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = transactions.find((t) => t['id'] === where.id);
        Object.assign(row!, data);
        return row;
      }),
      findMany: jest.fn(async () => transactions),
    },
    driftEvent: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(driftEvents.length + 60), detected_at: new Date(), resolved_at: null, resolution: null, ...data };
        driftEvents.push(row);
        return row;
      }),
      findMany: jest.fn(async () => driftEvents.filter((e) => !e['resolved_at'])),
      findFirst: jest.fn(async ({ where }: { where: { id: string } }) =>
        driftEvents.find((e) => e['id'] === where.id) ?? null,
      ),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = driftEvents.find((e) => e['id'] === where.id);
        Object.assign(row!, data);
        return row;
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };
  const agent = {
    nginxApplyVhost: jest.fn(async () => ({ status: 'applied', health_check: 'skipped', previous_existed: true })),
    nginxReload: jest.fn(async () => ({ status: 'skipped', detail: 'dev' })),
    configDriftCheck: jest.fn(async (_name: string, expected: string) => ({
      matches: false,
      exists: true,
      expected_hash: 'a'.repeat(64),
      actual_hash: 'b'.repeat(64),
      file_path: '/etc/nginx/conf.d/example.com.conf',
    })),
    configListActive: jest.fn(async () => ({ exists: true, content: 'server { disk }', file_path: '/x' })),
  };
  const svc = new ConfigService(
    prisma as unknown as PrismaService,
    agent as unknown as ConstructorParameters<typeof ConfigService>[1],
    audit,
  );
  return { svc, agent, versions, transactions, driftEvents, audit };
}

describe('config versions listing', () => {
  it('lists versions without content but with sizes', async () => {
    const h = harness();
    const res = await h.svc.versions('nginx_vhost', DOMAIN.id, SUPER);
    expect(res.data).toHaveLength(2);
    expect(res.data[0].version).toBe(2);
    expect(res.data[0].is_active).toBe(true);
    expect(JSON.stringify(res.data)).not.toContain('server { v2 }');
  });

  it('rejects unknown target types and invisible targets', async () => {
    const h = harness();
    await expect(h.svc.versions('postfix_main', DOMAIN.id, SUPER)).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.versions('nginx_vhost', DOMAIN.id, { userId: 'u2', isSuperAdmin: false }),
    ).rejects.toThrow(NotFoundException);
  });
});

describe('rollback writes forward', () => {
  it('re-applies v1 bytes as a NEW v3 and records the transaction', async () => {
    const h = harness();
    const dto = await h.svc.rollback('nginx_vhost', DOMAIN.id, uid(11), SUPER);
    expect(dto.version).toBe(3);
    expect(h.agent.nginxApplyVhost).toHaveBeenCalledWith('example.com', 'server { v1 }');
    expect(h.transactions).toHaveLength(1);
    expect(h.transactions[0]).toMatchObject({ status: 'applied' });
    const active = h.versions.find((v) => v['id'] === dto.id);
    expect(active?.['content']).toBe('server { v1 }');
    expect(h.versions.find((v) => v['id'] === uid(12))?.['is_active']).toBe(false);
  });

  it('marks the transaction failed when the agent rejects the apply', async () => {
    const h = harness();
    h.agent.nginxApplyVhost.mockRejectedValueOnce(new Error('health check failed'));
    await expect(h.svc.rollback('nginx_vhost', DOMAIN.id, uid(11), SUPER)).rejects.toThrow(
      'health check failed',
    );
    expect(h.transactions[0]['status']).toBe('failed');
    expect(h.transactions[0]['error_message']).toContain('health check');
    // No new version was written.
    expect(h.versions).toHaveLength(2);
  });

  it('refuses rolling back to the already-active version', async () => {
    const h = harness();
    await expect(h.svc.rollback('nginx_vhost', DOMAIN.id, uid(12), SUPER)).rejects.toThrow(
      /already the active/,
    );
  });

  it('refuses php_pool rollback honestly', async () => {
    const h = harness();
    await expect(h.svc.rollback('php_pool', DOMAIN.id, uid(11), SUPER)).rejects.toThrow(/pool-target/);
  });
});

describe('drift', () => {
  it('records an event on mismatch and reports matches on equality', async () => {
    const h = harness();
    const res = await h.svc.driftCheck('nginx_vhost', DOMAIN.id, SUPER);
    expect(res.matches).toBe(false);
    expect(res.drift_event_id).toBeTruthy();
    expect(h.driftEvents).toHaveLength(1);

    h.agent.configDriftCheck.mockResolvedValueOnce({
      matches: true,
      exists: true,
      expected_hash: 'a'.repeat(64),
      actual_hash: 'a'.repeat(64),
      file_path: '/x',
    });
    const ok = await h.svc.driftCheck('nginx_vhost', DOMAIN.id, SUPER);
    expect(ok.matches).toBe(true);
    expect(ok.drift_event_id).toBeNull();
    expect(h.driftEvents).toHaveLength(1); // no duplicate event
  });

  it('resolve requires a valid resolution value and marks the event', async () => {
    const h = harness();
    const res = await h.svc.driftCheck('nginx_vhost', DOMAIN.id, SUPER);
    await expect(h.svc.resolveDrift(res.drift_event_id as string, 'hacked', SUPER)).rejects.toThrow(
      BadRequestException,
    );
    const dto = await h.svc.resolveDrift(res.drift_event_id as string, 'investigated', SUPER);
    expect(dto.resolved_at).toBeTruthy();
    await expect(h.svc.resolveDrift(res.drift_event_id as string, 'ignored', SUPER)).rejects.toThrow(
      NotFoundException,
    );
  });
});
