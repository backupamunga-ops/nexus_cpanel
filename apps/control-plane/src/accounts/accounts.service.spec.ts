import { BadRequestException, NotFoundException } from '@nestjs/common';
import { AccountsService } from './accounts.service';
import { InMemoryAuditService } from '../audit/audit.service';

const ACTOR = '01900000-0000-7000-8000-0000000000aa';

function fakeRow(overrides: Record<string, unknown> = {}) {
  return {
    id: '01900000-0000-7000-8000-000000000c01',
    username: 'alice',
    package_id: '00000000-0000-0000-0000-000000000000',
    status: 'active',
    linux_uid: 2101,
    homedir: '/home/alice',
    created_at: new Date('2026-11-05T00:00:00Z'),
    deleted_at: null,
    ...overrides,
  };
}

async function makeService() {
  const rows: Record<string, Record<string, unknown>> = {};
  let seq = 0;
  const prisma = {
    hostingAccount: {
      findFirst: jest.fn().mockImplementation(({ where }) => {
        const match = Object.values(rows).find((r) => {
          if (where.id && r.id !== where.id) return false;
          if (where.username && r.username !== where.username) return false;
          if (where.deleted_at === null && r.deleted_at !== null) return false;
          return true;
        });
        return Promise.resolve(match ?? null);
      }),
      findMany: jest.fn().mockImplementation(() =>
        Promise.resolve(Object.values(rows).filter((r) => r.deleted_at === null)),
      ),
      create: jest.fn().mockImplementation(({ data }) => {
        const row = fakeRow({ id: `01900000-0000-7000-8000-${String(++seq).padStart(12, '0')}`, ...data });
        rows[row.id as string] = row;
        return Promise.resolve(row);
      }),
      update: jest.fn().mockImplementation(({ where, data }) => {
        rows[where.id] = { ...rows[where.id], ...data };
        return Promise.resolve(rows[where.id]);
      }),
    },
    package: {
      findFirst: jest.fn().mockResolvedValue({ id: '00000000-0000-0000-0000-000000000000' }),
      upsert: jest.fn().mockResolvedValue({ id: '00000000-0000-0000-0000-000000000000' }),
    },
    $transaction: jest.fn().mockImplementation(async (fn) => fn(prisma)),
  };
  const agent = {
    accountCreate: jest.fn().mockResolvedValue({ uid: 2101, gid: 2101, homedir: '/home/alice' }),
    accountSuspend: jest.fn().mockResolvedValue(undefined),
    accountDelete: jest.fn().mockResolvedValue(undefined),
    accountUsage: jest.fn().mockResolvedValue({ disk_mb: 12, cpu_percent: 0.4 }),
  };
  const audit = new InMemoryAuditService();
  const svc = new AccountsService(prisma as never, agent as never, audit);
  return { svc, prisma, agent, audit, rows };
}

describe('AccountsService (M0 slice)', () => {
  it('creates an account via the agent and persists it with an audit entry atomically', async () => {
    const { svc, agent, audit } = await makeService();

    const account = await svc.create('alice', 'pkg-default', ACTOR);

    expect(agent.accountCreate).toHaveBeenCalledWith('alice', '00000000-0000-0000-0000-000000000000');
    expect(account).toMatchObject({ username: 'alice', status: 'active', uid: 2101, homedir: '/home/alice' });

    const last = audit.list().at(-1)!;
    expect(last.operation).toBe('account.create');
    expect(last.actorUserId).toBe(ACTOR);
  });

  it('rejects reserved or malformed usernames before touching the agent', async () => {
    const { svc, agent } = await makeService();
    await expect(svc.create('root', 'pkg-default', ACTOR)).rejects.toThrow(BadRequestException);
    await expect(svc.create('Bad_Name', 'pkg-default', ACTOR)).rejects.toThrow(BadRequestException);
    expect(agent.accountCreate).not.toHaveBeenCalled();
  });

  it('rejects duplicate usernames', async () => {
    const { svc } = await makeService();
    await svc.create('alice', 'pkg-default', ACTOR);
    await expect(svc.create('alice', 'pkg-default', ACTOR)).rejects.toThrow('account exists');
  });

  it('suspend and resume flip the status and audit the action', async () => {
    const { svc, audit, agent } = await makeService();
    const account = await svc.create('alice', 'pkg-default', ACTOR);

    const suspended = await svc.suspend(account.id, ACTOR);
    expect(suspended.status).toBe('suspended');
    expect(agent.accountSuspend).toHaveBeenCalledWith('alice');

    const resumed = await svc.resume(account.id, ACTOR);
    expect(resumed.status).toBe('active');

    const ops = audit.list().map((e) => e.operation);
    expect(ops).toEqual(['account.create', 'account.suspend', 'account.resume']);
  });

  it('delete terminates the row (soft-delete) and deletes the OS user via the agent', async () => {
    const { svc, agent, rows, audit } = await makeService();
    const account = await svc.create('alice', 'pkg-default', ACTOR);

    await svc.remove(account.id, ACTOR);

    expect(agent.accountDelete).toHaveBeenCalledWith('alice');
    expect(rows[account.id]!.deleted_at).toBeInstanceOf(Date);
    expect(rows[account.id]!.status).toBe('terminated');
    await expect(svc.get(account.id)).rejects.toThrow(NotFoundException);
    expect(audit.list().at(-1)!.operation).toBe('account.delete');
  });

  it('usage proxies to the agent by username', async () => {
    const { svc, agent } = await makeService();
    const account = await svc.create('alice', 'pkg-default', ACTOR);
    const usage = await svc.usage(account.id);
    expect(usage).toEqual({ disk_mb: 12, cpu_percent: 0.4 });
    expect(agent.accountUsage).toHaveBeenCalledWith('alice');
  });
});
