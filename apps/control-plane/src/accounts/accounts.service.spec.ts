import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { AccountsService } from './accounts.service';
import { InMemoryAuditService } from '../audit/audit.service';

const ACTOR = '01900000-0000-7000-8000-0000000000aa';

let shareIdSeq = 0;
let userSeq = 0;

function nextShareId() {
  return `01900000-0000-7000-8000-${String(++shareIdSeq).padStart(12, '0')}`;
}

function fakeShare(
  userId: string,
  hostingAccountId: string,
  role: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    id: nextShareId(),
    user_id: userId,
    hosting_account_id: hostingAccountId,
    role,
    granted_by_user_id: null,
    created_at: new Date('2026-11-05T02:00:00Z'),
    revoked_at: null as Date | null,
    ...overrides,
  };
}

function fakeUser(email: string, overrides: Record<string, unknown> = {}) {
  return {
    id: `01900000-0000-7000-8000-${String(++userSeq).padStart(12, '0')}`,
    email,
    display_name: email.split('@')[0] ?? email,
    is_active: true,
    deleted_at: null,
    ...overrides,
  };
}

/** Generic Prisma-where matcher honoring null equality and `{ in: [...] }`. */
function matches(row: Record<string, unknown>, where: Record<string, unknown>): boolean {
  for (const [key, expected] of Object.entries(where)) {
    if (expected === null) {
      if (row[key] !== null) return false;
    } else if (typeof expected === 'object' && 'in' in (expected as object)) {
      if (!(expected as { in: unknown[] }).in.includes(row[key])) return false;
    } else if (row[key] !== expected) {
      return false;
    }
  }
  return true;
}

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
  const users: Array<Record<string, unknown>> = [];
  const shareRows: Array<Record<string, unknown>> = [];
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
      findMany: jest.fn().mockImplementation(({ where }) => {
        let out = Object.values(rows).filter((r) => r.deleted_at === null);
        // Honor the C7 access-row filter exactly like Prisma would.
        const scope =
          (where as { user_hosting_account_access__hosting_account_id?: { some: { user_id: string; revoked_at: null } } })
            ?.user_hosting_account_access__hosting_account_id?.some;
        if (scope) {
          // DB semantics: an account is visible iff the caller holds an
          // ACTIVE access row for it (the same rows the sharing API writes).
          const granted = new Set(
            shareRows
              .filter((s) => s.user_id === scope.user_id && s.revoked_at === null)
              .map((s) => s.hosting_account_id as string),
          );
          out = out.filter((r) => granted.has(r.id as string));
        }
        return Promise.resolve(out);
      }),
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
    user: {
      findFirst: jest.fn().mockImplementation(({ where }) =>
        Promise.resolve(users.find((u) => matches(u, where)) ?? null),
      ),
    },
    userHostingAccountAccess: {
      // Emulates Prisma `include`s: user + granted_by_user resolved from the
      // users registry (listShares/revokeShare read through these).
      withRelations(row: Record<string, unknown>): Record<string, unknown> {
        const target = users.find((u) => u.id === row.user_id);
        const grantor = row.granted_by_user_id
          ? users.find((u) => u.id === row.granted_by_user_id)
          : null;
        return {
          ...row,
          user: target
            ? { id: target.id, email: target.email, display_name: target.display_name }
            : null,
          granted_by_user: grantor ? { id: grantor.id, email: grantor.email } : null,
        };
      },
      findFirst: jest.fn().mockImplementation(function (this: { withRelations: (r: Record<string, unknown>) => Record<string, unknown> }, { where }) {
        const row = shareRows.find((r) => matches(r, where));
        return Promise.resolve(row ? this.withRelations(row) : null);
      }),
      findMany: jest.fn().mockImplementation(function (this: { withRelations: (r: Record<string, unknown>) => Record<string, unknown> }, { where }) {
        return Promise.resolve(shareRows.filter((r) => matches(r, where)).map((r) => this.withRelations(r)));
      }),
      create: jest.fn().mockImplementation(({ data }) => {
        const row: Record<string, unknown> = {
          id: nextShareId(),
          created_at: new Date('2026-11-05T01:00:00Z'),
          revoked_at: null,
          ...data,
        };
        // Emulate the `include` the service asks for.
        const target = users.find((u) => u.id === data.user_id);
        row.user = target
          ? { id: target.id, email: target.email, display_name: target.display_name }
          : null;
        const grantor = data.granted_by_user_id
          ? users.find((u) => u.id === data.granted_by_user_id)
          : null;
        row.granted_by_user = grantor ? { id: grantor.id, email: grantor.email } : null;
        shareRows.push(row);
        return Promise.resolve(row);
      }),
      update: jest.fn().mockImplementation(({ where, data }) => {
        const row = shareRows.find((r) => r.id === where.id)!;
        Object.assign(row, data);
        return Promise.resolve(row);
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
    accountResume: jest.fn().mockResolvedValue(undefined),
    isolationProvision: jest.fn().mockResolvedValue(undefined),
    accountDelete: jest.fn().mockResolvedValue(undefined),
    accountUsage: jest.fn().mockResolvedValue({ disk_mb: 12, cpu_percent: 0.4 }),
    accountQuota: jest
      .fn()
      .mockResolvedValue({ applied: ['cpu'], skipped: [] }),
    accountModify: jest.fn().mockResolvedValue({ status: 'active', applied: [] }),
  };
  const audit = new InMemoryAuditService();
  const svc = new AccountsService(prisma as never, agent as never, audit);
  return { svc, prisma, agent, audit, rows, users, shareRows };
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
    expect(agent.accountResume).toHaveBeenCalledWith('alice');

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

  it('provisions the isolation slice right after account.create (M0 §2.3–4)', async () => {
    const { svc, agent, audit } = await makeService();

    await svc.create('alice', 'pkg-default', ACTOR);

    expect(agent.isolationProvision).toHaveBeenCalledWith('alice', 'standard');
    // A successful provision writes no audit entry of its own — the create
    // entry covers the whole flow.
    expect(audit.list().map((e) => e.operation)).toEqual(['account.create']);
  });

  it('audits but survives an isolation.provision failure (no rollback in M0)', async () => {
    const { svc, agent, audit } = await makeService();
    agent.isolationProvision.mockRejectedValueOnce(new Error('cgroupfs not delegated'));

    const account = await svc.create('alice', 'pkg-default', ACTOR);

    expect(account.username).toBe('alice');
    const provision = audit.list().find((e) => e.operation === 'isolation.provision');
    expect(provision).toBeDefined();
    expect(provision!.outcome).toBe('failure');
  });

  it('resume failure is audited and propagates — the row stays suspended', async () => {
    const { svc, agent, audit } = await makeService();
    const account = await svc.create('alice', 'pkg-default', ACTOR);
    await svc.suspend(account.id, ACTOR);
    agent.accountResume.mockRejectedValueOnce(new Error('agent unreachable'));

    await expect(svc.resume(account.id, ACTOR)).rejects.toThrow('agent unreachable');

    const entry = audit.list().at(-1)!;
    expect(entry.operation).toBe('account.resume');
    expect(entry.outcome).toBe('failure');
    expect((await svc.get(account.id)).status).toBe('suspended');
  });

  it('C7: a non-admin lists only accounts they hold an active access row for', async () => {
    const { svc, rows, shareRows } = await makeService();
    const mine = await svc.create('alice', 'pkg-default');
    const other = await svc.create('bob', 'pkg-default');

    shareRows.push(fakeShare(ACTOR, mine.id, 'owner'));
    // Sanity: the fake rows registry holds both accounts.
    expect(Object.keys(rows)).toHaveLength(2);

    const scoped = await svc.list({ userId: ACTOR });
    expect(scoped.data.map((a) => a.id)).toEqual([mine.id]);
    expect(scoped.data[0]!.my_role).toBe('owner');

    const admin = await svc.list({ userId: ACTOR, isSuperAdmin: true });
    expect(admin.data.map((a) => a.id).sort()).toEqual([mine.id, other.id].sort());
    expect(admin.data.every((a) => a.my_role === 'super-admin')).toBe(true);

    const nobody = await svc.list({ userId: '01900000-0000-7000-8000-0000000000ff' });
    expect(nobody.data).toEqual([]);
  });
});

describe('AccountsService.updateQuotas (packages → agent quota path)', () => {
  it('merges package quotas with the override, applies via agent, persists the override partial', async () => {
    const { svc, prisma, agent, audit } = await makeService();
    const account = await svc.create('alice', 'pkg-default');

    (prisma.package.findFirst as jest.Mock).mockResolvedValue({
      id: account.package_id,
      quotas: { cpu: 2, mem_mb: 1024, disk_mb: 10240 },
    });
    agent.accountQuota.mockResolvedValue({
      applied: ['cpu', 'mem_mb', 'processes'],
      skipped: [{ key: 'disk_mb', reason: 'requires filesystem.quota (not yet enforced)' }],
    });

    const res = await svc.updateQuotas(account.id, { processes: 200, disk_mb: 20480 }, ACTOR);

    // The agent received the MERGED set (override wins).
    expect(agent.accountQuota).toHaveBeenCalledWith('alice', {
      cpu: 2,
      mem_mb: 1024,
      disk_mb: 20480,
      processes: 200,
    });
    // The DB stored the OVERRIDE partial (column semantics), not the merge.
    const txData = prisma.hostingAccount.update.mock.calls.at(-1)![0].data;
    expect(txData.quotas_override).toEqual({ processes: 200, disk_mb: 20480 });
    expect(res.quotas_override).toEqual({ processes: 200, disk_mb: 20480 });
    expect(res.applied).toEqual(['cpu', 'mem_mb', 'processes']);
    expect(res.skipped).toHaveLength(1);
    // The audit entry records the enforcement gap explicitly.
    const entry = audit.list().at(-1)!;
    expect(entry.operation).toBe('account.quota');
    expect(entry.outcome).toBe('success');
  });

  it('rejects unknown or empty overrides before touching the agent', async () => {
    const { svc, agent } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    await expect(svc.updateQuotas(account.id, { bogus_key: 5 }, ACTOR)).rejects.toThrow(BadRequestException);
    await expect(svc.updateQuotas(account.id, {}, ACTOR)).rejects.toThrow(/at least one key/);
    await expect(svc.updateQuotas(account.id, 'cpu:2', ACTOR)).rejects.toThrow(/must be an object/);
    expect(agent.accountQuota).not.toHaveBeenCalled();
  });

  it('agent failure is audited and propagates — the override is not persisted', async () => {
    const { svc, prisma, agent, audit } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    (prisma.package.findFirst as jest.Mock).mockResolvedValue({
      id: account.package_id,
      quotas: {},
    });
    agent.accountQuota.mockRejectedValue(new Error('agent unreachable'));

    await expect(svc.updateQuotas(account.id, { cpu: 1 }, ACTOR)).rejects.toThrow('agent unreachable');
    const entry = audit.list().at(-1)!;
    expect(entry.operation).toBe('account.quota');
    expect(entry.outcome).toBe('failure');
    expect(prisma.hostingAccount.update).not.toHaveBeenCalled();
  });
});

describe('AccountsService access sharing (§11.3 — user_hosting_account_access management)', () => {
  it('grants a share to an active user, records granted_by, and audits account.share.grant atomically', async () => {
    const { svc, users, shareRows, audit } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    users.push(fakeUser('owner@test.dev', { id: ACTOR }), fakeUser('bob@test.dev'));

    // Mixed-case + padded input on purpose: the service normalizes before lookup.
    const share = await svc.grantShare(account.id, '  Bob@Test.dev ', 'admin', ACTOR);

    expect(share.role).toBe('admin');
    expect(share.user.email).toBe('bob@test.dev'); // resolved from the DB row, canonical form
    expect(share.granted_by).toEqual({ id: ACTOR, email: 'owner@test.dev' });
    expect(shareRows).toHaveLength(1);
    const entry = audit.list().at(-1)!;
    expect(entry.operation).toBe('account.share.grant');
    expect(entry.outcome).toBe('success');
    expect(entry.parameters).toMatchObject({ account_id: account.id, email: 'bob@test.dev', role: 'admin' });
  });

  it('fail-closed: malformed email, unknown role, and the reserved owner role never reach a lookup', async () => {
    const { svc, users, shareRows } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    users.push(fakeUser('bob@test.dev'));

    await expect(svc.grantShare(account.id, 'not-an-email', 'admin', ACTOR)).rejects.toThrow(
      /valid email/,
    );
    await expect(svc.grantShare(account.id, 'bob@test.dev', 'ghost', ACTOR)).rejects.toThrow(
      /role must be one of/,
    );
    await expect(svc.grantShare(account.id, 'bob@test.dev', 'owner', ACTOR)).rejects.toThrow(
      /'owner' cannot be granted/,
    );
    expect(shareRows).toHaveLength(0);
  });

  it('grant: uniform 404 for unknown, deactivated and soft-deleted users (no existence oracle)', async () => {
    const { svc, users } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    users.push(
      fakeUser('idle@test.dev', { is_active: false }),
      fakeUser('gone@test.dev', { deleted_at: new Date() }),
    );

    for (const email of ['ghost@test.dev', 'idle@test.dev', 'gone@test.dev']) {
      await expect(svc.grantShare(account.id, email, 'admin', ACTOR)).rejects.toThrow(
        'no active user with that email',
      );
    }
  });

  it('grant: duplicate active row → 409, which also blocks self-grants (the caller already holds a row)', async () => {
    const { svc, users, shareRows } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    users.push(fakeUser('owner@test.dev', { id: ACTOR }), fakeUser('bob@test.dev'));

    shareRows.push(fakeShare(ACTOR, account.id, 'owner'));
    await expect(svc.grantShare(account.id, 'owner@test.dev', 'admin', ACTOR)).rejects.toThrow(
      ConflictException,
    );

    await svc.grantShare(account.id, 'bob@test.dev', 'member', ACTOR);
    await expect(svc.grantShare(account.id, 'bob@test.dev', 'admin', ACTOR)).rejects.toThrow(
      /already has active access/,
    );
    expect(shareRows).toHaveLength(2); // owner + bob — no third row was written
  });

  it('listShares: owner first, then trust descending; revoked rows excluded', async () => {
    const { svc, users, shareRows } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    const bob = fakeUser('bob@test.dev');
    const carol = fakeUser('carol@test.dev');
    users.push(fakeUser('owner@test.dev', { id: ACTOR }), bob, carol);
    const ownerShare = fakeShare(ACTOR, account.id, 'owner');
    const bobShare = fakeShare(bob.id as string, account.id, 'member');
    const carolShare = fakeShare(carol.id as string, account.id, 'admin');
    shareRows.push(carolShare, bobShare, ownerShare); // deliberately unsorted

    let list = await svc.listShares(account.id);
    expect(list.data.map((s) => [s.role, s.user.email])).toEqual([
      ['owner', 'owner@test.dev'],
      ['admin', 'carol@test.dev'],
      ['member', 'bob@test.dev'],
    ]);

    bobShare.revoked_at = new Date();
    list = await svc.listShares(account.id);
    expect(list.data.map((s) => s.user.email)).toEqual(['owner@test.dev', 'carol@test.dev']);
  });

  it('revoke soft-revokes the row and audits account.share.revoke', async () => {
    const { svc, users, shareRows, audit } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    const bob = fakeUser('bob@test.dev');
    users.push(bob);
    shareRows.push(fakeShare(bob.id as string, account.id, 'member'));

    await svc.revokeShare(account.id, shareRows[0]!.id as string, ACTOR);

    expect(shareRows[0]!.revoked_at).toBeInstanceOf(Date);
    const entry = audit.list().at(-1)!;
    expect(entry.operation).toBe('account.share.revoke');
    expect(entry.outcome).toBe('success');
    expect(entry.parameters).toMatchObject({ email: 'bob@test.dev', role: 'member' });
  });

  it('revoke: the owner row is irrevocable (409) — ownership transfer is a separate flow', async () => {
    const { svc, shareRows } = await makeService();
    const account = await svc.create('alice', 'pkg-default');
    shareRows.push(fakeShare(ACTOR, account.id, 'owner'));

    await expect(svc.revokeShare(account.id, shareRows[0]!.id as string, ACTOR)).rejects.toThrow(
      ConflictException,
    );
    expect(shareRows[0]!.revoked_at).toBeNull();
  });

  it('revoke: uniform 404 for unknown ids and rows belonging to ANOTHER account; no audit entry on a miss', async () => {
    const { svc, shareRows, audit } = await makeService();
    const mine = await svc.create('alice', 'pkg-default');
    const other = await svc.create('bob', 'pkg-default');
    const foreignShare = fakeShare('01900000-0000-7000-8000-0000000000cc', other.id, 'member');
    shareRows.push(foreignShare);

    await expect(svc.revokeShare(mine.id, foreignShare.id, ACTOR)).rejects.toThrow(NotFoundException);
    await expect(
      svc.revokeShare(mine.id, '01900000-0000-7000-8000-000000000999', ACTOR),
    ).rejects.toThrow('share not found');
    expect(foreignShare.revoked_at).toBeNull();
    expect(audit.list().some((e) => e.operation === 'account.share.revoke')).toBe(false);
  });

  it('account not found → 404 on every sharing operation (uniform, no leak of deleted accounts)', async () => {
    const { svc } = await makeService();
    await expect(svc.listShares('01900000-0000-7000-8000-0000000000e1')).rejects.toThrow(
      NotFoundException,
    );
    await expect(
      svc.grantShare('01900000-0000-7000-8000-0000000000e1', 'x@test.dev', 'admin', ACTOR),
    ).rejects.toThrow(NotFoundException);
    await expect(
      svc.revokeShare('01900000-0000-7000-8000-0000000000e1', '01900000-0000-7000-8000-0000000000e2', ACTOR),
    ).rejects.toThrow(NotFoundException);
  });
});
