import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { FilesService } from './files.service';

/**
 * File manager orchestration (ADR-0008): visibility (C7, 404-not-403),
 * path anchoring, trash ledger + agent-reconciled purge, and the audit
 * trail on every mutation. The agent seam is a jest mock — its side of the
 * contract is tested in Go.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true };
const VIEWER = { userId: 'u-viewer', isSuperAdmin: false };

const ACCOUNT = {
  id: '01900000-0000-7000-8000-00000000a001',
  username: 'alice',
  homedir: '/home/alice',
};

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

function harness(opts: { access?: boolean } = {}) {
  const audit = new InMemoryAuditService();
  const trash: Record<string, unknown>[] = [];
  const prisma = {
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: { id: string } }) =>
        where.id === ACCOUNT.id ? { ...ACCOUNT } : null,
      ),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async ({ where }: { where: { user_id: string; hosting_account_id: string } }) =>
        opts.access && where.user_id === VIEWER.userId && where.hosting_account_id === where.hosting_account_id
          ? { id: 'acc-row' }
          : null,
      ),
    },
    trashEntry: {
      findMany: jest.fn(async ({ where }: { where: { hosting_account_id: string } }) =>
        trash.filter((r) => r['hosting_account_id'] === where.hosting_account_id),
      ),
      findFirst: jest.fn(async ({ where }: { where: { id: string } }) =>
        trash.find((r) => r['id'] === where.id) ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(trash.length + 50), deleted_at: new Date(), ...data };
        trash.push(row);
        return row;
      }),
      delete: jest.fn(async ({ where }: { where: { id: string } }) => {
        const i = trash.findIndex((r) => r['id'] === where.id);
        const [row] = trash.splice(i, 1);
        return row;
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };
  const agent = {
    filesystemList: jest.fn(async () => ({ path: '/home/alice', entries: [], total: 0 })),
    filesystemRead: jest.fn(async () => ({ path: '/x', size_bytes: 2, content_b64: 'aGk=', truncated: false })),
    filesystemWrite: jest.fn(async () => ({ path: '/x', written_bytes: 2, overwritten: false, ownership: 'skipped' })),
    filesystemMkdir: jest.fn(async () => ({ path: '/x', created: true })),
    filesystemDelete: jest.fn(async (_u: string, _p: string, toTrash: boolean) => ({
      path: _p,
      trash_path: toTrash ? '/home/alice/.nexus-trash/20260101T000000.000000000-x' : '',
      size_bytes: 2,
      purged: !toTrash,
    })),
    filesystemChmod: jest.fn(async () => ({ path: '/x', mode: '0644' })),
    filesystemMove: jest.fn(async () => ({ from: '/x', to: '/y' })),
    filesystemUsage: jest.fn(async () => ({ bytes: 100, inodes: 3, partial: false })),
    trashPurge: jest.fn(async () => ({ removed: ['20200101T000000.000000000-old.txt'] })),
  };
  const svc = new FilesService(
    prisma as unknown as PrismaService,
    agent as unknown as ConstructorParameters<typeof FilesService>[1],
    audit,
  );
  return { svc, prisma, agent, audit, trash };
}

describe('files visibility (C7)', () => {
  it('404s accounts the caller cannot see, and bad account ids', async () => {
    const h = harness();
    await expect(h.svc.list(VIEWER, ACCOUNT.id, '.')).rejects.toThrow(NotFoundException);
    await expect(h.svc.list(SUPER, 'not-a-uuid', '.')).rejects.toThrow(BadRequestException);
    await expect(h.svc.list(SUPER, uid(999), '.')).rejects.toThrow(NotFoundException);
  });

  it('serves callers with an active access row', async () => {
    const h = harness({ access: true });
    const res = await h.svc.list(VIEWER, ACCOUNT.id, '.');
    expect(res.total).toBe(0);
  });
});

describe('path anchoring', () => {
  it('anchors relative paths at the account home and refuses tricks', async () => {
    const h = harness();
    await h.svc.list(SUPER, ACCOUNT.id, 'docs');
    expect(h.agent.filesystemList).toHaveBeenCalledWith('alice', '/home/alice/docs');

    await expect(h.svc.list(SUPER, ACCOUNT.id, '../etc')).rejects.toThrow(/forbidden/);
    await expect(h.svc.list(SUPER, ACCOUNT.id, '/etc/passwd')).rejects.toThrow(/inside the account home/);
    await expect(h.svc.list(SUPER, ACCOUNT.id, '')).rejects.toThrow(/path is required/);
    // absolute inside home is fine
    await h.svc.list(SUPER, ACCOUNT.id, '/home/alice/docs');
    expect(h.agent.filesystemList).toHaveBeenLastCalledWith('alice', '/home/alice/docs');
  });
});

describe('trash lifecycle', () => {
  it('records a ledger row with a 30-day purge horizon on delete', async () => {
    const h = harness();
    const dto = await h.svc.deleteToTrash(SUPER, { account_id: ACCOUNT.id, path: '/home/alice/old.txt' });
    expect(dto.original_path).toBe('/home/alice/old.txt');
    expect(dto.size_bytes).toBe(2);
    const horizon = new Date(dto.purge_after).getTime() - new Date(dto.deleted_at).getTime();
    expect(horizon).toBeGreaterThan(29 * 24 * 3600 * 1000);
    expect(h.trash).toHaveLength(1);
    const ops = h.audit.list().filter((e) => e.operation === 'file.delete');
    expect(ops).toHaveLength(1);
    expect(ops[0].outcome).toBe('success');
  });

  it('refuses to delete the account home', async () => {
    const h = harness();
    await expect(
      h.svc.deleteToTrash(SUPER, { account_id: ACCOUNT.id, path: '/home/alice' }),
    ).rejects.toThrow(/home cannot be deleted/);
  });

  it('purge reconciles the ledger against what the agent removed', async () => {
    const h = harness();
    // One entry whose trash file the agent removed (old name), one it did not.
    h.trash.push({
      id: uid(60),
      hosting_account_id: ACCOUNT.id,
      original_path: '/home/alice/a',
      trash_path: '/home/alice/.nexus-trash/20200101T000000.000000000-old.txt',
      size_bytes: 1,
      deleted_at: new Date(Date.now() - 40 * 24 * 3600 * 1000),
      purge_after: new Date(Date.now() - 10 * 24 * 3600 * 1000),
    });
    h.trash.push({
      id: uid(61),
      hosting_account_id: ACCOUNT.id,
      original_path: '/home/alice/b',
      trash_path: '/home/alice/.nexus-trash/20200101T000000.000000000-stuck.txt',
      size_bytes: 1,
      deleted_at: new Date(Date.now() - 40 * 24 * 3600 * 1000),
      purge_after: new Date(Date.now() - 10 * 24 * 3600 * 1000),
    });
    const res = await h.svc.purgeTrash(SUPER, ACCOUNT.id);
    expect(res.removed).toBe(1); // only the entry the agent actually removed
    expect(h.trash).toHaveLength(1);
    expect(h.trash[0]['trash_path']).toContain('stuck');
  });

  it('restore moves the file back and drops the ledger row', async () => {
    const h = harness();
    h.trash.push({
      id: uid(62),
      hosting_account_id: ACCOUNT.id,
      original_path: '/home/alice/back.txt',
      trash_path: '/home/alice/.nexus-trash/20200101T000000.000000000-back.txt',
      size_bytes: 1,
      deleted_at: new Date(),
      purge_after: new Date(),
    });
    await h.svc.restoreTrash(SUPER, uid(62));
    expect(h.agent.filesystemMove).toHaveBeenCalledWith(
      'alice',
      '/home/alice/.nexus-trash/20200101T000000.000000000-back.txt',
      '/home/alice/back.txt',
    );
    expect(h.trash).toHaveLength(0);
  });
});

describe('mutations are audited', () => {
  it('mkdir audits success and failure', async () => {
    const h = harness();
    await h.svc.mkdir(SUPER, { account_id: ACCOUNT.id, path: 'newdir' });
    h.agent.filesystemMkdir.mockRejectedValueOnce(new Error('agent unreachable'));
    await expect(h.svc.mkdir(SUPER, { account_id: ACCOUNT.id, path: 'newdir' })).rejects.toThrow(
      'agent unreachable',
    );
    const ops = h.audit.list().filter((e) => e.operation === 'file.mkdir');
    expect(ops.map((o) => o.outcome).sort()).toEqual(['failure', 'success']);
  });

  it('chmod validates the mode range', async () => {
    const h = harness();
    await expect(
      h.svc.chmod(SUPER, { account_id: ACCOUNT.id, path: 'f', mode: 0 }),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.chmod(SUPER, { account_id: ACCOUNT.id, path: 'f', mode: 0o10000 }),
    ).rejects.toThrow(BadRequestException);
  });
});
