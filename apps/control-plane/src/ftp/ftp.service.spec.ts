import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { FtpService } from './ftp.service';

/**
 * FTP accounts (ADR-0011): strict login shaping + global uniqueness,
 * root_dir confinement to the account home, agent-first provisioning
 * (failed agent call leaves no row), audited mutations, C7 404s.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true } as const;
const VIEWER = { userId: 'u-viewer', isSuperAdmin: false } as const;

const ACCOUNT = { id: '01900000-0000-7000-8000-00000000a001', username: 'alice', homedir: '/home/alice' };

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

function harness(opts: { accessRows?: Array<{ user_id: string; hosting_account_id: string }> } = {}) {
  const audit = new InMemoryAuditService();
  const accounts: Record<string, unknown>[] = [];
  const accessRows = opts.accessRows ?? [];

  const prisma = {
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = accounts.find((a) => a['id'] === where['id'] && a['deleted_at'] === null) ?? null;
        return row ? { ...row } : null;
      }),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        accessRows.find((a) => a.user_id === where['user_id'] && a.hosting_account_id === where['hosting_account_id']) ?? null,
      ),
    },
    fileAccount: {
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        accounts.filter(
          (r) =>
            r['kind'] === 'ftp' &&
            r['hosting_account_id'] === where['hosting_account_id'] &&
            r['deleted_at'] === null,
        ),
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        accounts.find(
          (r) =>
            r['kind'] === 'ftp' &&
            (where['username'] === undefined || r['username'] === where['username']) &&
            (where['id'] === undefined || r['id'] === where['id']) &&
            r['deleted_at'] === null,
        ) ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = {
          id: uid(accounts.length + 50),
          kind: 'ftp',
          ...data,
          created_at: new Date(),
          updated_at: new Date(),
          deleted_at: null,
          hosting_account: { username: ACCOUNT.username },
        };
        accounts.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = accounts.find((r) => r['id'] === where.id);
        Object.assign(row!, data);
        return row;
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };

  const agent = {
    ftpCreateAccount: jest.fn(async (input: { ftp_username: string; root_dir: string; read_only: boolean }) => ({
      status: 'created',
      root_dir: input.root_dir,
      read_only: input.read_only,
      userdb: { rebuilt: true },
    })),
    ftpDeleteAccount: jest.fn(async (_u: string) => ({ status: 'removed', userdb: { rebuilt: true } })),
    ftpSetPassword: jest.fn(async (_u: string, _p: string) => ({ status: 'updated', userdb: { rebuilt: true } })),
    ftpListAccounts: jest.fn(async () => ({ accounts: [] })),
  };

  const svc = new FtpService(prisma as unknown as PrismaService, agent as never, audit);
  accounts.push({ ...ACCOUNT, kind: 'account', deleted_at: null });
  return { svc, agent, audit, accounts, prisma };
}

describe('ftp accounts (ADR-0011)', () => {
  it('creates with a confined default root and audits the provisioning', async () => {
    const h = harness();
    const dto = await h.svc.create(SUPER, {
      account_id: ACCOUNT.id,
      username: 'Alice.Web',
      password: 's3cretpass',
    });
    expect(dto.username).toBe('alice.web');
    expect(dto.root_dir).toBe('/home/alice');
    expect(h.agent.ftpCreateAccount).toHaveBeenCalledWith({
      owner_username: 'alice',
      ftp_username: 'alice.web',
      password: 's3cretpass',
      root_dir: '/home/alice',
      read_only: false,
    });
    const ops = h.audit.list().filter((e) => e.operation === 'ftp.create');
    expect(ops).toHaveLength(1);
    expect(ops[0]['outcome']).toBe('success');
  });

  it('rejects bad logins, weak passwords and escaping root dirs before any agent call', async () => {
    const h = harness();
    await expect(
      h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'bad login!', password: 's3cretpass' }),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'ok.user', password: 'short' }),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'ok.user', password: 's3cretpass', root_dir: '../../etc' }),
    ).rejects.toThrow(BadRequestException);
    expect(h.agent.ftpCreateAccount).not.toHaveBeenCalled();
    expect(h.accounts.filter((r) => r['kind'] === 'ftp')).toHaveLength(0);
  });

  it('conflicts on a globally duplicated login', async () => {
    const h = harness();
    await h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'shared.login', password: 's3cretpass' });
    await expect(
      h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'shared.login', password: 's3cretpass' }),
    ).rejects.toThrow(ConflictException);
  });

  it('leaves no row when the agent fails, and audits the failure', async () => {
    const h = harness();
    h.agent.ftpCreateAccount.mockRejectedValueOnce(new Error('agent unreachable'));
    await expect(
      h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'doomed.login', password: 's3cretpass' }),
    ).rejects.toThrow('agent unreachable');
    expect(h.accounts.filter((r) => r['kind'] === 'ftp')).toHaveLength(0);
    const ops = h.audit.list().filter((e) => e.operation === 'ftp.create');
    expect(ops[0]['outcome']).toBe('failure');
  });

  it('scopes listing to the account and 404s invisible accounts (C7)', async () => {
    const h = harness({ accessRows: [] });
    await h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'mine.login', password: 's3cretpass' });
    const out = await h.svc.list(SUPER, ACCOUNT.id);
    expect(out.data).toHaveLength(1);
    await expect(h.svc.list(VIEWER, ACCOUNT.id)).rejects.toThrow(NotFoundException);
  });

  it('rotates passwords through the agent and 404s invisible rows', async () => {
    const h = harness();
    const dto = await h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'pw.login', password: 's3cretpass' });
    await h.svc.setPassword(SUPER, dto.id, { password: 'n3wpassword' });
    expect(h.agent.ftpSetPassword).toHaveBeenCalledWith('pw.login', 'n3wpassword');
    await expect(h.svc.setPassword(SUPER, dto.id, { password: 'short' })).rejects.toThrow(BadRequestException);
    await expect(h.svc.setPassword(VIEWER, dto.id, { password: 'n3wpassword' })).rejects.toThrow(NotFoundException);
  });

  it('removes through the agent then soft-deletes; failure keeps the row', async () => {
    const h = harness();
    const dto = await h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'rm.login', password: 's3cretpass' });
    await h.svc.remove(SUPER, dto.id);
    expect(h.agent.ftpDeleteAccount).toHaveBeenCalledWith('rm.login');
    const row = h.accounts.find((r) => r['id'] === dto.id) as Record<string, unknown>;
    expect(row['deleted_at']).not.toBeNull();

    h.agent.ftpDeleteAccount.mockRejectedValueOnce(new Error('agent down'));
    const doomed = await h.svc.create(SUPER, { account_id: ACCOUNT.id, username: 'doomed.rm', password: 's3cretpass' });
    await expect(h.svc.remove(SUPER, doomed.id)).rejects.toThrow('agent down');
    const kept = h.accounts.find((r) => r['id'] === doomed.id) as Record<string, unknown>;
    expect(kept['deleted_at']).toBeNull();
    const ops = h.audit.list().filter((e) => e.operation === 'ftp.delete');
    expect(ops.map((o) => o['outcome'])).toEqual(['success', 'failure']);
  });
});
