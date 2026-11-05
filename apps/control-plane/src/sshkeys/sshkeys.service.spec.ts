import { ConflictException, NotFoundException } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { SshKeysService } from './sshkeys.service';

/**
 * SSH keys: strict key validation, fingerprint computed at import (and
 * asserted against the well-known test vector), duplicate rejection, and
 * soft-delete with audit.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true };

const ACCOUNT = { id: '01900000-0000-7000-8000-00000000a001', username: 'alice' };

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

// A REAL ed25519 OpenSSH wire blob, built in-test: 4-byte len + type +
// 4-byte len + 32-byte point — so the base64 body and its fingerprint are
// always self-consistent.
const ED25519_PUB = Buffer.alloc(32, 7);
const ED25519_BODY = (() => {
  const type = Buffer.from('ssh-ed25519');
  const tlen = Buffer.alloc(4);
  tlen.writeUInt32BE(type.length, 0);
  const klen = Buffer.alloc(4);
  klen.writeUInt32BE(ED25519_PUB.length, 0);
  return Buffer.concat([tlen, type, klen, ED25519_PUB]).toString('base64');
})();
const ED25519_KEY = `ssh-ed25519 ${ED25519_BODY} test@laptop`;
const ED25519_FINGERPRINT = `SHA256:${crypto
  .createHash('sha256')
  .update(Buffer.from(ED25519_BODY, 'base64'))
  .digest('base64')
  .replace(/=+$/, '')}`;

function harness() {
  const audit = new InMemoryAuditService();
  const keys: Record<string, unknown>[] = [];
  const prisma = {
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: { id: string } }) =>
        where.id === ACCOUNT.id ? { ...ACCOUNT } : null,
      ),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async () => null),
    },
    sshKey: {
      findMany: jest.fn(async ({ select }: { select?: unknown }) =>
        keys.map((k) => (select ? Object.fromEntries(Object.keys(select as string[]).map((f) => [f, k[f]])) : k)),
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        keys.find(
          (k) =>
            (where['id'] === undefined || k['id'] === where['id']) &&
            (where['fingerprint'] === undefined || k['fingerprint'] === where['fingerprint']) &&
            k['deleted_at'] === null,
        ) ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: uid(keys.length + 70), ...data, created_at: new Date(), deleted_at: null };
        keys.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = keys.find((k) => k['id'] === where.id);
        Object.assign(row!, data);
        return row;
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };
  const agent = {
    sshDeployKeys: jest.fn(async (_username: string, ks: Array<{ fingerprint: string }>) => ({
      file: '/home/alice/.ssh/authorized_keys',
      managed_count: ks.length,
      foreign_count: 1,
      ownership: 'account-owned',
    })),
    sshListDeployed: jest.fn(async (_username: string) => ({
      file: '/home/alice/.ssh/authorized_keys',
      exists: true,
      managed: [] as Array<{ fingerprint: string; public_key: string }>,
      foreign_count: 0,
      ownership: 'account-owned',
    })),
  };
  const svc = new SshKeysService(prisma as unknown as PrismaService, agent as never, audit);
  return { svc, keys, audit, prisma, agent };
}

describe('ssh keys', () => {
  it('imports a valid key with the correct SHA-256 fingerprint', async () => {
    const h = harness();
    const dto = await h.svc.create(SUPER, {
      account_id: ACCOUNT.id,
      name: 'laptop',
      public_key: ED25519_KEY,
    });
    expect(dto.fingerprint).toBe(ED25519_FINGERPRINT);
    expect(h.keys).toHaveLength(1);
  });

  it('rejects garbage keys, wrong types and oversized names', async () => {
    const h = harness();
    await expect(
      h.svc.create(SUPER, { account_id: ACCOUNT.id, name: 'x', public_key: 'not a key' }),
    ).rejects.toThrow(/OpenSSH single-line/);
    await expect(
      h.svc.create(SUPER, {
        account_id: ACCOUNT.id,
        name: 'x',
        public_key: 'ssh-dsa AAAAB3NzaC1kc3MAA test',
      }),
    ).rejects.toThrow(/OpenSSH single-line/);
    await expect(
      h.svc.create(SUPER, {
        account_id: ACCOUNT.id,
        name: 'k'.repeat(101),
        public_key: ED25519_KEY,
      }),
    ).rejects.toThrow(/name is required/);
  });

  it('rejects duplicate fingerprints', async () => {
    const h = harness();
    await h.svc.create(SUPER, { account_id: ACCOUNT.id, name: 'a', public_key: ED25519_KEY });
    await expect(
      h.svc.create(SUPER, { account_id: ACCOUNT.id, name: 'b', public_key: ED25519_KEY }),
    ).rejects.toThrow(ConflictException);
  });

  it('soft-deletes and 404s unknown ids', async () => {
    const h = harness();
    const dto = await h.svc.create(SUPER, { account_id: ACCOUNT.id, name: 'a', public_key: ED25519_KEY });
    await h.svc.remove(SUPER, dto.id);
    expect(h.keys[0]['deleted_at']).not.toBeNull();
    await expect(h.svc.remove(SUPER, dto.id)).rejects.toThrow(NotFoundException);
    await expect(h.svc.remove(SUPER, 'nope')).rejects.toThrow(NotFoundException);
  });

  it('404s accounts the caller cannot see', async () => {
    const h = harness();
    await expect(
      h.svc.create({ userId: 'u2', isSuperAdmin: false }, { account_id: ACCOUNT.id, name: 'a', public_key: ED25519_KEY }),
    ).rejects.toThrow(NotFoundException);
  });
});

describe('ssh key deployment (ADR-0010)', () => {
  it('deploys every stored key to the node and audits the reconcile', async () => {
    const h = harness();
    await h.svc.create(SUPER, { account_id: ACCOUNT.id, name: 'laptop', public_key: ED25519_KEY });
    const out = await h.svc.deploy(SUPER, ACCOUNT.id);
    expect(out).toEqual({ deployed: 1, foreign_preserved: 1, ownership: 'account-owned' });
    expect(h.agent.sshDeployKeys).toHaveBeenCalledWith('alice', [
      { fingerprint: ED25519_FINGERPRINT, public_key: ED25519_KEY },
    ]);
    const ops = h.audit.list().filter((e) => e.operation === 'sshkey.deploy');
    expect(ops).toHaveLength(1);
    expect(ops[0]['outcome']).toBe('success');
  });

  it('deploys the empty set when no keys are stored (removes managed lines only)', async () => {
    const h = harness();
    const out = await h.svc.deploy(SUPER, ACCOUNT.id);
    expect(out.deployed).toBe(0);
    expect(h.agent.sshDeployKeys).toHaveBeenCalledWith('alice', []);
  });

  it('audits failures and rethrows agent errors', async () => {
    const h = harness();
    h.agent.sshDeployKeys.mockRejectedValueOnce(new Error('agent unreachable'));
    await expect(h.svc.deploy(SUPER, ACCOUNT.id)).rejects.toThrow('agent unreachable');
    const ops = h.audit.list().filter((e) => e.operation === 'sshkey.deploy');
    expect(ops[0]['outcome']).toBe('failure');
  });

  it('reports live on-node state matched against stored fingerprints', async () => {
    const h = harness();
    const a = await h.svc.create(SUPER, { account_id: ACCOUNT.id, name: 'on-node', public_key: ED25519_KEY });
    h.keys.push({
      id: uid(999), hosting_account_id: ACCOUNT.id, name: 'not-yet',
      public_key: ED25519_KEY, fingerprint: 'SHA256:different',
      created_at: new Date(), deleted_at: null,
    });
    const other = { id: uid(999) };
    h.agent.sshListDeployed.mockResolvedValueOnce({
      file: '/home/alice/.ssh/authorized_keys',
      exists: true,
      managed: [{ fingerprint: ED25519_FINGERPRINT, public_key: ED25519_KEY }],
      foreign_count: 2,
      ownership: 'account-owned',
    });
    const out = await h.svc.deployed(SUPER, ACCOUNT.id);
    expect(out.exists).toBe(true);
    expect(out.foreign_count).toBe(2);
    const byId = Object.fromEntries(out.data.map((d) => [d.ssh_key_id, d]));
    expect(byId[a.id].on_node).toBe(true);
    expect(byId[other.id].on_node).toBe(false);
  });

  it('404s deployment surfaces for unknown accounts', async () => {
    const h = harness();
    await expect(h.svc.deploy(SUPER, '01900000-0000-7000-8000-0000000000ff')).rejects.toThrow(
      NotFoundException,
    );
    await expect(h.svc.deployed(SUPER, '01900000-0000-7000-8000-0000000000ff')).rejects.toThrow(
      NotFoundException,
    );
  });
});
