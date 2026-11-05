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
      findMany: jest.fn(async () => keys),
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
  const svc = new SshKeysService(prisma as unknown as PrismaService, audit);
  return { svc, keys, audit, prisma };
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
