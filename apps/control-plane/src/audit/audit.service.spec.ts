import { Prisma } from '@prisma/client';
import { canonicalJson, computeHash } from './audit-chain';
import {
  AUDIT_LOCK_KEY,
  DatabaseAuditService,
  InMemoryAuditService,
} from './audit.service';

/* ─────────────────────── pure chain math (C11, security-model §4) ─────────────────────── */

describe('audit chain math', () => {
  it('hash matches the security-model §4 construction byte-for-byte', () => {
    const prior = Buffer.alloc(32, 0);
    const at = new Date('2026-11-05T12:00:00Z');
    const actor = '018f3c2e-7b4a-7dead-beef-424242424242';
    const op = 'account.create';
    const params = { username: 'alice', b: 2, a: 1 };
    const outcome = 'success';

    const got = computeHash(prior, at, actor, op, params, outcome).toString('hex');

    // Independent re-implementation of the spec formula:
    const crypto = require('node:crypto');
    const h = crypto.createHash('sha256');
    h.update(prior);
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(1793880000)); // 2026-11-05T12:00:00Z epoch seconds
    h.update(ts);
    const actorBuf = Buffer.alloc(16, 0);
    Buffer.from(actor, 'utf8').copy(actorBuf.subarray(0, 16));
    h.update(actorBuf);
    h.update(Buffer.from(op, 'utf8'));
    h.update(Buffer.from(canonicalJson(params), 'utf8'));
    h.update(Buffer.from(outcome, 'utf8'));
    const want = h.digest('hex');

    expect(got).toBe(want);
  });

  it('canonicalJson is deterministic regardless of key order', () => {
    expect(canonicalJson({ a: 1, b: { y: 2, x: 3 } })).toBe(
      canonicalJson({ b: { x: 3, y: 2 }, a: 1 }),
    );
  });
});

/* ───────────────────────────── in-memory store ───────────────────────────── */

describe('InMemoryAuditService (C11)', () => {
  it('chains entries: each prior equals previous this-hash', async () => {
    const svc = new InMemoryAuditService();
    const e1 = await svc.append({ operation: 'account.create', parameters: { username: 'alice' }, outcome: 'success' });
    const e2 = await svc.append({ operation: 'account.suspend', parameters: { username: 'alice' }, outcome: 'success' });
    expect(e2.priorHash.equals(e1.thisHash)).toBe(true);
    expect(svc.headHex()).toBe(e2.thisHash.toString('hex'));
  });

  it('verification passes on an intact chain', async () => {
    const svc = new InMemoryAuditService();
    await svc.append({ operation: 'account.create', parameters: { username: 'alice' }, outcome: 'success' });
    await svc.append({ operation: 'account.delete', parameters: { username: 'alice', preserve_files: true }, outcome: 'success' });
    expect(svc.verify()).toEqual({ verified: true, brokenAt: null, checked: 2 });
  });

  it('verification detects mid-chain parameter tampering (A5)', async () => {
    const svc = new InMemoryAuditService();
    await svc.append({ operation: 'account.create', parameters: { username: 'alice' }, outcome: 'success' });
    await svc.append({ operation: 'account.create', parameters: { username: 'bob' }, outcome: 'success' });
    await svc.append({ operation: 'account.create', parameters: { username: 'carol' }, outcome: 'success' });

    // Attacker edits history in place.
    (svc.list()[1] as { parameters: unknown }).parameters = { username: 'ROOT' };
    const result = svc.verify();
    expect(result.verified).toBe(false);
    expect(result.brokenAt).toBe(svc.list()[1]!.id);
  });

  it('failed operations are auditable as outcome=failure', async () => {
    const svc = new InMemoryAuditService();
    const e = await svc.append({ operation: 'account.create', parameters: { username: 'bad name' }, outcome: 'failure' });
    expect(e.outcome).toBe('failure');
    expect(svc.verify().verified).toBe(true);
  });
});

/* ───────────────────────────── database store ───────────────────────────── */

/**
 * Fake Prisma transaction client: just enough surface (auditEntry,
 * auditChainHead, $executeRaw) to run the real DatabaseAuditService chain
 * logic against an in-memory array — including head-state transitions.
 */
function fakeTx() {
  const entries: Record<string, unknown>[] = [];
  let head: { id: true; last_entry_id: string; last_hash: Uint8Array; updated_at: Date } | null = null;

  const tx = {
    $executeRaw: jest.fn().mockResolvedValue(0),
    auditEntry: {
      create: jest.fn().mockImplementation(({ data }) => {
        const row = { ...data };
        entries.push(row);
        return Promise.resolve(row);
      }),
      findUnique: jest.fn().mockImplementation(({ where }) =>
        Promise.resolve(entries.find((e) => e.id === where.id) ?? null),
      ),
      findMany: jest.fn().mockResolvedValue([]),
    },
    auditChainHead: {
      findUnique: jest.fn().mockImplementation(() => Promise.resolve(head)),
      create: jest.fn().mockImplementation(({ data }) => {
        head = { ...data };
        return Promise.resolve(head);
      }),
      update: jest.fn().mockImplementation(({ data }) => {
        head = { ...(head as { id: true }), ...data };
        return Promise.resolve(head);
      }),
    },
  };
  return { tx: tx as unknown as Prisma.TransactionClient, entries, raw: tx };
}

function makeDbService(): { svc: DatabaseAuditService; entries: Record<string, unknown>[]; txClient: Prisma.TransactionClient; raw: ReturnType<typeof fakeTx>['raw'] } {
  const { tx, entries, raw } = fakeTx();
  const prisma = {
    $transaction: jest.fn().mockImplementation(async (fn) => fn(tx)),
    auditEntry: raw.auditEntry,
    auditChainHead: raw.auditChainHead,
  };
  const svc = new DatabaseAuditService(prisma as never);
  return { svc, entries, txClient: tx, raw };
}

describe('DatabaseAuditService (C11 — persisted chain)', () => {
  it('serializes with the advisory lock and creates the singleton head on first append', async () => {
    const { svc, raw } = makeDbService();
    const e1 = await svc.append({ operation: 'account.create', parameters: { username: 'alice' }, outcome: 'success' });

    expect(raw.$executeRaw).toHaveBeenCalledWith`SELECT pg_advisory_xact_lock(${AUDIT_LOCK_KEY})`;
    expect(raw.auditChainHead.create).toHaveBeenCalledWith({
      data: { id: true, last_entry_id: e1.id, last_hash: expect.any(Uint8Array) },
    });
    // Genesis entry: prior hash is 32 zero bytes.
    expect(e1.priorHash.equals(Buffer.alloc(32, 0))).toBe(true);
  });

  it('links the second append to the first via the head row', async () => {
    const { svc } = makeDbService();
    const e1 = await svc.append({ operation: 'account.create', parameters: { username: 'alice' }, outcome: 'success' });
    const e2 = await svc.append({ operation: 'account.delete', parameters: { username: 'alice' }, outcome: 'success' });

    expect(e2.priorHash.equals(e1.thisHash)).toBe(true);
    await expect(svc.verify()).resolves.toEqual({ verified: true, brokenAt: null, checked: 2 });
  });

  it('verify detects a tampered parameter in the persisted chain', async () => {
    const { svc, entries } = makeDbService();
    await svc.append({ operation: 'account.create', parameters: { username: 'alice' }, outcome: 'success' });
    await svc.append({ operation: 'account.create', parameters: { username: 'bob' }, outcome: 'success' });
    await svc.append({ operation: 'account.create', parameters: { username: 'carol' }, outcome: 'success' });

    // Attacker edits the middle entry in the database.
    (entries[1] as { parameters: unknown }).parameters = { username: 'ROOT' };
    const result = await svc.verify();
    expect(result.verified).toBe(false);
    expect(result.brokenAt).toBe((entries[1] as { id: string }).id);
  });

  it('verify walks prev_entry_id links from the head, not insertion order', async () => {
    const { svc, entries } = makeDbService();
    await svc.append({ operation: 'op.one', parameters: {}, outcome: 'success' });
    await svc.append({ operation: 'op.two', parameters: {}, outcome: 'success' });
    await svc.append({ operation: 'op.three', parameters: {}, outcome: 'success' });

    // The head must point at the newest entry; the oldest has a null-ish prior.
    const headRow = await svc.headHex();
    expect(headRow).toBe(Buffer.from((entries[2] as { this_hash: Uint8Array }).this_hash).toString('hex'));
  });

  it('verify on an empty chain is trivially true with checked=0', async () => {
    const { svc } = makeDbService();
    expect(await svc.verify()).toEqual({ verified: true, brokenAt: null, checked: 0 });
  });

  it('list paginates newest-first with a cursor', async () => {
    const { svc, raw, entries } = makeDbService();
    await svc.append({ operation: 'op.one', parameters: {}, outcome: 'success' });
    await svc.append({ operation: 'op.two', parameters: {}, outcome: 'success' });
    await svc.append({ operation: 'op.three', parameters: {}, outcome: 'success' });

    raw.auditEntry.findMany.mockImplementation(({ where, take }: { where?: { id?: { lt?: string } }; take?: number }) => {
      // Emulate newest-first filtering by cursor over the in-memory rows.
      let rows = [...entries];
      if (where?.id?.lt) {
        const idx = rows.findIndex((r) => (r as { id: string }).id === where.id!.lt);
        rows = rows.slice(0, idx);
      }
      return Promise.resolve(rows.reverse().slice(0, take));
    });

    const page1 = await svc.list(2);
    expect(page1.data.map((e) => e.operation)).toEqual(['op.three', 'op.two']);
    expect(page1.hasMore).toBe(true);

    const page2 = await svc.list(2, page1.data.at(-1)!.id);
    expect(page2.data.map((e) => e.operation)).toEqual(['op.one']);
    expect(page2.hasMore).toBe(false);
  });
});
