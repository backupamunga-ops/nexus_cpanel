import { PrismaService } from '../prisma/prisma.service';
import { DatabaseAuditService, InMemoryAuditService } from './audit.service';
import { AuditVerifyCronService } from './verify-cron.service';
import { NotificationsService } from '../notifications/notifications.service';

/**
 * Audit verify cron (B13, C11) — the batch-plan exit criterion:
 * a MID-CHAIN TAMPER is detected by the cron pass and becomes both a
 * super-admin notification and a failure audit entry.
 */

function harness() {
  const entries: Array<Record<string, unknown>> = [];
  const headState: { last_entry_id: string; last_hash: Uint8Array } | null = null;
  const notifications: Array<Record<string, unknown>> = [];
  const cronAudit = new InMemoryAuditService();

  const dbPrisma: Record<string, any> = {
    $transaction: jest.fn(),
    $executeRaw: jest.fn(async () => 0),
    auditEntry: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { ...data };
        entries.push(row);
        return row;
      }),
      findUnique: jest.fn(async ({ where }: { where: { id: string } }) =>
        entries.find((e) => e.id === where.id) ?? null,
      ),
    },
    auditChainHead: {
      // `headState` is re-read on every call so tests can arm it.
      findUnique: jest.fn(async () => headRef.current),
    },
    notification: {
      createMany: jest.fn(async ({ data }: { data: Array<Record<string, unknown>> }) => {
        notifications.push(...data);
        return { count: data.length };
      }),
    },
    user: { findMany: jest.fn(async () => [{ id: 'u1', is_super_admin: true }]) },
  };

  // Mutable head handle (the singleton row the DB would hold).
  const headRef: { current: { last_entry_id: string; last_hash: Uint8Array } | null } = {
    current: null,
  };

  const dbAudit = new DatabaseAuditService(dbPrisma as unknown as PrismaService);
  const notificationsSvc = new NotificationsService(dbPrisma as unknown as PrismaService);
  const cron = new AuditVerifyCronService(dbAudit, notificationsSvc, cronAudit);
  return { cron, dbAudit, entries, notifications, cronAudit, headRef };
}

describe('audit verify cron (B13, C11)', () => {
  it('an unarmed head verifies silently (no notification spam)', async () => {
    const { cron, notifications } = harness();
    const res = await cron.verifyChainNow();
    expect(res.verified).toBe(true);
    expect(notifications).toHaveLength(0);
  });

  it('MID-CHAIN TAMPER: cron detects the break, alerts admins, writes a failure audit entry', async () => {
    const { cron, entries, notifications, cronAudit, headRef } = harness();
    const { computeHash } = require('./audit-chain') as {
      computeHash: (
        prior: Buffer,
        occurredAt: Date | string,
        actor: string | null,
        op: string,
        params: unknown,
        outcome: string,
      ) => Buffer;
    };

    const occurredAt = new Date('2026-11-05T10:00:00Z');
    const genesis = Buffer.alloc(32, 0);
    const h1 = computeHash(genesis, occurredAt, null, 'account.create', { username: 'alice' }, 'success');
    const h2 = computeHash(h1, occurredAt, null, 'site.create', { domain: 'alpha.demo' }, 'success');

    entries.push(
      {
        id: 'e1', occurred_at: occurredAt, actor_user_id: null,
        operation: 'account.create', parameters: { username: 'alice' },
        outcome: 'success', prior_hash: genesis, this_hash: h1, prev_entry_id: null,
      },
      {
        id: 'e2', occurred_at: occurredAt, actor_user_id: null,
        operation: 'site.create', parameters: { domain: 'alpha.demo' },
        outcome: 'success', prior_hash: h1, this_hash: h2, prev_entry_id: 'e1',
      },
    );
    headRef.current = { last_entry_id: 'e2', last_hash: h2 };

    // TAMPER: rewrite a parameter of the FIRST entry (mid-chain).
    (entries[0].parameters as Record<string, unknown>).username = 'mallory';

    const res = await cron.verifyChainNow();
    expect(res.verified).toBe(false);
    expect(res.brokenAt).toBe('e1');
    // Admins alerted…
    expect(notifications).toHaveLength(1);
    expect(notifications[0].severity).toBe('error');
    expect(String(notifications[0].title)).toContain('FAILED');
    // …and the failure became part of the chain.
    const ops = cronAudit.list().map((e) => e.operation);
    expect(ops).toContain('audit.chain.verify');
    const entry = cronAudit.list().find((e) => e.operation === 'audit.chain.verify');
    expect(entry?.outcome).toBe('failure');
  });
});
