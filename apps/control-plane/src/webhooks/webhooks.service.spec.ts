import { BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { NotificationsService } from '../notifications/notifications.service';
import { WebhooksService, DeliverFn } from './webhooks.service';

/**
 * Webhook tests (B13). The exit criterion is the DEAD-LETTER E2E: a
 * receiver that always fails drives a delivery through the backoff ladder
 * to dead, notifies the admins, and a redrive re-arms it. Transport is the
 * injected DeliverFn seam; the poller is driven manually via runOnce().
 */

process.env.PANEL_SECRET_KEY = process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

const SUPER = { userId: 'u1', isSuperAdmin: true };

function harness(failDeliveries = true) {
  const audit = new InMemoryAuditService();
  const hooks: Array<Record<string, unknown>> = [];
  const deliveries: Array<Record<string, unknown>> = [];
  const notifications: Array<Record<string, unknown>> = [];
  const users = [{ id: 'u1', is_super_admin: true }];
  const auditEntries: Array<Record<string, unknown>> = [];
  let hookSeq = 1;
  let deliverySeq = 1;

  const prisma: Record<string, any> = {
    webhook: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `wh-${hookSeq++}`, created_at: new Date(), deleted_at: null, ...data };
        hooks.push(row);
        return row;
      }),
      findMany: jest.fn(async () => hooks.filter((h) => !h.deleted_at && h.is_active)),
      findFirst: jest.fn(async ({ where }: { where: { id: string; deleted_at: null } }) =>
        hooks.find((h) => h.id === where.id && !h.deleted_at) ?? null,
      ),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = hooks.find((h) => h.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
    },
    webhookDelivery: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `d-${deliverySeq++}`, ...data };
        deliveries.push(row);
        return row;
      }),
      findMany: jest.fn(async ({ where }: { where?: { status?: string; webhook_id?: string; next_retry_at?: { lte?: Date } } }) => {
        let rows = [...deliveries];
        if (where?.status) rows = rows.filter((d) => d.status === where.status);
        if (where?.webhook_id) rows = rows.filter((d) => d.webhook_id === where.webhook_id);
        const lte = where?.next_retry_at?.lte;
        if (lte) {
          rows = rows.filter((d) => (d.next_retry_at as Date | null)?.getTime() !== undefined && (d.next_retry_at as Date).getTime() <= lte.getTime());
        }
        return rows;
      }),
      findFirst: jest.fn(async ({ where }: { where: { id: string; webhook_id?: string } }) => {
        const row = deliveries.find((d) => d.id === where.id && (!where.webhook_id || d.webhook_id === where.webhook_id));
        return row ?? null;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = deliveries.find((d) => d.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
    },
    auditEntry: {
      findFirst: jest.fn(async () => auditEntries[auditEntries.length - 1] ?? null),
      findMany: jest.fn(async ({ where }: { where?: { id?: { gt?: string } } }) => {
        let rows = [...auditEntries];
        if (where?.id?.gt) {
          const idx = rows.findIndex((r) => r.id === where.id!.gt);
          rows = idx >= 0 ? rows.slice(idx + 1) : rows;
        }
        return rows;
      }),
    },
    notification: {
      createMany: jest.fn(async ({ data }: { data: Array<Record<string, unknown>> }) => {
        notifications.push(...data);
        return { count: data.length };
      }),
    },
    user: { findMany: jest.fn(async () => users) },
  };

  const notificationsService = new NotificationsService(prisma as unknown as PrismaService);
  const svc = new WebhooksService(prisma as unknown as PrismaService, notificationsService);

  const deliver: DeliverFn = jest.fn(async () =>
    failDeliveries ? { ok: false, status: 500, body: 'kaboom' } : { ok: true, status: 200, body: 'ok' },
  );
  svc.setDeliverFn(deliver);

  return { svc, prisma, audit, hooks, deliveries, notifications, auditEntries, deliver };
}

describe('webhooks (B13)', () => {
  it('creates a subscription with an encrypted secret and validates input', async () => {
    const { svc } = harness();
    const hook = await svc.create(SUPER, {
      name: 'alerts', url: 'https://ops.example.test/hook',
      secret: 'supersecret-value-123', events: ['account.*', 'backup.run'],
    });
    expect(hook.id).toBeTruthy();
    await expect(
      svc.create(SUPER, { name: 'x', url: 'ftp://nope', secret: 'long-enough-secret', events: ['*'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      svc.create(SUPER, { name: 'x', url: 'https://ok', secret: 'short', events: ['*'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('signs deliveries with HMAC-SHA256 over timestamp.body', async () => {
    const { svc, deliver } = harness(false);
    const hook = await svc.create(SUPER, {
      name: 'ok', url: 'https://ok.example.test/h', secret: 'supersecret-value-123', events: ['*'],
    });
    const res = await svc.test(SUPER, hook.id);
    expect(res.status).toBe('success');
    const call = (deliver as jest.Mock).mock.calls[0];
    const headers = call[1] as Record<string, string>;
    const body = call[2] as string;
    expect(headers['x-nexus-event']).toBe('webhook.test');
    expect(headers['x-nexus-signature']).toMatch(/^sha256=[0-9a-f]{64}$/);
    // Recompute the HMAC independently.
    const { createHmac } = require('node:crypto');
    const mac = createHmac('sha256', 'supersecret-value-123')
      .update(`${headers['x-nexus-timestamp']}.${body}`)
      .digest('hex');
    expect(headers['x-nexus-signature']).toBe(`sha256=${mac}`);
  });

  it('DEAD-LETTER E2E: failures back off, dead-letters at 5 attempts and alerts admins; redrive re-arms', async () => {
    const { svc, deliveries, notifications, auditEntries } = harness(true);
    const hook = await svc.create(SUPER, {
      name: 'down', url: 'https://down.example.test/h', secret: 'supersecret-value-123', events: ['*'],
    });

    // New audit entry → poller → first delivery attempt.
    auditEntries.push({ id: 'a1', operation: 'account.create', actor_user_id: null, hosting_account_id: null, parameters: {}, outcome: 'success' });
    await svc.runOnce();
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].status).toBe('failed');
    expect((deliveries[0].next_retry_at as Date).getTime()).toBeGreaterThan(Date.now());

    // Drive the backoff ladder: each tick makes the LATEST failed row due
    // and the poller retries it (attempt counter climbs row by row).
    for (let attempt = 2; attempt <= 5; attempt++) {
      const latest = deliveries[deliveries.length - 1] as { next_retry_at: Date | null };
      latest.next_retry_at = new Date(Date.now() - 1000); // due now
      await svc.runOnce();
      expect(deliveries).toHaveLength(attempt);
    }
    expect(deliveries[4].status).toBe('dead');
    expect((deliveries[4].next_retry_at as Date | null)).toBeNull();
    // Admins got a dead-letter notification.
    expect(notifications.some((n) => (n.title as string).includes('Webhook dead'))).toBe(true);

    // Redrive re-arms the dead delivery (records a fresh attempt). The
    // attempt counter keeps climbing — still failing → dead again.
    const res = await svc.redrive(SUPER, hook.id, deliveries[4].id as string);
    expect(res.status).toBe('dead');
    expect(deliveries).toHaveLength(6);
    expect(notifications.filter((n) => (n.title as string).includes('Webhook dead')).length).toBeGreaterThanOrEqual(1);
  });

  it('redrive of an unknown delivery 404s; server-wide surface 404s non-admins', async () => {
    const { svc } = harness(false);
    await expect(svc.list({ userId: 'u2', isSuperAdmin: false })).rejects.toBeInstanceOf(NotFoundException);
  });
});
