import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { getSecretBox } from '../common/secretbox';
import { NotificationsService } from '../notifications/notifications.service';
import { Actor } from '../sites/sites.service';

/**
 * Outbound webhooks (API spec §4.22, security model §9.4) — B13.
 *
 * Delivery contract:
 *   - POST JSON `{ event, occurred_at, data }` to the subscriber URL;
 *   - `X-Nexus-Event` carries the event type; `X-Nexus-Timestamp` the unix
 *     seconds; `X-Nexus-Signature` is `sha256=<HMAC-SHA256(secret,
 *     timestamp + '.' + rawBody)>` (GitHub-style signing: replay-resistant
 *     when the receiver checks the timestamp window);
 *   - the secret is stored as a SecretBox envelope (ADR-0009) and decrypted
 *     only at delivery time — it is never returned by any endpoint;
 *   - failures retry with exponential backoff (30s · 2^(attempt-1), capped
 *     at 1h) for up to 5 attempts, then the delivery is DEAD;
 *   - redrive re-delivers a dead delivery on demand (attempt counter keeps
 *     climbing, status returns to the retry loop);
 *   - subscription patterns: exact event names, `*` (everything) or family
 *     wildcards like `account.*` / `backup.*`.
 *
 * Dispatch source: the audit chain. A lightweight in-process poller tails
 * `audit_entries` (cursor = last seen id) and fans out matching deliveries.
 * No broker is required for v1.0 single-node deployments; the BullMQ
 * migration (if/when multi-node lands) replaces only the poller, not the
 * delivery contract (documented in ADR-0018).
 */

const MAX_ATTEMPTS = 5;
const BACKOFF_BASE_SEC = 30;
const BACKOFF_CAP_SEC = 3600;
const POLL_INTERVAL_MS = 5_000;
const DELIVERY_TIMEOUT_MS = 5_000;

export type DeliverFn = (
  url: string,
  headers: Record<string, string>,
  body: string,
) => Promise<{ ok: boolean; status: number; body: string }>;

export const EVENT_FAMILIES = [
  'account',
  'site',
  'dns',
  'mail',
  'db',
  'backup',
  'ssl',
  'firewall',
  'malware',
  'waf',
  'auth',
] as const;

@Injectable()
export class WebhooksService {
  private readonly logger = new Logger(WebhooksService.name);
  private cursor: string | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  /** Injected transport (tests); default is a real fetch. */
  private deliverFn: DeliverFn = async (url, headers, body) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), DELIVERY_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body,
        signal: ctrl.signal,
      });
      const text = await res.text().catch(() => '');
      return { ok: res.ok, status: res.status, body: text.slice(0, 512) };
    } catch (e) {
      return { ok: false, status: 0, body: (e as Error).message.slice(0, 512) };
    } finally {
      clearTimeout(t);
    }
  };

  constructor(
    private readonly prisma: PrismaService,
    private readonly notifications: NotificationsService,
  ) {}

  /** Test seam: replace the HTTP transport. */
  setDeliverFn(fn: DeliverFn): void {
    this.deliverFn = fn;
  }

  // ---- subscription CRUD -----------------------------------------------------

  async list(actor?: Actor) {
    if (!actor?.isSuperAdmin) throw new NotFoundException('webhook not found');
    const rows = await this.prisma.webhook.findMany({
      where: { deleted_at: null },
      orderBy: { created_at: 'asc' },
      include: {
        webhook_deliveries__webhook_id: {
          orderBy: { attempted_at: 'desc' },
          take: 1,
          select: { status: true, attempted_at: true },
        },
      },
    });
    return {
      data: rows.map((w) => ({
        id: w.id,
        name: w.name,
        url: w.url,
        events: w.events,
        is_active: w.is_active,
        last_delivery: w.webhook_deliveries__webhook_id[0]
          ? { status: w.webhook_deliveries__webhook_id[0].status, attempted_at: w.webhook_deliveries__webhook_id[0].attempted_at.toISOString() }
          : null,
        created_at: w.created_at.toISOString(),
      })),
    };
  }

  async create(actor: Actor | undefined, input: Record<string, unknown>) {
    if (!actor?.isSuperAdmin) {
      throw new NotFoundException('webhook not found'); // anti-enumeration for a server-wide surface
    }
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    const url = typeof input.url === 'string' ? input.url.trim() : '';
    const secret = typeof input.secret === 'string' ? input.secret : '';
    const events = Array.isArray(input.events) ? input.events.map(String) : [];
    if (!name || name.length > 120) throw new BadRequestException('name is required (≤120 chars)');
    if (!/^https?:\/\/.+/.test(url)) throw new BadRequestException('url must be an http(s) URL');
    if (secret.length < 16) throw new BadRequestException('secret must be at least 16 characters');
    if (events.length === 0) throw new BadRequestException('subscribe to at least one event (or "*")');
    for (const e of events) {
      if (e !== '*' && !/^[a-z0-9_]+(\.[a-z0-9_*]+)*$/.test(e)) {
        throw new BadRequestException(`invalid event pattern "${e}"`);
      }
    }
    const row = await this.prisma.webhook.create({
      data: {
        name,
        url,
        secret_enc: Buffer.from(getSecretBox().encrypt(secret), 'utf8'),
        events,
        is_active: true,
      },
    });
    return { id: row.id, name: row.name, url: row.url, events: row.events, is_active: true };
  }

  async update(actor: Actor | undefined, id: string, input: Record<string, unknown>) {
    if (!actor?.isSuperAdmin) throw new NotFoundException('webhook not found');
    const row = await this.prisma.webhook.findFirst({ where: { id, deleted_at: null } });
    if (!row) throw new NotFoundException('webhook not found');
    const data: Record<string, unknown> = {};
    if (typeof input.name === 'string' && input.name.trim()) data.name = input.name.trim();
    if (typeof input.url === 'string' && /^https?:\/\/.+/.test(input.url)) data.url = input.url.trim();
    if (Array.isArray(input.events) && input.events.length > 0) data.events = input.events.map(String);
    if (typeof input.is_active === 'boolean') data.is_active = input.is_active;
    if (typeof input.secret === 'string' && input.secret.length >= 16) {
      data.secret_enc = Buffer.from(getSecretBox().encrypt(input.secret), 'utf8');
    } else if (input.secret !== undefined) {
      throw new BadRequestException('secret must be at least 16 characters');
    }
    await this.prisma.webhook.update({ where: { id }, data });
    return { id, updated: Object.keys(data) };
  }

  async delete(actor: Actor | undefined, id: string): Promise<void> {
    if (!actor?.isSuperAdmin) throw new NotFoundException('webhook not found');
    const row = await this.prisma.webhook.findFirst({ where: { id, deleted_at: null } });
    if (!row) throw new NotFoundException('webhook not found');
    await this.prisma.webhook.update({ where: { id }, data: { deleted_at: new Date(), is_active: false } });
  }

  async deliveries(actor: Actor | undefined, webhookId: string) {
    if (!actor?.isSuperAdmin) throw new NotFoundException('webhook not found');
    const row = await this.prisma.webhook.findFirst({ where: { id: webhookId, deleted_at: null } });
    if (!row) throw new NotFoundException('webhook not found');
    const rows = await this.prisma.webhookDelivery.findMany({
      where: { webhook_id: webhookId },
      orderBy: { attempted_at: 'desc' },
      take: 50,
    });
    return {
      data: rows.map((d) => ({
        id: d.id,
        event_type: d.event_type,
        attempt: d.attempt,
        status: d.status,
        response_status: d.response_status,
        attempted_at: d.attempted_at.toISOString(),
        next_retry_at: d.next_retry_at?.toISOString() ?? null,
      })),
    };
  }

  /** Sends a signed test ping; the delivery row records the outcome. */
  async test(actor: Actor | undefined, webhookId: string) {
    if (!actor?.isSuperAdmin) throw new NotFoundException('webhook not found');
    const row = await this.prisma.webhook.findFirst({ where: { id: webhookId, deleted_at: null } });
    if (!row) throw new NotFoundException('webhook not found');
    return this.deliver(row, 'webhook.test', { note: 'NexusPanel test delivery' }, 1);
  }

  /** Redrives a dead (or failed) delivery immediately. */
  async redrive(actor: Actor | undefined, webhookId: string, deliveryId: string) {
    if (!actor?.isSuperAdmin) throw new NotFoundException('delivery not found');
    const d = await this.prisma.webhookDelivery.findFirst({
      where: { id: deliveryId, webhook_id: webhookId },
    });
    if (!d) throw new NotFoundException('delivery not found');
    const w = await this.prisma.webhook.findFirst({ where: { id: webhookId, deleted_at: null } });
    if (!w) throw new NotFoundException('webhook not found');
    return this.deliver(
      w,
      d.event_type,
      (d.payload as { data?: unknown })?.data ?? {},
      d.attempt + 1,
    );
  }

  // ---- dispatch --------------------------------------------------------------

  private matches(patterns: string[], event: string): boolean {
    for (const p of patterns) {
      if (p === '*' || p === event) return true;
      if (p.endsWith('.*') && event.startsWith(p.slice(0, -1))) return true;
    }
    return false;
  }

  private sign(secret: string, timestamp: string, body: string): string {
    const mac = crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
    return `sha256=${mac}`;
  }

  private async deliver(
    webhook: { id: string; url: string; secret_enc: Uint8Array; name: string },
    event: string,
    data: unknown,
    attempt: number,
  ) {
    const body = JSON.stringify({
      event,
      occurred_at: new Date().toISOString(),
      data,
    });
    const ts = Math.floor(Date.now() / 1000).toString();
    const secret = getSecretBox().decrypt(Buffer.from(webhook.secret_enc).toString('utf8'));
    const headers = {
      'x-nexus-event': event,
      'x-nexus-timestamp': ts,
      'x-nexus-signature': this.sign(secret, ts, body),
      'x-nexus-delivery': crypto.randomUUID(),
    };
    const res = await this.deliverFn(webhook.url, headers, body);
    const success = res.ok;
    const dead = !success && attempt >= MAX_ATTEMPTS;
    await this.prisma.webhookDelivery.create({
      data: {
        webhook_id: webhook.id,
        event_type: event,
        payload: { data } as object,
        attempt,
        status: success ? 'success' : dead ? 'dead' : 'failed',
        response_status: res.status,
        response_body: res.body,
        attempted_at: new Date(),
        next_retry_at: success || dead ? null : this.nextBackoff(attempt),
      },
    });
    if (dead) {
      this.logger.warn(`webhook ${webhook.name} → ${event} dead after ${attempt} attempts`);
      const admins = await this.notifications.superAdminIds();
      await this.notifications.notify({
        userIds: admins,
        category: 'webhooks',
        title: `Webhook dead: ${webhook.name}`,
        body: `${event} could not be delivered after ${attempt} attempts (${res.status || 'no response'}). Redrive it from the webhook view.`,
        actionUrl: '/webhooks',
        severity: 'error',
      });
    }
    return { status: success ? 'success' : dead ? 'dead' : 'failed', attempt, response_status: res.status };
  }

  private nextBackoff(attempt: number): Date {
    const sec = Math.min(BACKOFF_BASE_SEC * 2 ** (attempt - 1), BACKOFF_CAP_SEC);
    return new Date(Date.now() + sec * 1000);
  }

  /** One poller tick: tail new audit entries + retry due deliveries. */
  async runOnce(): Promise<void> {
    // 1. tail audit entries for new events
    const batch = await this.prisma.auditEntry.findMany({
      where: this.cursor ? { id: { gt: this.cursor } } : {},
      orderBy: { occurred_at: 'asc' },
      take: 200,
    });
    if (batch.length > 0) {
      this.cursor = batch[batch.length - 1].id;
      const hooks = await this.prisma.webhook.findMany({
        where: { deleted_at: null, is_active: true },
      });
      for (const entry of batch) {
        for (const w of hooks) {
          if (!this.matches(w.events, entry.operation)) continue;
          await this.deliver(
            w,
            entry.operation,
            {
              actor_user_id: entry.actor_user_id,
              hosting_account_id: entry.hosting_account_id,
              parameters: entry.parameters,
              outcome: entry.outcome,
            },
            1,
          );
        }
      }
    }
    // 2. retry due deliveries
    const due = await this.prisma.webhookDelivery.findMany({
      where: { status: 'failed', next_retry_at: { lte: new Date() } },
      take: 20,
      orderBy: { next_retry_at: 'asc' },
    });
    for (const d of due) {
      const w = await this.prisma.webhook.findFirst({ where: { id: d.webhook_id, deleted_at: null } });
      if (!w || !w.is_active) continue;
      await this.deliver(w, d.event_type, (d.payload as { data?: unknown })?.data ?? {}, d.attempt + 1);
      // The new row now owns the schedule — hand this row's off so the
      // failed row is never re-picked by a later tick (double-delivery).
      await this.prisma.webhookDelivery.update({
        where: { id: d.id },
        data: { next_retry_at: null },
      });
    }
  }

  onModuleInit(): void {
    // First tick aligns the cursor to "now" (no replay of pre-boot history),
    // then the loop tails the chain.
    this.prisma.auditEntry
      .findFirst({ orderBy: { occurred_at: 'desc' }, select: { id: true } })
      .then((last) => {
        this.cursor = last?.id ?? null;
      })
      .catch(() => undefined);
    this.pollTimer = setInterval(() => {
      void this.runOnce().catch((e) => this.logger.debug(`webhook poll: ${(e as Error).message}`));
    }, POLL_INTERVAL_MS);
    this.pollTimer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }
}
