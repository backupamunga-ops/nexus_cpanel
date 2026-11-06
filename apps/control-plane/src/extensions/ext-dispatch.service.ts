import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { getSecretBox } from '../common/secretbox';
import { HOOK_EVENT_ALIASES } from './extension-scopes';
import { panelToExtHeaders } from './signature';

/**
 * Extension hook dispatch (SDK spec §5.2, P7).
 *
 * Same architecture as outbound webhooks (ADR-0018): a lightweight
 * in-process poller tails `audit_entries` and fans out matching hook
 * deliveries — no broker required for v1.0 single-node deployments. Each
 * delivery is a signed POST to `<callback_base_url><hook path>`:
 *
 *   { event_type, event_id, occurred_at, payload }
 *
 * with the §5.1 signature headers (X-Nexuspanel-Extension-Id / -Timestamp /
 * -Signature over method + path + body + timestamp). Manifest hook keys are
 * the SDK-canonical event names (e.g. `backup.completed`); the
 * HOOK_EVENT_ALIASES map translates them to the audit operations the panel
 * actually emits (`backup.run.success`). No retry queue in v1.0 — a failed
 * hook delivery is recorded on the extension (`last_error`) and the next
 * matching event re-drives it; durable retries remain the webhooks module's
 * job (documented in ADR-0021).
 */

const POLL_INTERVAL_MS = 5_000;
const DELIVERY_TIMEOUT_MS = 5_000;

export type HookDeliverFn = (
  url: string,
  headers: Record<string, string>,
  body: string,
) => Promise<{ ok: boolean; status: number; body: string }>;

const DEFAULT_DELIVER: HookDeliverFn = async (url, headers, body) => {
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

@Injectable()
export class ExtDispatchService {
  private readonly logger = new Logger(ExtDispatchService.name);
  private cursor: string | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private deliverFn: HookDeliverFn = DEFAULT_DELIVER;

  constructor(private readonly prisma: PrismaService) {}

  /** Test seam: replace the HTTP transport. */
  setDeliverFn(fn: HookDeliverFn): void {
    this.deliverFn = fn;
  }

  /** Which audit operations does this hook key fire for? */
  operationsFor(hookEvent: string): readonly string[] {
    return HOOK_EVENT_ALIASES[hookEvent] ?? [hookEvent];
  }

  /** One poller tick: tail new audit entries, fan out matching hooks. Test seam. */
  async runOnce(): Promise<void> {
    const batch = await this.prisma.auditEntry.findMany({
      where: this.cursor ? { id: { gt: this.cursor } } : {},
      orderBy: { occurred_at: 'asc' },
      take: 200,
    });
    if (batch.length === 0) return;
    this.cursor = batch[batch.length - 1].id;

    const exts = await this.prisma.extension.findMany({
      where: { status: 'enabled' },
      include: {
        extension_registrations__extension_id: {
          where: { is_active: true },
          take: 1,
        },
      },
    });

    for (const ext of exts) {
      const reg = ext.extension_registrations__extension_id[0];
      if (!reg) continue;
      const hooks = (ext.manifest as { endpoints?: { hooks?: Record<string, string> } })
        ?.endpoints?.hooks;
      if (!hooks || Object.keys(hooks).length === 0) continue;

      let secret: string;
      try {
        const env = JSON.parse(
          getSecretBox().decrypt(Buffer.from(reg.shared_secret_enc).toString('utf8')),
        ) as { v: number; shared_secret: string };
        if (env.v !== 1) continue;
        secret = env.shared_secret;
      } catch {
        this.logger.warn(`extension ${ext.slug}: undecryptable secret envelope, skipping dispatch`);
        continue;
      }

      for (const entry of batch) {
        for (const [hookEvent, hookPath] of Object.entries(hooks)) {
          if (!this.operationsFor(hookEvent).includes(entry.operation)) continue;
          await this.deliverHook(ext.id, ext.slug, secret, reg.callback_url, hookPath, entry.id, entry.operation, entry.occurred_at, entry.parameters);
        }
      }
    }
  }

  private async deliverHook(
    extensionId: string,
    slug: string,
    secret: string,
    callbackBase: string,
    hookPath: string,
    eventId: string,
    operation: string,
    occurredAt: Date,
    parameters: unknown,
  ): Promise<void> {
    const payload = {
      event_type: operation,
      event_id: eventId,
      occurred_at: occurredAt.toISOString(),
      payload: parameters ?? {},
    };
    const body = JSON.stringify(payload);
    const url = `${callbackBase}${hookPath}`;
    const headers = panelToExtHeaders(extensionId, secret, 'POST', hookPath, body);
    const res = await this.deliverFn(url, headers, body);
    if (res.ok) {
      await this.prisma.extension
        .update({ where: { id: extensionId }, data: { last_error: null } })
        .catch(() => undefined);
      return;
    }
    this.logger.warn(`hook ${slug} ← ${operation} failed: HTTP ${res.status || 'no response'}`);
    await this.prisma.extension
      .update({
        where: { id: extensionId },
        data: { last_error: `hook ${operation} delivery failed: HTTP ${res.status || 'no response'}` },
      })
      .catch(() => undefined);
  }

  onModuleInit(): void {
    this.prisma.auditEntry
      .findFirst({ orderBy: { occurred_at: 'desc' }, select: { id: true } })
      .then((last) => {
        this.cursor = last?.id ?? null;
      })
      .catch(() => undefined);
    this.pollTimer = setInterval(() => {
      void this.runOnce().catch((e) =>
        this.logger.debug(`extension hook poll: ${(e as Error).message}`),
      );
    }, POLL_INTERVAL_MS);
    this.pollTimer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }
}
