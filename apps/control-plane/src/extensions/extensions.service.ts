import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { getSecretBox } from '../common/secretbox';
import { NotificationsService } from '../notifications/notifications.service';
import { AUDIT_APPENDER, AuditAppender } from '../audit/audit.service';
import { Actor } from '../sites/sites.service';
import { validateManifest, originOf, ExtensionManifest } from './manifest';
import { EXTENSION_SCOPES } from './extension-scopes';
import { newSharedSecret, deriveExtToken } from './signature';

/**
 * Extension SDK runtime — panel side (P7, SDK spec §3–§8, API spec §4.24).
 *
 * Trust ladder (fail-closed, spec §3):
 *   1. install    — admin points at a manifest URL (or posts a manifest);
 *                   the manifest is validated, unknown scopes REJECTED, and
 *                   the row lands `disabled` with NO granted scopes;
 *   2. review     — the admin sees the requested scopes (extension:list);
 *   3. approve    — scopes are granted, status → `enabled`, and the
 *                   one-time credentials (shared secret + derived token)
 *                   are returned EXACTLY ONCE — they are never retrievable
 *                   again through any endpoint;
 *   4. operate    — hooks dispatch + widget slots + `/api/v1/ext/*` calls
 *                   (see ext-proxy / ext-dispatch); heartbeats every 60 s
 *                   flip the row to `errored` + admin notification when the
 *                   extension stops answering;
 *   5. disable/uninstall — token stops working immediately (the derived
 *                   token is recomputed from the registration secret, and
 *                   disabled extensions never resolve).
 *
 * Secrets at rest follow ADR-0009: the shared secret lives in a SecretBox
 * envelope in `extension_registrations.shared_secret_enc`, decrypted only to
 * sign outbound calls / re-derive the ext token — never returned by list/get.
 */

/** Credentials shown once at approval time (spec §5.1 response shape). */
export interface ExtensionCredentials {
  extension_id: string;
  shared_secret: string;
  derived_token: string;
  panel_base_url: string;
  issued_at: string;
}

export interface ExtHttpClientResult {
  ok: boolean;
  status: number;
  body: string;
}

export type ExtHttpFn = (
  url: string,
  headers: Record<string, string>,
  body?: string,
) => Promise<ExtHttpClientResult>;

const DEFAULT_EXT_HTTP: ExtHttpFn = async (url, headers, body) => {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5_000);
  try {
    const res = await fetch(url, {
      method: body === undefined ? 'GET' : 'POST',
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

const HEARTBEAT_INTERVAL_MS = 60_000;

interface SecretEnvelope {
  v: 1;
  shared_secret: string;
}

function env0(sharedSecret: string): SecretEnvelope {
  return { v: 1, shared_secret: sharedSecret };
}

@Injectable()
export class ExtensionsService {
  private readonly logger = new Logger(ExtensionsService.name);
  /** Injected transports (tests). */
  private fetchManifestFn: (url: string) => Promise<unknown> = async (url) => {
    const res = await fetch(url, { signal: AbortSignal.timeout(5_000) });
    if (!res.ok) throw new BadRequestException(`manifest fetch failed: HTTP ${res.status}`);
    return res.json();
  };
  private httpFn: ExtHttpFn = DEFAULT_EXT_HTTP;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  /** Sliding failure state per registration id (for notify-once). */
  private readonly heartbeatFailing = new Set<string>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly notifications: NotificationsService,
    @Inject(AUDIT_APPENDER) private readonly audit: AuditAppender,
  ) {}

  /** Test seams. */
  setFetchManifestFn(fn: (url: string) => Promise<unknown>): void {
    this.fetchManifestFn = fn;
  }

  setHttpFn(fn: ExtHttpFn): void {
    this.httpFn = fn;
  }

  // ---- admin surface (API spec §4.24) --------------------------------------

  async list(actor?: Actor) {
    this.requireAdmin(actor);
    const rows = await this.prisma.extension.findMany({
      orderBy: { installed_at: 'asc' },
      include: {
        extension_registrations__extension_id: {
          where: { is_active: true },
          select: { last_heartbeat_at: true, callback_url: true },
        },
      },
    });
    return {
      data: rows.map((r) => ({
        id: r.id,
        slug: r.slug,
        name: r.name,
        version: r.version,
        status: r.status,
        granted_scopes: r.granted_scopes,
        requested_scopes: this.requestedScopes(r.manifest as unknown as ExtensionManifest),
        types: this.manifestOf(r.manifest).types ?? [],
        last_error: r.last_error,
        last_heartbeat_at: r.extension_registrations__extension_id[0]?.last_heartbeat_at?.toISOString() ?? null,
        callback_url: r.extension_registrations__extension_id[0]?.callback_url ?? null,
        installed_at: r.installed_at.toISOString(),
      })),
    };
  }

  async get(actor: Actor | undefined, id: string) {
    this.requireAdmin(actor);
    const r = await this.prisma.extension.findUnique({
      where: { id },
      include: {
        extension_registrations__extension_id: {
          where: { is_active: true },
          select: { last_heartbeat_at: true, callback_url: true, registered_at: true },
        },
      },
    });
    if (!r) throw new NotFoundException('extension not found');
    const manifest = this.manifestOf(r.manifest);
    return {
      data: {
        id: r.id,
        slug: r.slug,
        name: r.name,
        version: r.version,
        status: r.status,
        granted_scopes: r.granted_scopes,
        requested_scopes: this.requestedScopes(manifest),
        types: manifest.types ?? [],
        manifest,
        last_error: r.last_error,
        last_heartbeat_at: r.extension_registrations__extension_id[0]?.last_heartbeat_at?.toISOString() ?? null,
        callback_url: r.extension_registrations__extension_id[0]?.callback_url ?? null,
        installed_at: r.installed_at.toISOString(),
      },
    };
  }

  /**
   * Install by manifest URL (spec §3.2 dev-mode install): fetch
   * `<origin>/nexuspanel-manifest.json`, validate, create `disabled` with
   * zero granted scopes. The callback base is the manifest origin.
   */
  async installFromUrl(actor: Actor | undefined, input: Record<string, unknown>) {
    this.requireAdmin(actor);
    const manifestUrl = typeof input.manifest_url === 'string' ? input.manifest_url.trim() : '';
    if (!/^https?:\/\/.+/.test(manifestUrl)) {
      throw new BadRequestException('manifest_url must be an http(s) URL');
    }
    const origin = originOf(manifestUrl);
    if (!origin) throw new BadRequestException('manifest_url must be an absolute http(s) URL');
    const raw = await this.fetchManifestFn(manifestUrl).catch((e: Error) => {
      throw new BadRequestException(`could not fetch manifest: ${e.message}`);
    });
    return this.installRaw(actor, raw, origin, `${origin}/health`);
  }

  /** Direct registration payload (SDK spec §5.1 — extension → panel). */
  async register(actor: Actor | undefined, input: Record<string, unknown>) {
    this.requireAdmin(actor);
    const callback = typeof input.callback_base_url === 'string' ? input.callback_base_url.trim() : '';
    if (!/^https?:\/\/.+/.test(callback)) {
      throw new BadRequestException('callback_base_url must be an http(s) URL');
    }
    const health = typeof input.health_check_url === 'string' && input.health_check_url.trim()
      ? input.health_check_url.trim()
      : `${callback.replace(/\/$/, '')}/health`;
    return this.installRaw(actor, input.manifest, callback.replace(/\/$/, ''), health);
  }

  /** Approve the scope review: grant scopes, enable, issue one-time creds. */
  async approve(actor: Actor | undefined, id: string): Promise<ExtensionCredentials> {
    this.requireAdmin(actor);
    const ext = await this.mustFind(id);
    if (ext.status === 'enabled') {
      throw new BadRequestException('extension is already enabled — credentials were issued once at approval and cannot be re-shown; uninstall and re-install to rotate');
    }
    const manifest = this.manifestOf(ext.manifest);
    const reg = await this.activeRegistration(ext.id);
    if (!reg) throw new NotFoundException('extension registration not found');

    const sharedSecret = this.decryptSecret(reg.shared_secret_enc);
    const creds: ExtensionCredentials = {
      extension_id: ext.id,
      shared_secret: sharedSecret,
      derived_token: deriveExtToken(sharedSecret),
      panel_base_url: '/api/v1/ext',
      issued_at: new Date().toISOString(),
    };
    await this.prisma.extension.update({
      where: { id: ext.id },
      data: {
        status: 'enabled',
        granted_scopes: manifest.permissions,
        last_error: null,
      },
    });
    await this.audit.append({
      operation: 'extension.approve',
      parameters: { slug: ext.slug, version: ext.version, scopes: manifest.permissions },
      outcome: 'success',
      actorUserId: actor!.userId,
    });
    // one-time reveal — never persisted in a readable form anywhere else
    return creds;
  }

  /** Reject the scope review: remove the extension entirely (spec §3.3). */
  async reject(actor: Actor | undefined, id: string): Promise<void> {
    this.requireAdmin(actor);
    const ext = await this.mustFind(id);
    await this.prisma.extension.delete({ where: { id: ext.id } });
    await this.audit.append({
      operation: 'extension.reject',
      parameters: { slug: ext.slug, reason: 'scope_review_rejected' },
      outcome: 'success',
      actorUserId: actor!.userId,
    });
  }

  async enable(actor: Actor | undefined, id: string): Promise<void> {
    this.requireAdmin(actor);
    const ext = await this.mustFind(id);
    if (ext.granted_scopes.length === 0) {
      throw new BadRequestException('extension has no approved scopes — use approve (scope review) first');
    }
    await this.prisma.extension.update({
      where: { id: ext.id },
      data: { status: 'enabled', last_error: null },
    });
    await this.audit.append({
      operation: 'extension.enable',
      parameters: { slug: ext.slug },
      outcome: 'success',
      actorUserId: actor!.userId,
    });
  }

  async disable(actor: Actor | undefined, id: string): Promise<void> {
    this.requireAdmin(actor);
    const ext = await this.mustFind(id);
    await this.prisma.extension.update({
      where: { id: ext.id },
      data: { status: 'disabled' },
    });
    await this.audit.append({
      operation: 'extension.disable',
      parameters: { slug: ext.slug },
      outcome: 'success',
      actorUserId: actor!.userId,
    });
  }

  async uninstall(actor: Actor | undefined, id: string): Promise<void> {
    this.requireAdmin(actor);
    const ext = await this.mustFind(id);
    await this.prisma.extension.delete({ where: { id: ext.id } }); // registration cascades
    await this.audit.append({
      operation: 'extension.uninstall',
      parameters: { slug: ext.slug },
      outcome: 'success',
      actorUserId: actor!.userId,
    });
  }

  /** Widget slots for the dashboard (any authenticated user). */
  async widgets() {
    const rows = await this.prisma.extension.findMany({
      where: { status: 'enabled' },
      include: {
        extension_registrations__extension_id: {
          where: { is_active: true },
          select: { callback_url: true },
        },
      },
    });
    const data: Array<{ slug: string; name: string; widget_id: string; slot: string; entry_url: string }> = [];
    for (const r of rows) {
      const manifest = this.manifestOf(r.manifest);
      const base = r.extension_registrations__extension_id[0]?.callback_url;
      if (!base) continue;
      for (const [widgetId, w] of Object.entries(manifest.endpoints.widgets ?? {})) {
        data.push({
          slug: r.slug,
          name: r.name,
          widget_id: widgetId,
          slot: w.slot,
          entry_url: `${base}${w.entry}`,
        });
      }
    }
    return { data };
  }

  // ---- heartbeats (spec §5.2: health every 60 s) ---------------------------

  /** One heartbeat sweep across all active registrations. Test seam: drive manually. */
  async runHeartbeatsOnce(): Promise<void> {
    const regs = await this.prisma.extensionRegistration.findMany({
      where: { is_active: true },
      include: { extension: true },
    });
    for (const reg of regs) {
      if (reg.extension.status === 'disabled') continue; // not operating — no probe
      const healthUrl = this.healthUrlOf(reg.callback_url, reg.extension.manifest as unknown as ExtensionManifest);
      const secret = this.decryptSecret(reg.shared_secret_enc);
      const res = await this.httpFn(healthUrl, { 'x-nexuspanel-extension-id': reg.extension_id }).catch(
        (): ExtHttpClientResult => ({ ok: false, status: 0, body: 'heartbeat error' }),
      );
      const ok = res.ok;
      await this.prisma.extensionRegistration.update({
        where: { id: reg.id },
        data: { last_heartbeat_at: new Date() },
      });
      if (ok) {
        if (this.heartbeatFailing.has(reg.extension_id)) {
          this.heartbeatFailing.delete(reg.extension_id);
          await this.prisma.extension.update({
            where: { id: reg.extension_id },
            data: { status: 'enabled', last_error: null },
          });
          this.logger.log(`extension ${reg.extension.slug} healthy again`);
        }
        continue;
      }
      const firstFailure = !this.heartbeatFailing.has(reg.extension_id);
      this.heartbeatFailing.add(reg.extension_id);
      await this.prisma.extension.update({
        where: { id: reg.extension_id },
        data: { status: 'errored', last_error: `health check failed: HTTP ${res.status || 'no response'}` },
      });
      if (firstFailure) {
        const admins = await this.notifications.superAdminIds();
        await this.notifications.notify({
          userIds: admins,
          category: 'extensions',
          title: `Extension not responding: ${reg.extension.name}`,
          body: `The health check for "${reg.extension.slug}" failed (HTTP ${res.status || 'no response'}). The extension is marked errored and its /api/v1/ext/* token is suspended until it recovers.`,
          actionUrl: '/extensions',
          severity: 'warning',
        });
        await this.audit.append({
          operation: 'extension.heartbeat_failure',
          parameters: { slug: reg.extension.slug, status: res.status },
          outcome: 'failure',
        });
      }
    }
  }

  onModuleInit(): void {
    this.heartbeatTimer = setInterval(() => {
      void this.runHeartbeatsOnce().catch((e) =>
        this.logger.debug(`heartbeat sweep failed: ${(e as Error).message}`),
      );
    }, HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
  }

  // ---- internals ------------------------------------------------------------

  private async installRaw(
    actor: Actor | undefined,
    raw: unknown,
    callbackBase: string,
    healthUrl: string,
  ) {
    const { manifest, problems } = validateManifest(raw);
    if (problems.length > 0) {
      throw new BadRequestException(`invalid manifest: ${problems.join('; ')}`);
    }
    const existing = await this.prisma.extension.findUnique({ where: { slug: manifest.slug } });
    if (existing) {
      throw new BadRequestException(`extension slug "${manifest.slug}" is already installed — uninstall it first (updates arrive via uninstall + install in v1.0, SDK spec §9)`);
    }
    const sharedSecret = newSharedSecret();
    const created = await this.prisma.extension.create({
      data: {
        slug: manifest.slug,
        name: manifest.name,
        version: manifest.version,
        manifest: manifest as unknown as object,
        granted_scopes: [], // nothing granted until the scope review approves it
        status: 'disabled',
        installed_by_user_id: actor!.userId!,
      },
    });
    await this.prisma.extensionRegistration.create({
      data: {
        extension_id: created.id,
        callback_url: callbackBase,
        shared_secret_enc: this.encryptSecret(env0(sharedSecret)),
        is_active: true,
      },
    });
    // health URL: the manifest's heartbeat endpoint when present,
    // else <callback>/health (spec §5.2 default probe target)
    const healthCheckUrl = manifest.endpoints.heartbeat
      ? `${callbackBase}${manifest.endpoints.heartbeat}`
      : healthUrl;
    await this.audit.append({
      operation: 'extension.install',
      parameters: {
        slug: manifest.slug,
        version: manifest.version,
        requested_scopes: manifest.permissions,
        callback_base_url: callbackBase,
      },
      outcome: 'success',
      actorUserId: actor!.userId,
    });
    return {
      data: {
        id: created.id,
        slug: created.slug,
        name: created.name,
        version: created.version,
        status: created.status,
        granted_scopes: created.granted_scopes,
        requested_scopes: manifest.permissions,
        callback_url: callbackBase,
        health_check_url: healthCheckUrl,
      },
      next_step: 'review the requested scopes, then POST /extensions/{id}/approve to grant them and receive the one-time credentials',
    };
  }

  private healthUrlOf(callbackBase: string, manifest: ExtensionManifest): string {
    const ep = manifest.endpoints?.heartbeat ?? '/health';
    return `${callbackBase}${ep}`;
  }

  private requestedScopes(manifest: ExtensionManifest | undefined): string[] {
    return manifest?.permissions ?? [];
  }

  private manifestOf(manifest: unknown): ExtensionManifest {
    return manifest as unknown as ExtensionManifest;
  }

  private encryptSecret(env: SecretEnvelope): Uint8Array<ArrayBuffer> {
    // Prisma's Bytes = ReturnType<Uint8Array['slice']> = Uint8Array<ArrayBuffer>;
    // copy through a fixed-length view so the type is exact.
    const src = Buffer.from(getSecretBox().encrypt(JSON.stringify(env)), 'utf8');
    const out = new Uint8Array(src.length);
    out.set(src);
    return out;
  }

  private decryptSecret(blob: Uint8Array): string {
    const json = getSecretBox().decrypt(Buffer.from(blob).toString('utf8'));
    const env = JSON.parse(json) as SecretEnvelope;
    if (env.v !== 1 || typeof env.shared_secret !== 'string') {
      throw new Error('malformed extension secret envelope');
    }
    return env.shared_secret;
  }

  private async mustFind(id: string) {
    const ext = await this.prisma.extension.findUnique({ where: { id } });
    if (!ext) throw new NotFoundException('extension not found');
    return ext;
  }

  private activeRegistration(extensionId: string) {
    return this.prisma.extensionRegistration.findFirst({
      where: { extension_id: extensionId, is_active: true },
    });
  }

  private requireAdmin(actor?: Actor): void {
    if (!actor?.isSuperAdmin) {
      // server-wide surface: 404 anti-enumeration, same as webhooks
      throw new NotFoundException('extension not found');
    }
  }
}

/** Exposed for the admin UI's scope-review step. */
export const EXTENSION_SCOPE_CATALOG = EXTENSION_SCOPES;
