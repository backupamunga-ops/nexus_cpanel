import {
  ForbiddenException,
  HttpException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { getSecretBox } from '../common/secretbox';
import { NotificationsService } from '../notifications/notifications.service';
import { AUDIT_APPENDER, AuditAppender } from '../audit/audit.service';
import {
  EXT_PROXY_ROUTES,
  EXTENSION_WRITE_SCOPES,
} from './extension-scopes';
import { deriveExtToken, safeEqual } from './signature';

/**
 * `/api/v1/ext/*` — the namespaced, scope-enforced API extensions call
 * (SDK spec §5.3, P7).
 *
 * Contract, enforced in this order on EVERY call:
 *   1. `Authorization: Bearer <derived-token>` resolves to exactly one
 *      ACTIVE registration (token = HMAC(shared_secret) — recomputed here,
 *      never stored); mismatch → 401 with no enumeration surface;
 *   2. the extension must be `enabled` — disabled/errored → 403;
 *   3. the (method, path) pair must be on the closed EXT_PROXY_ROUTES list —
 *      anything else → 404. Extensions can never reach `/api/v1/*`;
 *   4. the bound scope must be in `granted_scopes` → 403 otherwise;
 *   5. write scopes are refused in v1.0 with `write_requires_confirmation`
 *      (spec §6: every extension write needs per-call admin approval — the
 *      confirmation queue is the v1.x trust-level work; failing closed here
 *      is the safe subset) + admins are notified (deduped per 10 min);
 *   6. rate limit: 60 calls / minute / extension (spec §5.3) → 429;
 *   7. the call is audited as `extension.<slug>.call` — attributed via the
 *      audit entry's slug parameter (C11 chain).
 *
 * Resolvers expose METADATA ONLY. Secret-bearing columns (mailbox password
 * hashes, database credentials, certificate/key PEM) are structurally absent
 * from every query below — there is no code path that can leak them, which
 * is a stronger guarantee than filtering responses.
 */

const RATE_LIMIT_PER_MIN = 60;

const WINDOW_MS = 60_000;
const NOTIFY_DEDUPE_MS = 10 * 60_000;

interface RateWindow {
  windowStart: number;
  count: number;
}

export interface ExtPrincipal {
  extensionId: string;
  slug: string;
  grantedScopes: string[];
}

@Injectable()
export class ExtProxyService {
  private readonly logger = new Logger(ExtProxyService.name);
  private readonly rate = new Map<string, RateWindow>();
  private readonly writeNotifiedAt = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly notifications: NotificationsService,
    @Inject(AUDIT_APPENDER) private readonly audit: AuditAppender,
  ) {}

  /** Resolve a bearer token to an enabled extension (spec §5.3 steps 1–3). */
  async authenticate(bearer: string | undefined): Promise<ExtPrincipal> {
    if (!bearer) throw new UnauthorizedException('missing bearer token');
    const regs = await this.prisma.extensionRegistration.findMany({
      where: { is_active: true },
      include: { extension: true },
      take: 100,
    });
    for (const reg of regs) {
      let secret: string;
      try {
        secret = getSecretBox().decrypt(Buffer.from(reg.shared_secret_enc).toString('utf8'));
        const env = JSON.parse(secret) as { v: number; shared_secret?: string };
        if (env.v !== 1 || typeof env.shared_secret !== 'string') continue;
        secret = env.shared_secret;
      } catch {
        continue; // undecryptable envelope — never match
      }
      if (safeEqual(deriveExtToken(secret), bearer)) {
        if (reg.extension.status !== 'enabled') {
          throw new ForbiddenException('extension_disabled');
        }
        return {
          extensionId: reg.extension.id,
          slug: reg.extension.slug,
          grantedScopes: reg.extension.granted_scopes,
        };
      }
    }
    throw new UnauthorizedException('invalid bearer token');
  }

  /**
   * Enforce route table + scopes + rate limit; returns the matched route.
   * MUST be called after authenticate().
   */
  authorize(principal: ExtPrincipal, method: string, path: string): { scope: string } {
    const route = EXT_PROXY_ROUTES.find(
      (r) => r.method === method.toUpperCase() && r.path === path,
    );
    if (!route) {
      // unknown ext endpoint — same answer for every miss (anti-probing)
      throw new NotFoundException('unknown ext endpoint');
    }
    if (!principal.grantedScopes.includes(route.scope)) {
      throw new ForbiddenException('scope_not_granted');
    }
    if (EXTENSION_WRITE_SCOPES.has(route.scope)) {
      this.notifyWriteConfirmation(principal.slug, route.scope);
      throw new ForbiddenException('write_requires_confirmation');
    }
    if (!this.allowRate(principal.extensionId)) {
      throw new HttpException('rate_limited', 429);
    }
    return { scope: route.scope };
  }

  /** Rate limiter: fixed 60 s window per extension (spec §5.3 default). */
  private allowRate(extensionId: string): boolean {
    const now = Date.now();
    const w = this.rate.get(extensionId);
    if (!w || now - w.windowStart >= WINDOW_MS) {
      this.rate.set(extensionId, { windowStart: now, count: 1 });
      return true;
    }
    w.count += 1;
    return w.count <= RATE_LIMIT_PER_MIN;
  }

  private notifyWriteConfirmation(slug: string, scope: string): void {
    const key = `${slug}:${scope}`;
    const last = this.writeNotifiedAt.get(key) ?? 0;
    const now = Date.now();
    if (now - last < NOTIFY_DEDUPE_MS) return;
    this.writeNotifiedAt.set(key, now);
    void this.notifications
      .superAdminIds()
      .then((admins) =>
        this.notifications.notify({
          userIds: admins,
          category: 'extensions',
          title: `Extension write blocked: ${slug}`,
          body: `"${slug}" attempted a ${scope} call. Extension writes require per-call admin confirmation in v1.0 (SDK spec §6) — the call was refused and nothing changed.`,
          actionUrl: '/extensions',
          severity: 'info',
        }),
      )
      .catch(() => undefined);
  }

  /** Audit a proxied call into the C11 chain, attributed to the extension. */
  async auditCall(principal: ExtPrincipal, method: string, path: string, outcome: 'success' | 'failure', detail?: Record<string, unknown>): Promise<void> {
    await this.audit.append({
      operation: `extension.${principal.slug}.call`,
      parameters: { method, path, ...detail },
      outcome,
    });
  }

  // ---- resolvers (metadata only) --------------------------------------------

  async resolveGet(path: string, query: URLSearchParams): Promise<unknown> {
    switch (path) {
      case '/accounts':
        return this.wrap(
          await this.prisma.hostingAccount.findMany({
            where: { deleted_at: null },
            select: { id: true, username: true, primary_domain: true, status: true, created_at: true },
            orderBy: { created_at: 'asc' },
            take: 500,
          }),
        );
      case '/sites':
        return this.wrap(
          await this.prisma.domain.findMany({
            where: { deleted_at: null },
            select: { id: true, hosting_account_id: true, name: true, type: true, php_version: true, is_active: true },
            orderBy: { created_at: 'asc' },
            take: 500,
          }),
        );
      case '/mail/domains':
        return this.wrap(
          await this.prisma.mailDomain.findMany({
            where: { deleted_at: null },
            select: { id: true, hosting_account_id: true, name: true, is_active: true },
            orderBy: { created_at: 'asc' },
            take: 500,
          }),
        );
      case '/dns/zones':
        return this.wrap(
          await this.prisma.dnZone.findMany({
            where: { deleted_at: null },
            select: { id: true, hosting_account_id: true, name: true, dnssec_enabled: true, is_active: true },
            orderBy: { created_at: 'asc' },
            take: 500,
          }),
        );
      case '/databases':
        return this.wrap(
          await this.prisma.database.findMany({
            where: { deleted_at: null },
            select: { id: true, hosting_account_id: true, engine: true, name: true, size_mb: true, created_at: true },
            orderBy: { created_at: 'asc' },
            take: 500,
          }),
        );
      case '/ssl/certificates':
        return this.wrap(
          await this.prisma.certificate.findMany({
            select: {
              id: true, domain_id: true, issuer: true, common_name: true,
              san_names: true, issued_at: true, expires_at: true, auto_renew: true,
            },
            orderBy: { issued_at: 'desc' },
            take: 500,
          }),
        );
      case '/backups/jobs':
        return this.wrap(
          await this.prisma.backupJob.findMany({
            select: {
              id: true, name: true, scope: true, scope_id: true, schedule: true,
              retention_days: true, keep_daily: true, keep_weekly: true,
              keep_monthly: true, is_enabled: true,
            },
            orderBy: { created_at: 'asc' },
            take: 500,
          }),
        );
      case '/backups/runs': {
        const take = Math.min(Number(query.get('limit') ?? 100) || 100, 200);
        const rows = await this.prisma.backupRun.findMany({
          select: {
            id: true, job_id: true, status: true, started_at: true,
            completed_at: true, size_bytes: true, verified_at: true, error_message: true,
          },
          orderBy: { started_at: 'desc' },
          take,
        });
        return this.wrap(
          rows.map((r) => ({
            ...r,
            size_bytes: r.size_bytes === null ? null : Number(r.size_bytes),
          })),
        );
      }
      case '/audit':
        return this.wrap(
          await this.prisma.auditEntry.findMany({
            select: { id: true, occurred_at: true, operation: true, outcome: true },
            orderBy: { occurred_at: 'desc' },
            take: 100,
          }),
        );
      case '/users':
        return this.wrap(
          await this.prisma.user.findMany({
            where: { deleted_at: null },
            select: { id: true, email: true, display_name: true, is_super_admin: true, is_active: true, created_at: true },
            orderBy: { created_at: 'asc' },
            take: 500,
          }),
        );
      default:
        throw new NotFoundException('unknown ext endpoint');
    }
  }

  /** Create an in-panel notification (scope notification:write, spec §6). */
  async resolvePost(principal: ExtPrincipal, path: string, body: Record<string, unknown>): Promise<unknown> {
    if (path !== '/notifications') throw new NotFoundException('unknown ext endpoint');
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const text = typeof body.body === 'string' ? body.body.trim() : '';
    if (!title || title.length > 200) {
      throw new ForbiddenException('title is required (1-200 chars)');
    }
    if (text.length > 2000) throw new ForbiddenException('body must be ≤2000 chars');
    const admins = await this.notifications.superAdminIds();
    await this.notifications.notify({
      userIds: admins,
      category: 'extensions',
      title: `${principal.slug}: ${title}`,
      body: text || '(no details)',
      severity: body.severity === 'warning' || body.severity === 'error' ? body.severity : 'info',
    });
    return { data: { delivered: true } };
  }

  private wrap<T>(data: T): { data: T } {
    return { data };
  }
}
