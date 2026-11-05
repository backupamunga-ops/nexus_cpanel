import {
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { SettingsService } from '../settings/settings.service';
import { JwtService } from './jwt.service';
import { TwoFactorService } from './two-factor.service';
import { PasswordService } from './password.service';
import { hashRefreshToken, mintRefreshToken, refreshSessionId } from './refresh-token';
import { assertSessionHostAllowed, normalizeHost } from './session-host';
import * as crypto from 'node:crypto';
import { isIP } from 'node:net';

/**
 * PasswordHasher/PasswordService live in password.service.ts (extracted to
 * break the auth.service ⇄ two-factor.service import cycle). Re-exported
 * here so existing import sites keep working.
 */
export { PasswordService, PasswordHasher, ARGON2ID_PARAMS } from './password.service';

/**
 * Authentication & sessions (security controls C1 + C3, API spec §4.1).
 *
 * - Passwords: Argon2id (C1) via PasswordService.
 * - Access tokens: 15-minute JWT (sid-bound for revocation).
 * - Refresh tokens: 7-day, rotating, device-fingerprint-bound, stored only as
 *   SHA-256. Reuse of a rotated token revokes EVERY session of the user (C3).
 * - Session host binding (C14): the session records the Host it was created
 *   on; refresh re-classifies the presenting Host against active reseller
 *   custom domains and refuses cross-domain replay (session-host.ts).
 * - Lockout: `failed_login_count` ≥ security.max_failed_logins ⇒
 *   `locked_until` = now + security.lockout_minutes. Both are read LIVE from
 *   the server-settings table at every event (D-11); absent rows fall back
 *   to the catalog defaults (5 / 15).
 * - Session lifetime: refresh tokens slide by security.session_ttl_days,
 *   read live at login and every rotation; the cookie Max-Age mirrors it.
 * - Unknown-email logins burn a real Argon2id verify against a decoy hash so
 *   response timing does not leak account existence (no user oracle).
 * - 2FA (C2): totp-enabled users MUST present a valid TOTP or backup code;
 *   wrong second factors count as failed login attempts (lockout applies).
 *   The consumed TOTP timestep is persisted atomically with the login's own
 *   user.update — no replay window.
 */

export interface LoginContext {
  ip?: string | null;
  userAgent?: string | null;
  deviceFingerprint?: string | null;
  totp?: string;
  /** Raw Host header, bound to the session at creation (C14). */
  host?: string | null;
}

export interface TokenPairResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'jwt';
  expires_in: number;
  user: {
    id: string;
    email: string;
    display_name: string;
    is_super_admin: boolean;
    /** Additive P2 field: lets the UI render the 2FA settings state. */
    two_factor_enabled: boolean;
  };
}

/** One row of GET /auth/sessions (never exposes the token material itself). */
export interface SessionView {
  id: string;
  ip: string | null;
  user_agent: string | null;
  device_fingerprint: string | null;
  /** Host this session was created on (C14 binding; null = legacy row). */
  bound_host: string | null;
  created_at: Date;
  last_used_at: Date;
  expires_at: Date;
  /** True for the session this request was made with. */
  current: boolean;
}

/**
 * Internal alias: login/refresh return the FULL pair including refresh
 * material; the controller owns the transport decision (httpOnly cookie vs
 * §4.1 body) and strips the token from the body in cookie mode.
 */
export type AuthSessionTokens = TokenPairResponse;

/** Access-token TTL stays C3-fixed (env-tunable); it is not an admin setting. */
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SEC ?? 900); // 15 min (C3)

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);
  private readonly bootstrapSeed: Promise<void>;
  /** Decoy hash for the uniform-failure path (lazy, computed once). */
  private decoyHash: Promise<string> | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    @InjectAudit() private readonly audit: AuditAppender,
    private readonly twoFactor: TwoFactorService,
    private readonly settings: SettingsService,
    private readonly hasher: PasswordService,
  ) {
    const email = process.env.DEV_ADMIN_EMAIL;
    const password = process.env.DEV_ADMIN_PASSWORD;
    if (email && password) {
      this.bootstrapSeed = this.hasher
        .hash(password)
        .then((hash) =>
          // Bootstrap admin is idempotent: re-seeding refreshes the hash only.
          this.prisma.user.upsert({
            where: { email: email.toLowerCase() },
            create: {
              email: email.toLowerCase(),
              password_hash: hash,
              display_name: process.env.DEV_ADMIN_NAME ?? 'Dev Admin',
              is_super_admin: true,
            },
            update: { password_hash: hash, is_active: true, deleted_at: null },
          }),
        )
        .then(() => {
          this.logger.log(`dev bootstrap admin seeded (${email})`);
        })
        .catch((e: unknown) => {
          this.logger.error(`dev bootstrap seeding failed: ${(e as Error).message}`);
        });
    } else {
      this.bootstrapSeed = Promise.resolve();
    }
  }

  /** Resolves once the dev bootstrap account is usable (dev/test aid). */
  whenBootstrapSeeded(): Promise<void> {
    return this.bootstrapSeed;
  }

  async onModuleInit(): Promise<void> {
    // Fail fast if the JWT secret is misconfigured (e.g. too short).
    // JwtService throws in its constructor; touching it here surfaces that
    // during boot, not on the first request.
    void this.jwt;
  }

  async login(email: string, password: string, ctx: LoginContext = {}): Promise<TokenPairResponse> {
    const normalized = email.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email: normalized } });

    const known = !!user && !user.deleted_at && user.is_active;
    // Lockout gates BEFORE any password work: a locked account must not burn
    // Argon2id CPU for an attacker (and the uniform 401 hides account state).
    if (known && user!.locked_until && user!.locked_until > new Date()) {
      await this.audit.append({ operation: 'auth.login', parameters: { email: normalized, reason: 'locked' }, outcome: 'failure', actorUserId: user!.id });
      throw new UnauthorizedException('invalid credentials');
    }

    // Uniform failure for unknown users: burn a real Argon2id verify (C1/C3).
    const storedHash = known ? user!.password_hash : await this.decoyVerifyHash();
    const passwordOk = await this.hasher.verify(password, storedHash);

    if (!known || !passwordOk) {
      if (known) {
        await this.registerFailedAttempt(user!);
      }
      await this.audit.append({
        operation: 'auth.login',
        parameters: { email: normalized, reason: known ? 'bad_password' : 'unknown_user' },
        outcome: 'failure',
        actorUserId: known ? user!.id : null,
      });
      throw new UnauthorizedException('invalid credentials');
    }

    // 2FA challenge (C2): never silently bypass an enrolled factor. A missing
    // code is a distinct audit reason (UI shows the challenge); a WRONG code
    // counts as a failed attempt so lockout protects the second factor too.
    let secondFactor: 'totp' | 'backup_code' | undefined;
    let totpStep: number | undefined;
    if (user!.totp_enabled_at) {
      if (!ctx.totp || typeof ctx.totp !== 'string' || ctx.totp.trim().length === 0) {
        await this.audit.append({
          operation: 'auth.login',
          parameters: { email: normalized, reason: 'totp_missing' },
          outcome: 'failure',
          actorUserId: user!.id,
        });
        throw new UnauthorizedException('totp code required');
      }
      const consumed = await this.twoFactor.consumeLoginCode(user!, ctx.totp);
      if (!consumed.ok) {
        await this.registerFailedAttempt(user!);
        await this.audit.append({
          operation: 'auth.login',
          parameters: { email: normalized, reason: consumed.reason },
          outcome: 'failure',
          actorUserId: user!.id,
        });
        throw new UnauthorizedException('invalid credentials');
      }
      secondFactor = consumed.method;
      totpStep = consumed.totpStep;
    }

    await this.prisma.user.update({
      where: { id: user!.id },
      data: {
        failed_login_count: 0,
        locked_until: null,
        last_login_at: new Date(),
        last_login_ip: sanitizeIp(ctx.ip),
        // Persist the consumed TOTP timestep in the SAME write as the login
        // bookkeeping — replay of that step is impossible after this commits.
        ...(totpStep !== undefined
          ? { preferences: this.twoFactor.preferencesWithStep(user!.preferences, totpStep) }
          : {}),
      },
    });

    const sessionId = crypto.randomUUID(); // client-side uuid v4 — single create call
    const minted = mintRefreshToken(sessionId);
    const session = await this.prisma.userSession.create({
      data: {
        id: sessionId,
        user_id: user!.id,
        refresh_token_hash: new Uint8Array(minted.tokenHash),
        device_fingerprint: ctx.deviceFingerprint ?? null,
        ip: sanitizeIp(ctx.ip),
        user_agent: ctx.userAgent ?? null,
        bound_host: normalizeHost(ctx.host),
        expires_at: addDays(await this.sessionTtlDays()),
      },
    });

    await this.audit.append({
      operation: 'auth.login',
      parameters: {
        email: normalized,
        session_id: session.id,
        ...(secondFactor ? { second_factor: secondFactor } : {}),
      },
      outcome: 'success',
      actorUserId: user!.id,
    });
    this.logger.log(`login ok (${normalized}, session ${session.id})`);
    return this.tokenPair(user!, minted.token, session.id, ctx);
  }

  async refresh(presentedToken: string, ctx: LoginContext = {}): Promise<TokenPairResponse> {
    const sid = refreshSessionId(presentedToken ?? '');
    if (!sid) {
      throw new UnauthorizedException('invalid refresh token');
    }
    const session = await this.prisma.userSession.findUnique({
      where: { id: sid },
      include: { user: true },
    });
    if (!session || session.revoked_at || session.expires_at <= new Date()) {
      throw new UnauthorizedException('invalid refresh token');
    }

    const presentedHash = hashRefreshToken(presentedToken);
    const storedHashMatches =
      Buffer.compare(Buffer.from(session.refresh_token_hash), presentedHash) === 0;
    if (!storedHashMatches) {
      // C3 reuse response: a rotated token came back → assume theft, kill all.
      await this.prisma.userSession.updateMany({
        where: { user_id: session.user_id, revoked_at: null },
        data: { revoked_at: new Date() },
      });
      await this.audit.append({
        operation: 'auth.session.reuse_detected',
        parameters: { session_id: session.id, user_id: session.user_id },
        outcome: 'failure',
        actorUserId: session.user_id,
      });
      this.logger.warn(`refresh reuse detected (session ${session.id}) — all sessions revoked`);
      throw new UnauthorizedException('invalid refresh token');
    }
    if (session.device_fingerprint && ctx.deviceFingerprint && session.device_fingerprint !== ctx.deviceFingerprint) {
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: { revoked_at: new Date() },
      });
      await this.audit.append({ operation: 'auth.refresh', parameters: { session_id: session.id, reason: 'fingerprint_mismatch' }, outcome: 'failure', actorUserId: session.user_id });
      throw new UnauthorizedException('invalid refresh token');
    }

    // C14 — cross-reseller host gate. The token hash matched, so this IS the
    // session's secret; a presentation from the wrong origin is either token
    // theft or a Host-rewriting proxy. Same posture as fingerprint mismatch:
    // revoke the session and demand re-authentication. Domains still pending
    // (no active custom_domain row) do not participate — classification only
    // sees ACTIVE reseller domains.
    const requestHost = normalizeHost(ctx.host);
    if (session.bound_host || requestHost) {
      const activeDomains = await this.prisma.reseller.findMany({
        where: { deleted_at: null, custom_domain_status: 'active' },
        select: { custom_domain: true },
      });
      const domains = activeDomains
        .map((r) => normalizeHost(r.custom_domain))
        .filter((d): d is string => typeof d === 'string');
      try {
        assertSessionHostAllowed(session.bound_host, requestHost, domains);
      } catch (e) {
        await this.prisma.userSession.update({
          where: { id: session.id },
          data: { revoked_at: new Date() },
        });
        await this.audit.append({
          operation: 'auth.refresh',
          parameters: { session_id: session.id, reason: 'host_crossing', bound_host: session.bound_host, request_host: requestHost },
          outcome: 'failure',
          actorUserId: session.user_id,
        });
        this.logger.warn(`refresh host-crossing rejected (session ${session.id}: ${session.bound_host ?? '∅'} → ${requestHost ?? '∅'})`);
        throw e;
      }
    }

    // Rotate: new secret, sliding expiry per security.session_ttl_days (D-11).
    const rotated = mintRefreshToken(session.id);
    await this.prisma.userSession.update({
      where: { id: session.id },
      data: {
        refresh_token_hash: new Uint8Array(rotated.tokenHash),
        expires_at: addDays(await this.sessionTtlDays()),
        last_used_at: new Date(),
        ip: sanitizeIp(ctx.ip),
      },
    });
    await this.audit.append({ operation: 'auth.refresh', parameters: { session_id: session.id }, outcome: 'success', actorUserId: session.user_id });
    return this.tokenPair(session.user, rotated.token, session.id, ctx);
  }

  async logout(userId: string, sessionId: string): Promise<void> {
    await this.prisma.userSession.updateMany({
      where: { id: sessionId, user_id: userId, revoked_at: null },
      data: { revoked_at: new Date() },
    });
    await this.audit.append({ operation: 'auth.logout', parameters: { session_id: sessionId }, outcome: 'success', actorUserId: userId });
  }

  /**
   * GET /auth/sessions — the caller's own live sessions, newest-use first
   * (API spec §4.1 "List own active sessions"). Revoked and expired rows are
   * excluded server-side; `current` flags the presenting session so the UI
   * can mark it and offer "sign out this device" distinctly.
   */
  async listSessions(userId: string, currentSessionId: string): Promise<SessionView[]> {
    const rows = await this.prisma.userSession.findMany({
      where: { user_id: userId, revoked_at: null, expires_at: { gt: new Date() } },
      orderBy: { last_used_at: 'desc' },
    });
    return rows.map((s) => ({
      id: s.id,
      ip: s.ip,
      user_agent: s.user_agent,
      device_fingerprint: s.device_fingerprint,
      bound_host: s.bound_host,
      created_at: s.created_at,
      last_used_at: s.last_used_at,
      expires_at: s.expires_at,
      current: s.id === currentSessionId,
    }));
  }

  /**
   * DELETE /auth/sessions/{id} — revoke one of the caller's OWN sessions
   * ("Revoke own session", §4.1). Unknown, foreign or already-revoked ids
   * are a uniform 404: no enumeration of other users' sessions. Revoking
   * the presenting session is allowed and behaves like logout.
   */
  async revokeSession(userId: string, sessionId: string): Promise<void> {
    const result = await this.prisma.userSession.updateMany({
      where: { id: sessionId, user_id: userId, revoked_at: null },
      data: { revoked_at: new Date() },
    });
    if (result.count === 0) {
      throw new NotFoundException();
    }
    await this.audit.append({
      operation: 'auth.session.revoke',
      parameters: { session_id: sessionId },
      outcome: 'success',
      actorUserId: userId,
    });
  }

  private tokenPair(
    user: {
      id: string;
      email: string;
      display_name: string;
      is_super_admin: boolean;
      totp_enabled_at?: Date | null;
    },
    refreshToken: string,
    sessionId: string,
    ctx: LoginContext,
  ): TokenPairResponse {
    const access = this.jwt.sign(
      { sub: user.id, sid: sessionId, fp: ctx.deviceFingerprint ?? undefined },
      ACCESS_TTL_SECONDS,
    );
    return {
      access_token: access,
      refresh_token: refreshToken,
      token_type: 'jwt',
      expires_in: ACCESS_TTL_SECONDS,
      user: {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        is_super_admin: user.is_super_admin,
        two_factor_enabled: !!user.totp_enabled_at,
      },
    };
  }

  /** D-11 runtime seams — live settings reads, default on any failure. */
  private lockoutThreshold(): Promise<number> {
    return this.settings.runtimeInt('security.max_failed_logins');
  }

  private lockoutMinutes(): Promise<number> {
    return this.settings.runtimeInt('security.lockout_minutes');
  }

  private sessionTtlDays(): Promise<number> {
    return this.settings.runtimeInt('security.session_ttl_days');
  }

  private async registerFailedAttempt(user: {
    id: string;
    failed_login_count: number;
  }): Promise<void> {
    const [threshold, minutes] = await Promise.all([this.lockoutThreshold(), this.lockoutMinutes()]);
    const count = user.failed_login_count + 1;
    const data: { failed_login_count: number; locked_until?: Date } = { failed_login_count: count };
    if (count >= threshold) {
      data.locked_until = addMinutes(minutes);
      this.logger.warn(`account locked for ${minutes}m after ${count} failures (threshold ${threshold}) (${user.id})`);
    }
    await this.prisma.user.update({ where: { id: user.id }, data });
  }

  /** Lazily-generated decoy Argon2id hash (of a throwaway secret) — no password policy. */
  private decoyVerifyHash(): Promise<string> {
    this.decoyHash ??= this.hasher.hashSecret(crypto.randomBytes(24).toString('base64url'));
    return this.decoyHash;
  }
}

function addDays(days: number): Date {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

function addMinutes(minutes: number): Date {
  return new Date(Date.now() + minutes * 60 * 1000);
}

/** Only well-formed IPs reach inet columns; anything else is stored as null. */
function sanitizeIp(value?: string | null): string | null {
  if (!value) {
    return null;
  }
  const candidate = value.split(',')[0]!.trim();
  return isIP(candidate) !== 0 ? candidate : null;
}
