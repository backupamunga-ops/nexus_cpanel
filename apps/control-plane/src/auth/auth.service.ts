import {
  Injectable,
  Logger,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { JwtService } from './jwt.service';
import { hashRefreshToken, mintRefreshToken, refreshSessionId } from './refresh-token';
import * as crypto from 'node:crypto';
import { isIP } from 'node:net';

import { hash as argon2Hash, verify as argon2Verify } from '@node-rs/argon2';

/**
 * Password hashing (security control C1).
 *
 * C1 requires Argon2id (m=64MiB, t=3, p=4) — bound here via @node-rs/argon2
 * (native, no WASM fallback: a soft-fallback would silently weaken C1).
 * Verification also accepts legacy dev-bootstrap scrypt hashes so existing
 * dev environments keep working until the next password change; production
 * provisioning only ever creates Argon2id hashes (PHC string format).
 */
export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
}

/** C1 parameters — mirrored in tests; changing them requires an ADR. */
export const ARGON2ID_PARAMS = { memoryCost: 65_536, timeCost: 3, parallelism: 4 } as const;

@Injectable()
export class PasswordService implements PasswordHasher {
  async hash(password: string): Promise<string> {
    if (typeof password !== 'string' || password.length < 12) {
      throw new Error('password policy: minimum 12 characters (C1)');
    }
    return argon2Hash(password, ARGON2ID_PARAMS);
  }

  async verify(password: string, stored: string): Promise<boolean> {
    if (typeof stored !== 'string') {
      return false;
    }
    if (stored.startsWith('$argon2id$')) {
      try {
        return await argon2Verify(stored, password);
      } catch {
        return false;
      }
    }
    if (stored.startsWith('scrypt$')) {
      return this.verifyLegacyScrypt(password, stored);
    }
    return false;
  }

  /** Dev-bootstrap format (M0 seam). Verify-only; never produced anymore. */
  private verifyLegacyScrypt(password: string, stored: string): boolean {
    const [scheme, nStr, rStr, pStr, saltHex, keyHex] = stored.split('$');
    if (scheme !== 'scrypt') {
      return false;
    }
    const key = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), keyHex.length / 2, {
      N: Number(nStr),
      r: Number(rStr),
      p: Number(pStr),
      maxmem: 256 * 1024 * 1024,
    });
    return timingSafeEqual(key, Buffer.from(keyHex, 'hex'));
  }
}

function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Authentication & sessions (security controls C1 + C3, API spec §4.1).
 *
 * - Passwords: Argon2id (C1) via PasswordService.
 * - Access tokens: 15-minute JWT (sid-bound for revocation).
 * - Refresh tokens: 7-day, rotating, device-fingerprint-bound, stored only as
 *   SHA-256. Reuse of a rotated token revokes EVERY session of the user (C3).
 * - Lockout: `failed_login_count` ≥ 5 ⇒ `locked_until` = now + 15 min.
 * - Unknown-email logins burn a real Argon2id verify against a decoy hash so
 *   response timing does not leak account existence (no user oracle).
 */

export interface LoginContext {
  ip?: string | null;
  userAgent?: string | null;
  deviceFingerprint?: string | null;
  totp?: string;
}

export interface TokenPairResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'jwt';
  expires_in: number;
  user: { id: string; email: string; display_name: string; is_super_admin: boolean };
}

const LOCKOUT_THRESHOLD = Number(process.env.LOCKOUT_THRESHOLD ?? 5);
const LOCKOUT_MINUTES = Number(process.env.LOCKOUT_MINUTES ?? 15);
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SEC ?? 900); // 15 min (C3)
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS ?? 7); // 7 days (C3)

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);
  private readonly hasher = new PasswordService();
  private readonly bootstrapSeed: Promise<void>;
  /** Decoy hash for the uniform-failure path (lazy, computed once). */
  private decoyHash: Promise<string> | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    @InjectAudit() private readonly audit: AuditAppender,
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
    if (user!.totp_enabled_at) {
      // 2FA (C2) lands in P2; never silently bypass an enrolled factor.
      await this.audit.append({ operation: 'auth.login', parameters: { email: normalized, reason: 'totp_required' }, outcome: 'failure', actorUserId: user!.id });
      throw new UnauthorizedException('totp required');
    }

    await this.prisma.user.update({
      where: { id: user!.id },
      data: {
        failed_login_count: 0,
        locked_until: null,
        last_login_at: new Date(),
        last_login_ip: sanitizeIp(ctx.ip),
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
        expires_at: addDays(REFRESH_TTL_DAYS),
      },
    });

    await this.audit.append({ operation: 'auth.login', parameters: { email: normalized, session_id: session.id }, outcome: 'success', actorUserId: user!.id });
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

    // Rotate: new secret, sliding 7-day expiry.
    const rotated = mintRefreshToken(session.id);
    await this.prisma.userSession.update({
      where: { id: session.id },
      data: {
        refresh_token_hash: new Uint8Array(rotated.tokenHash),
        expires_at: addDays(REFRESH_TTL_DAYS),
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

  private tokenPair(
    user: { id: string; email: string; display_name: string; is_super_admin: boolean },
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
      },
    };
  }

  private async registerFailedAttempt(user: {
    id: string;
    failed_login_count: number;
  }): Promise<void> {
    const count = user.failed_login_count + 1;
    const data: { failed_login_count: number; locked_until?: Date } = { failed_login_count: count };
    if (count >= LOCKOUT_THRESHOLD) {
      data.locked_until = addMinutes(LOCKOUT_MINUTES);
      this.logger.warn(`account locked for ${LOCKOUT_MINUTES}m after ${count} failures (${user.id})`);
    }
    await this.prisma.user.update({ where: { id: user.id }, data });
  }

  /** Lazily-generated decoy Argon2id hash (of a throwaway secret). */
  private decoyVerifyHash(): Promise<string> {
    this.decoyHash ??= this.hasher.hash(crypto.randomBytes(24).toString('base64url'));
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
