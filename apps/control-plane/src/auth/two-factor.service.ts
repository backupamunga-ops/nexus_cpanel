import {
  ConflictException,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { PasswordService } from './auth.service';
import { SecretBox } from './secret-box';
import { generateTotpSecret, otpauthUri, verifyTotp } from './totp';
import { Prisma } from '@prisma/client';
import * as crypto from 'node:crypto';

/**
 * Two-factor authentication (security control C2, API spec §4.1 /auth/2fa/*).
 *
 * - TOTP: RFC 6238 (see totp.ts) — 160-bit secret, base32, ±1 step drift,
 *   replay-guarded by persisting the highest consumed timestep in
 *   users.preferences.totp_last_step.
 * - Secret at rest: age-encrypted in M0's successor — today the NXPB1
 *   AES-256-GCM envelope (secret-box.ts) keyed outside the database (C9
 *   properties; the installer's age/HKDF hierarchy replaces the envelope
 *   format, not the properties).
 * - Backup codes: 10 × 16-char (RFC-4648-style alphabet, grouped for
 *   humans), Argon2id-hashed, the hash JSON itself encrypted at rest
 *   (backup_codes_enc). A used code is consumed — its hash is removed —
 *   so replays fail. Plaintext codes are returned exactly once.
 * - Password re-entry gates every destructive action (disable, regenerate).
 * - Failure discipline: wrong second factors count as failed login attempts
 *   (lockout machinery, C3) via AuthService.registerFailedAttempt.
 *
 * All routes on this service are @SessionOnly(): an API token can never
 * enable, disable or read second factors.
 */

const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_LEN = 16;
/** Unambiguous 32-char alphabet (no I/L/O/0/1) — 5 bits per char, bias-free. */
const BACKUP_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export interface TwoFactorSetup {
  /** base32 secret — shown/QR'd exactly once, re-runnable until enabled. */
  secret: string;
  otpauth_uri: string;
}

export interface TwoFactorConsumed {
  ok: true;
  method: 'totp' | 'backup_code';
  /** Matched timestep — the caller persists it with its own user.update. */
  totpStep?: number;
}

export type TwoFactorRejected = { ok: false; reason: 'totp_invalid' | 'backup_code_invalid' };

/** Minimal user row shape the service loads (fresh state on every call). */
export interface EnrolledUser {
  id: string;
  email: string;
  password_hash: string;
  totp_secret_enc: Uint8Array | null;
  totp_enabled_at: Date | null;
  backup_codes_enc: Uint8Array | null;
  preferences: unknown;
}

@Injectable()
export class TwoFactorService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly box: SecretBox,
    private readonly hasher: PasswordService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  /** Begins enrollment: mint + store an encrypted secret (not yet enabled). */
  async setup(userId: string): Promise<TwoFactorSetup> {
    const user = await this.loadUser(userId);
    this.requireAvailable();
    if (user.totp_enabled_at) {
      throw new ConflictException('two-factor authentication is already enabled');
    }
    const secret = generateTotpSecret();
    await this.prisma.user.update({
      where: { id: user.id },
      data: { totp_secret_enc: new Uint8Array(this.box.encrypt(Buffer.from(secret, 'utf8'))) },
    });
    await this.audit.append({
      operation: 'auth.2fa.setup',
      parameters: {},
      outcome: 'success',
      actorUserId: user.id,
    });
    return { secret, otpauth_uri: otpauthUri(user.email, secret) };
  }

  /** Confirms enrollment with a live code; enables 2FA and mints backup codes. */
  async verifyEnrollment(userId: string, code: string): Promise<{ backup_codes: string[] }> {
    const user = await this.loadUser(userId);
    this.requireAvailable();
    if (user.totp_enabled_at) {
      throw new ConflictException('two-factor authentication is already enabled');
    }
    if (!user.totp_secret_enc) {
      throw new ConflictException('no pending enrollment — call /auth/2fa/setup first');
    }
    const secret = this.decryptSecret(user.totp_secret_enc);
    const check = verifyTotp(secret, code, {
      lastStep: lastStepFrom(user.preferences),
    });
    if (!check.valid || check.step === undefined) {
      await this.audit.append({
        operation: 'auth.2fa.verify',
        parameters: { reason: 'invalid_code' },
        outcome: 'failure',
        actorUserId: user.id,
      });
      throw new UnauthorizedException('invalid verification code');
    }

    const backupCodes = this.generateBackupCodes();
    const hashes: string[] = [];
    for (const c of backupCodes) {
      hashes.push(await this.hasher.hashSecret(c));
    }
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        totp_enabled_at: new Date(),
        backup_codes_enc: new Uint8Array(this.box.encrypt(Buffer.from(JSON.stringify(hashes)))),
        // Persist the consumed enrollment step so it can never be replayed.
        preferences: withLastStep(user.preferences, check.step),
      },
    });
    await this.audit.append({
      operation: 'auth.2fa.enabled',
      parameters: {},
      outcome: 'success',
      actorUserId: user.id,
    });
    return { backup_codes: backupCodes };
  }

  /** Disables 2FA — requires the account password (C2). */
  async disable(userId: string, password: string): Promise<void> {
    const user = await this.loadUser(userId);
    await this.requirePassword(user, password, 'auth.2fa.disable');
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        totp_secret_enc: null,
        totp_enabled_at: null,
        backup_codes_enc: null,
      },
    });
    await this.audit.append({
      operation: 'auth.2fa.disable',
      parameters: {},
      outcome: 'success',
      actorUserId: user.id,
    });
  }

  /** Regenerates the backup-code set (old codes die) — password re-entry. */
  async regenerateBackupCodes(
    userId: string,
    password: string,
  ): Promise<{ backup_codes: string[] }> {
    const user = await this.loadUser(userId);
    if (!user.totp_enabled_at) {
      throw new ConflictException('two-factor authentication is not enabled');
    }
    await this.requirePassword(user, password, 'auth.2fa.backup_codes_regenerated');
    const backupCodes = this.generateBackupCodes();
    const hashes: string[] = [];
    for (const c of backupCodes) {
      hashes.push(await this.hasher.hashSecret(c));
    }
    await this.prisma.user.update({
      where: { id: user.id },
      data: { backup_codes_enc: new Uint8Array(this.box.encrypt(Buffer.from(JSON.stringify(hashes)))) },
    });
    await this.audit.append({
      operation: 'auth.2fa.backup_codes_regenerated',
      parameters: {},
      outcome: 'success',
      actorUserId: user.id,
    });
    return { backup_codes: backupCodes };
  }

  /**
   * Login challenge (called by AuthService.login for totp-enabled users).
   * A 6-digit input is treated as a TOTP code, anything else as a backup
   * code — the two never cross-verify, so one Argon2id verify at most is
   * wasted per failed attempt.
   */
  async consumeLoginCode(user: EnrolledUser, code: string): Promise<TwoFactorConsumed | TwoFactorRejected> {
    const normalized = typeof code === 'string' ? code.trim() : '';
    if (/^\d{6}$/.test(normalized)) {
      return this.consumeTotp(user, normalized);
    }
    return this.consumeBackupCode(user, normalized);
  }

  private async consumeTotp(user: EnrolledUser, code: string): Promise<TwoFactorConsumed | TwoFactorRejected> {
    if (!user.totp_secret_enc) {
      // Enabled flag without a secret is a corrupt state — fail closed.
      return { ok: false, reason: 'totp_invalid' };
    }
    this.requireAvailable();
    const secret = this.decryptSecret(user.totp_secret_enc);
    const check = verifyTotp(secret, code, { lastStep: lastStepFrom(user.preferences) });
    if (!check.valid || check.step === undefined) {
      return { ok: false, reason: 'totp_invalid' };
    }
    // The step is persisted by the caller's own successful-login update —
    // single write, no replay window between verify and persist.
    return { ok: true, method: 'totp', totpStep: check.step };
  }

  private async consumeBackupCode(
    user: EnrolledUser,
    code: string,
  ): Promise<TwoFactorConsumed | TwoFactorRejected> {
    if (!user.backup_codes_enc) {
      return { ok: false, reason: 'backup_code_invalid' };
    }
    this.requireAvailable();
    const normalized = normalizeBackupCode(code);
    if (!normalized) {
      return { ok: false, reason: 'backup_code_invalid' };
    }
    const hashes = this.decryptBackupHashes(user.backup_codes_enc);
    let matchIndex = -1;
    for (const [i, h] of hashes.entries()) {
      if (await this.hasher.verify(normalized, h)) {
        matchIndex = i;
        break;
      }
    }
    if (matchIndex < 0) {
      return { ok: false, reason: 'backup_code_invalid' };
    }
    // Consume: rewrite the set without the used hash (replay-proof).
    hashes.splice(matchIndex, 1);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { backup_codes_enc: new Uint8Array(this.box.encrypt(Buffer.from(JSON.stringify(hashes)))) },
    });
    return { ok: true, method: 'backup_code' };
  }

  // ───────────────────────────── helpers ─────────────────────────────

  /**
   * Public seam for AuthService: the successful-login update persists the
   * consumed TOTP step in the same write as its own bookkeeping.
   */
  preferencesWithStep(preferences: unknown, step: number): Prisma.InputJsonValue {
    return withLastStep(preferences, step);
  }

  /**
   * Loads fresh user state for every call — enrollment decisions must never
   * run against a controller-cached snapshot (a parallel disable or a second
   * setup tab would otherwise race the check).
   */
  private async loadUser(userId: string): Promise<EnrolledUser> {
    const row = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!row) {
      throw new UnauthorizedException('account not found');
    }
    return row as unknown as EnrolledUser;
  }

  private requireAvailable(): void {
    if (!this.box.configured) {
      throw new ServiceUnavailableException(
        'two-factor storage is unavailable: secrets key not configured (CP_SECRETS_KEY / CP_SECRETS_KEY_PATH)',
      );
    }
  }

  private decryptSecret(enc: Uint8Array): string {
    try {
      return this.box.decrypt(Buffer.from(enc)).toString('utf8');
    } catch {
      // Wrong/rotated key or corrupt row: fail closed, never fall back.
      throw new ServiceUnavailableException('two-factor secret cannot be decrypted with the configured key');
    }
  }

  private decryptBackupHashes(enc: Uint8Array): string[] {
    try {
      const parsed: unknown = JSON.parse(this.box.decrypt(Buffer.from(enc)).toString('utf8'));
      if (!Array.isArray(parsed) || parsed.some((h) => typeof h !== 'string')) {
        throw new Error('bad shape');
      }
      return parsed as string[];
    } catch {
      throw new ServiceUnavailableException('backup codes cannot be decrypted with the configured key');
    }
  }

  private async requirePassword(user: EnrolledUser, password: string, operation: string): Promise<void> {
    const ok = await this.hasher.verify(password ?? '', user.password_hash);
    if (!ok) {
      await this.audit.append({
        operation,
        parameters: { reason: 'bad_password' },
        outcome: 'failure',
        actorUserId: user.id,
      });
      throw new UnauthorizedException('invalid credentials');
    }
  }

  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < BACKUP_CODE_COUNT; i += 1) {
      const raw = crypto.randomBytes(BACKUP_CODE_LEN);
      let code = '';
      for (let j = 0; j < BACKUP_CODE_LEN; j += 1) {
        code += BACKUP_ALPHABET[raw[j]! & 31];
        if (j % 4 === 3 && j !== BACKUP_CODE_LEN - 1) {
          code += '-';
        }
      }
      codes.push(code);
    }
    return codes;
  }
}

/** Normalizes a presented backup code: uppercase, dashes/spaces stripped. */
export function normalizeBackupCode(code: string): string | null {
  const normalized = code.toUpperCase().replace(/[\s-]/g, '');
  return normalized.length === BACKUP_CODE_LEN ? normalized : null;
}

function lastStepFrom(preferences: unknown): number | undefined {
  if (preferences && typeof preferences === 'object' && !Array.isArray(preferences)) {
    const v = (preferences as Record<string, unknown>)['totp_last_step'];
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) {
      return v;
    }
  }
  return undefined;
}

function withLastStep(preferences: unknown, step: number): Prisma.InputJsonValue {
  const base: Record<string, unknown> =
    preferences && typeof preferences === 'object' && !Array.isArray(preferences)
      ? { ...(preferences as Record<string, unknown>) }
      : {};
  base['totp_last_step'] = step;
  return base as Prisma.InputJsonValue;
}
