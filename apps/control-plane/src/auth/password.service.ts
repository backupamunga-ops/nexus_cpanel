import { Injectable } from '@nestjs/common';
import { SettingsService } from '../settings/settings.service';
import * as crypto from 'node:crypto';

import { hash as argon2Hash, verify as argon2Verify } from '@node-rs/argon2';

/**
 * Password hashing (security control C1) — extracted from auth.service so
 * that two-factor.service can depend on it WITHOUT the
 * auth.service ⇄ two-factor.service circular import that left
 * design:paramtypes holding an `undefined` at DI-evaluation time (the app
 * could not boot; the app.module.spec DI-graph gate now pins this).
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
  constructor(private readonly settings?: SettingsService) {}

  /**
   * Effective minimum password length (D-11): the stored
   * `security.password_min_length` override when the settings seam is
   * available, else the catalog default (12). No seam (unit tests, exotic
   * bootstraps) means the shipped baseline — never weaker than C1's floor.
   */
  private async minLength(): Promise<number> {
    return this.settings
      ? this.settings.runtimeInt('security.password_min_length')
      : 12;
  }

  async hash(password: string): Promise<string> {
    if (typeof password !== 'string') {
      throw new Error('password policy: password must be a string (C1)');
    }
    const min = await this.minLength();
    if (password.length < min) {
      throw new Error(`password policy: minimum ${min} characters (C1)`);
    }
    return argon2Hash(password, ARGON2ID_PARAMS);
  }

  /**
   * Argon2id for NON-password secrets (2FA backup codes, the login decoy):
   * same C1 parameters, deliberately OUTSIDE the password policy. Backup
   * codes are fixed-format ~19-char strings — an admin raising the password
   * minimum must never brick enrollment, and the decoy secret must never
   * trip the policy on the unknown-user path.
   */
  async hashSecret(secret: string): Promise<string> {
    return argon2Hash(secret, ARGON2ID_PARAMS);
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
