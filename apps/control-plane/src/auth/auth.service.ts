import {
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';
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
 * M0 accounts: the single dev bootstrap admin. P1 replaces this with the
 * `users` table (schema v2.0) + JWT (15 min) + rotating refresh tokens (C3).
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly passwords = new Map<string, string>();
  private readonly hasher = new PasswordService();
  private readonly bootstrapSeed: Promise<void>;

  constructor() {
    const email = process.env.DEV_ADMIN_EMAIL;
    const password = process.env.DEV_ADMIN_PASSWORD;
    if (email && password) {
      this.bootstrapSeed = this.hasher
        .hash(password)
        .then((h) => {
          this.passwords.set(email.toLowerCase(), h);
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

  async login(
    email: string,
    password: string,
    _totp?: string,
  ): Promise<{ access_token: string; token_type: 'jwt'; expires_in: number; user: unknown }> {
    const stored = this.passwords.get(email.toLowerCase());
    const ok = stored ? await this.hasher.verify(password, stored) : false;
    if (!ok) {
      // Uniform failure: no user-existence oracle (C3/C1 posture).
      throw new UnauthorizedException('invalid credentials');
    }
    // M0 dev token. P1: real 15-minute JWT with sid + device binding (C3).
    return {
      access_token: `dev.${Buffer.from(email).toString('base64url')}.${Date.now()}`,
      token_type: 'jwt',
      expires_in: 900,
      user: { email: email.toLowerCase() },
    };
  }
}
