import {
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';

/**
 * Password hashing seam (security control C1).
 *
 * C1 requires Argon2id (m=64MiB, t=3, p=4). Node's stdlib has no argon2; the
 * native binding lands with Prisma + the users table in P1. The M0 dev-mode
 * bootstrap account uses scrypt (memory-hard, RFC 7914) so nothing in this file
 * is a placeholder API: the interface is final, the algorithm binding is the
 * only P1 change.
 */
export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
}

@Injectable()
export class PasswordService implements PasswordHasher {
  private static readonly params = { N: 2 ** 17, r: 8, p: 1, keylen: 32 };

  async hash(password: string): Promise<string> {
    if (typeof password !== 'string' || password.length < 12) {
      throw new Error('password policy: minimum 12 characters (C1)');
    }
    const salt = crypto.randomBytes(16);
    const { N, r, p, keylen } = PasswordService.params;
    const key = crypto.scryptSync(password, salt, keylen, { N, r, p });
    return `scrypt$${N}$${r}$${p}$${salt.toString('hex')}$${key.toString('hex')}`;
  }

  async verify(password: string, stored: string): Promise<boolean> {
    const [scheme, nStr, rStr, pStr, saltHex, keyHex] = stored.split('$');
    if (scheme !== 'scrypt') {
      return false;
    }
    const key = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), keyHex.length / 2, {
      N: Number(nStr),
      r: Number(rStr),
      p: Number(pStr),
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
  private readonly passwords = new Map<string, string>();
  private readonly hasher = new PasswordService();

  constructor() {
    const email = process.env.DEV_ADMIN_EMAIL;
    const password = process.env.DEV_ADMIN_PASSWORD;
    if (email && password) {
      void this.hasher.hash(password).then((h) => {
        this.passwords.set(email.toLowerCase(), h);
      });
    }
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
