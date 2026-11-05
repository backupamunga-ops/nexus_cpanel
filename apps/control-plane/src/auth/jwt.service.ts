import { Injectable } from '@nestjs/common';
import * as crypto from 'node:crypto';

/**
 * Minimal, dependency-free HS256 JWT (RFC 7519) for access tokens.
 *
 * Why hand-rolled: the M0 access-token surface is tiny (sign / verify with one
 * algorithm, fixed claims). Pulling in a full JWT framework adds supply-chain
 * surface for no gain. Algorithm confusion is structurally impossible: the
 * header is checked against the one supported alg and `verify()` only ever
 * computes HMAC-SHA-256.
 *
 * Secret provisioning: `AUTH_JWT_SECRET` (≥ 32 bytes). If absent, an ephemeral
 * random secret is generated per boot — safe-by-default for dev (tokens simply
 * do not survive restarts); production installs provision the secret via the
 * installer (never in code or CI logs, G-23/G-24).
 */
export interface AccessClaims {
  /** subject — user id (uuid v7) */
  sub: string;
  /** session id — ties the access token to its refresh session (revocation) */
  sid: string;
  /** token type — always 'access' */
  typ: 'access';
  /** device fingerprint binding (optional, C3) */
  fp?: string;
  /** issued at (unix seconds) */
  iat: number;
  /** expiry (unix seconds) */
  exp: number;
  /** issuer */
  iss: 'nexuspanel';
}

const SUPPORTED_ALG = 'HS256';

@Injectable()
export class JwtService {
  private readonly secret: Buffer;

  constructor(secretEnv?: string) {
    const raw = secretEnv ?? process.env.AUTH_JWT_SECRET;
    if (raw && raw.length >= 32) {
      this.secret = Buffer.from(raw, 'utf8');
    } else if (raw) {
      throw new Error('AUTH_JWT_SECRET must be at least 32 characters');
    } else {
      this.secret = crypto.randomBytes(48);
    }
  }

  sign(claims: Omit<AccessClaims, 'iat' | 'exp' | 'iss' | 'typ'> & { typ?: 'access' }, ttlSeconds: number): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: AccessClaims = {
      typ: 'access',
      iss: 'nexuspanel',
      iat: now,
      exp: now + ttlSeconds,
      ...claims,
    };
    const header = b64url(Buffer.from(JSON.stringify({ alg: SUPPORTED_ALG, typ: 'JWT' })));
    const body = b64url(Buffer.from(JSON.stringify(payload)));
    const mac = crypto.createHmac('sha256', this.secret).update(`${header}.${body}`).digest();
    return `${header}.${body}.${b64url(mac)}`;
  }

  /** Verifies signature, alg, and exp. Returns claims or null (never throws). */
  verify(token: string): AccessClaims | null {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    const [header, body, mac] = parts;
    let parsedHeader: { alg?: string };
    try {
      parsedHeader = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
    } catch {
      return null;
    }
    if (parsedHeader?.alg !== SUPPORTED_ALG) {
      return null;
    }
    const expected = crypto.createHmac('sha256', this.secret).update(`${header}.${body}`).digest();
    const given = unb64urlToBuffer(mac);
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
      return null;
    }
    let claims: AccessClaims;
    try {
      claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as AccessClaims;
    } catch {
      return null;
    }
    if (claims.typ !== 'access' || claims.iss !== 'nexuspanel') {
      return null;
    }
    if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) {
      return null;
    }
    return claims;
  }
}

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function unb64urlToBuffer(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}
