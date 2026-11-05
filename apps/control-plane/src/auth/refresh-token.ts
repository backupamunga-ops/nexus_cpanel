import * as crypto from 'node:crypto';

/**
 * Refresh token format (C3): `nxf1.<session-id>.<secret>`
 *
 * The session id is embedded so a presented token can be attributed to its
 * session even after rotation — that is what makes reuse detection possible
 * with the single `refresh_token_hash` column of schema v2.0:
 *
 *   - lookup session by embedded sid
 *   - SHA-256(presented token) === stored hash  → valid, rotate
 *   - SHA-256(presented token) !== stored hash  → STALE TOKEN REUSED →
 *     revoke every session of the user (C3 reuse response)
 */

export interface MintedRefreshToken {
  token: string;
  /** SHA-256 of the full token — the only thing stored server-side. */
  tokenHash: Buffer;
  sessionId: string;
}

export function mintRefreshToken(sessionId: string): MintedRefreshToken {
  const secret = crypto.randomBytes(32).toString('base64url');
  const token = `nxf1.${sessionId}.${secret}`;
  return { token, tokenHash: hashRefreshToken(token), sessionId };
}

export function hashRefreshToken(token: string): Buffer {
  return crypto.createHash('sha256').update(token, 'utf8').digest();
}

/** Extracts the embedded session id; null if the token is malformed. */
export function refreshSessionId(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'nxf1' || !parts[1] || !parts[2]) {
    return null;
  }
  return parts[1];
}
