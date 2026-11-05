import * as crypto from 'node:crypto';

/**
 * RFC 6238 TOTP (time-based one-time password) — dependency-free
 * implementation on node:crypto HMAC. The security model (C2) specifies
 * `otplib`; this module covers the exact subset the panel needs with the
 * same primitives the rest of the code base already trusts (HS256 JWT,
 * SHA-256 token hashes), keeping the supply-chain surface at zero.
 *
 * Parameters (RFC 6238 §5.1 defaults, and what every mainstream
 * authenticator app expects):
 *   - HMAC-SHA-1, 30-second time step, 6 digits
 *   - verification window: ±1 step (clock drift tolerance)
 *   - replay guard: a timestep may only be consumed once (caller persists
 *     the highest-seen step via TwoFactorService/preferences)
 *
 * Secret encoding is RFC 4648 base32 (no padding), the otpauth:// default.
 */

const TIME_STEP_SECONDS = 30;
const DIGITS = 6;
export const VERIFICATION_WINDOW = 1; // steps of allowed clock drift

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32 decode (no padding accepted). Returns null on garbage. */
export function base32Decode(input: string): Buffer | null {
  if (typeof input !== 'string' || input.length === 0) {
    return null;
  }
  const clean = input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (clean.length === 0 || /[^A-Z2-7]/.test(clean)) {
    return null;
  }
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 4648 base32 encode, unpadded (otpauth convention). */
export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** Generates a 160-bit TOTP secret (RFC 6238 §5.1 recommends ≥ 160 bits). */
export function generateTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

/** HOTP truncation (RFC 4226 §5.3) for one timestep. */
export function hotp(key: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! & 0xff) << 16) |
    ((mac[offset + 2]! & 0xff) << 8) |
    (mac[offset + 3]! & 0xff);
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}

export function totpAt(secretBase32: string, unixSeconds: number): string | null {
  const key = base32Decode(secretBase32);
  if (!key) {
    return null;
  }
  return hotp(key, Math.floor(unixSeconds / TIME_STEP_SECONDS));
}

export interface TotpCheck {
  valid: boolean;
  /** The matched timestep — persist it to block replays (only when valid). */
  step?: number;
}

/**
 * Verifies a user-supplied code against the current window (±1 step).
 *
 * `lastStep` (the highest previously consumed timestep) hardens against
 * replay: a code from a step at or below it is rejected even though it
 * would still verify cryptographically. Callers must persist a valid
 * check's step.
 */
export function verifyTotp(
  secretBase32: string,
  code: string,
  opts: { nowUnix?: number; lastStep?: number } = {},
): TotpCheck {
  const key = base32Decode(secretBase32);
  if (!key || typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
    return { valid: false };
  }
  const step = Math.floor((opts.nowUnix ?? Date.now() / 1000) / TIME_STEP_SECONDS);
  for (let delta = -VERIFICATION_WINDOW; delta <= VERIFICATION_WINDOW; delta += 1) {
    const candidate = step + delta;
    if (opts.lastStep !== undefined && candidate <= opts.lastStep) {
      continue;
    }
    if (timingSafeEq(hotp(key, candidate), code.trim())) {
      return { valid: true, step: candidate };
    }
  }
  return { valid: false };
}

/** Builds the otpauth:// URI authenticator apps import (account = user email). */
export function otpauthUri(email: string, secretBase32: string, issuer = 'NexusPanel'): string {
  // Conventional label form: otpauth://totp/<Issuer>:<account> — a literal
  // colon separates the parts; each part is percent-encoded individually.
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(email)}`;
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(TIME_STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function timingSafeEq(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
