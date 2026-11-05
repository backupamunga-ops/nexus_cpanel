import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Dovecot-compatible password hashing for mailboxes (ADR-0013).
 *
 * Mailbox credentials are verified by Dovecot's SQL userdb against the
 * panel DB, so the stored hash must be a scheme Dovecot natively parses.
 * `{SSHA512}` is that scheme in every default build: base64 of
 * SHA512(password ‖ salt) ‖ salt, prefixed with the scheme tag. Salt is
 * 16 random bytes; verification is constant-time where the lengths match.
 *
 * The agent is deliberately not in this path (ADR-0013): plaintext travels
 * browser → control plane → DB only.
 */

const SCHEME = '{SSHA512}';
const SALT_BYTES = 16;

/** Hashes a password into Dovecot's `{SSHA512}` one-line format. */
export function hashMailboxPassword(password: string): string {
  assertPasswordShape(password);
  const salt = randomBytes(SALT_BYTES);
  const digest = createHash('sha512').update(password, 'utf8').update(salt).digest();
  return SCHEME + Buffer.concat([digest, salt]).toString('base64');
}

/** Verifies a password against a stored `{SSHA512}` hash. */
export function verifyMailboxPassword(password: string, stored: string): boolean {
  if (!stored.startsWith(SCHEME)) return false;
  let decoded: Buffer;
  try {
    decoded = Buffer.from(stored.slice(SCHEME.length), 'base64');
  } catch {
    return false;
  }
  // 64-byte SHA-512 digest + the salt that follows it.
  if (decoded.length <= 64) return false;
  const digest = decoded.subarray(0, 64);
  const salt = decoded.subarray(64);
  const candidate = createHash('sha512').update(password, 'utf8').update(salt).digest();
  return timingSafeEqual(digest, candidate);
}

export const MIN_MAILBOX_PASSWORD_LEN = 8;
export const MAX_MAILBOX_PASSWORD_LEN = 1024;

/** Shared shape rule: 8–1024 bytes, no NUL (mirrors the FTP rule). */
export function assertPasswordShape(password: string): void {
  const bytes = Buffer.byteLength(password, 'utf8');
  if (
    password.length < MIN_MAILBOX_PASSWORD_LEN ||
    bytes > MAX_MAILBOX_PASSWORD_LEN ||
    password.includes('\0')
  ) {
    throw new Error(`password must be ${MIN_MAILBOX_PASSWORD_LEN}-${MAX_MAILBOX_PASSWORD_LEN} bytes without NUL`);
  }
}
