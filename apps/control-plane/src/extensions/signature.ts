import * as crypto from 'node:crypto';

/**
 * Extension wire-signing helpers (SDK spec §5.1/§5.2) — P7.
 *
 * Every call the PANEL makes to an EXTENSION carries:
 *
 *   X-Nexuspanel-Extension-Id: <uuid>
 *   X-Nexuspanel-Timestamp:    <unix seconds>
 *   X-Nexuspanel-Signature:    base64(hmac_sha256(shared_secret,
 *                              method + path + body + timestamp))
 *
 * The extension MUST verify the signature and reject anything whose
 * timestamp drifts more than 60 s (replay window, spec §5.1). Signing input
 * is the exact concatenation `method + path + body + timestamp` — method
 * upper-case, path as called, body the raw JSON string (empty string for
 * GET). The same construction lives in `nexus-example-reporter` (the
 * acceptance extension), which is what keeps the two sides honest.
 */

export const SIGNATURE_TIMESTAMP_TOLERANCE_SEC = 60;

export function signPanelToExt(
  sharedSecret: string,
  method: string,
  path: string,
  body: string,
  timestamp: string,
): string {
  const mac = crypto
    .createHmac('sha256', sharedSecret)
    .update(`${method.toUpperCase()}${path}${body}${timestamp}`)
    .digest('base64');
  return mac;
}

/** Headers object for a panel → extension call. */
export function panelToExtHeaders(
  extensionId: string,
  sharedSecret: string,
  method: string,
  path: string,
  body: string,
): Record<string, string> {
  const ts = Math.floor(Date.now() / 1000).toString();
  return {
    'x-nexuspanel-extension-id': extensionId,
    'x-nexuspanel-timestamp': ts,
    'x-nexuspanel-signature': signPanelToExt(sharedSecret, method, path, body, ts),
  };
}

/**
 * The extension's API token for `/api/v1/ext/*` (spec §5.3: "derived from
 * shared_secret at registration time and rotated on uninstall/re-register").
 * Derivation is deterministic: token = base64url(HMAC(secret, domain-label)).
 * The panel recomputes it per request from the stored SecretBox envelope —
 * the derived token is never itself stored.
 */
export function deriveExtToken(sharedSecret: string): string {
  return crypto
    .createHmac('sha256', sharedSecret)
    .update('nexuspanel/ext-token/v1')
    .digest('base64url');
}

/** Constant-time string comparison (length-safe). */
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) {
    // Still burn a comparison so short/long probes don't short-circuit faster.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

/** A fresh one-time shared secret: 32 random bytes, base64. */
export function newSharedSecret(): string {
  return crypto.randomBytes(32).toString('base64');
}
