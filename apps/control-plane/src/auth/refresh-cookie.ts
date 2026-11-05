import type { Response } from 'express';

/**
 * Refresh-token cookie transport (security control C3).
 *
 * The master documentation commits P2 to moving the browser's refresh token
 * out of localStorage (XSS-readable) into an httpOnly cookie. The transport
 * is opt-in per request via the `X-Auth-Transport: cookie` header:
 *
 *   - cookie mode  — login/refresh set the httpOnly cookie and the response
 *     body OMITS the refresh token entirely, so no XSS can ever observe the
 *     secret. Rotation re-issues the cookie on every refresh.
 *   - body mode    — programmatic clients (SDK/CLI) keep the §4.1 body
 *     contract until they move to API tokens (C4). Browsers never use it.
 *
 * Cookie attributes:
 *   - HttpOnly            — invisible to JavaScript (the whole point)
 *   - SameSite=Strict     — never sent cross-site → CSRF-inert for refresh
 *   - Path=/api/v1/auth   — scoped: only auth endpoints ever receive it
 *   - Secure              — in production (dev runs plain-HTTP localhost)
 *   - Max-Age=7d          — mirrors REFRESH_TTL_DAYS (C3 sliding window)
 *
 * The cookie carries the same opaque, server-hashed random secret as the
 * body token — no signing needed; tampering fails the hash comparison.
 */

export const REFRESH_COOKIE = 'nexuspanel_rt';
export const TRANSPORT_COOKIE_HEADER = 'x-auth-transport';

/** TTL must mirror the session's sliding expiry in auth.service.ts. */
const REFRESH_COOKIE_MAX_AGE_SECONDS = Number(process.env.REFRESH_TTL_DAYS ?? 7) * 24 * 60 * 60;

/** Minimal structural view of a request's headers (Express-compatible). */
interface HeaderCarrier {
  headers: Record<string, string | string[] | undefined>;
}

export function wantsCookieTransport(req: HeaderCarrier): boolean {
  const value = req.headers[TRANSPORT_COOKIE_HEADER];
  const v = Array.isArray(value) ? value[0] : value;
  return typeof v === 'string' && v.trim().toLowerCase() === 'cookie';
}

/** Sets (or rotates) the refresh cookie on a passthrough response. */
export function setRefreshCookie(res: Response, token: string): void {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/api/v1/auth',
    maxAge: REFRESH_COOKIE_MAX_AGE_SECONDS * 1000,
  });
}

/** Clears the refresh cookie (logout / revocation). */
export function clearRefreshCookie(res: Response): void {
  res.cookie(REFRESH_COOKIE, '', {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/api/v1/auth',
    maxAge: 0,
  });
}

/**
 * Extracts the refresh cookie from the raw Cookie header (no cookie-parser
 * dependency). Returns undefined when absent — callers fall back to the
 * §4.1 body field.
 */
export function readRefreshCookie(req: HeaderCarrier): string | undefined {
  const header = req.headers.cookie;
  if (typeof header !== 'string' || header.length === 0) {
    return undefined;
  }
  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    if (name === REFRESH_COOKIE) {
      const value = pair.slice(eq + 1).trim();
      return value.length > 0 ? value : undefined;
    }
  }
  return undefined;
}
