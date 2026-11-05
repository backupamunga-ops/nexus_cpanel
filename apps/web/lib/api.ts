'use client';

/**
 * Control-plane API client.
 *
 * Token posture (C3, P2): the 15-minute access token lives in memory +
 * sessionStorage ONLY. The rotating refresh token never touches JavaScript-
 * observable storage: login/refresh opt into the control plane's httpOnly
 * cookie transport (`X-Auth-Transport: cookie`), and the server stores it in
 * an httpOnly, SameSite=Strict cookie scoped to /api/v1/auth. The response
 * body carries no refresh token at all — the XSS read path is gone.
 *
 * A stable per-browser device fingerprint is sent on login/refresh so the
 * backend can bind sessions to the device (C3).
 */

const BASE = '/api/v1';
const ACCESS_KEY = 'nexuspanel.access';
const USER_KEY = 'nexuspanel.user';
const FP_KEY = 'nexuspanel.fp';

/** Detail string the control plane returns when an enrolled user omits the TOTP code. */
export const TOTP_CHALLENGE_DETAIL = 'totp code required';

/** Raised when the backend demands a second factor before completing login. */
export class TotpChallengeError extends Error {
  constructor() {
    super(TOTP_CHALLENGE_DETAIL);
    this.name = 'TotpChallengeError';
  }
}

export interface SessionUser {
  id: string;
  email: string;
  display_name: string;
  is_super_admin: boolean;
}

function deviceFingerprint(): string {
  if (typeof window === 'undefined') return 'server';
  let fp = localStorage.getItem(FP_KEY);
  if (!fp) {
    fp = crypto.randomUUID();
    localStorage.setItem(FP_KEY, fp);
  }
  return fp;
}

export function getAccessToken(): string | null {
  if (typeof window === 'undefined') return null;
  return sessionStorage.getItem(ACCESS_KEY);
}

export function getUser(): SessionUser | null {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem(USER_KEY);
  return raw ? (JSON.parse(raw) as SessionUser) : null;
}

function store(access: string, user: SessionUser): void {
  sessionStorage.setItem(ACCESS_KEY, access);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession(): void {
  sessionStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(USER_KEY);
  // Legacy M0 clients kept the refresh token here; remove it if present.
  localStorage.removeItem('nexuspanel.refresh');
}

export async function login(email: string, password: string, totp?: string): Promise<SessionUser> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Device-Fingerprint': deviceFingerprint(),
      'X-Auth-Transport': 'cookie',
    },
    body: JSON.stringify({ email, password, ...(totp ? { totp } : {}) }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (body?.detail === TOTP_CHALLENGE_DETAIL) {
      throw new TotpChallengeError();
    }
    throw new Error(body?.detail ?? 'Login failed.');
  }
  store(body.access_token, body.user);
  return body.user as SessionUser;
}

let refreshInFlight: Promise<boolean> | null = null;

/**
 * Single-flight refresh: N concurrent 401s trigger exactly one rotation.
 * The httpOnly cookie is attached by the browser automatically (same-origin);
 * no body token exists anymore.
 */
async function refreshSession(): Promise<boolean> {
  refreshInFlight ??= (async () => {
    try {
      const res = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Fingerprint': deviceFingerprint(),
        },
      });
      if (!res.ok) {
        clearSession();
        return false;
      }
      const body = await res.json();
      store(body.access_token, body.user);
      return true;
    } catch {
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

/** Authenticated fetch: Bearer token, one silent refresh + retry on 401. */
export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const doFetch = () =>
    fetch(`${BASE}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}),
        ...init.headers,
      },
    });

  let res = await doFetch();
  if (res.status === 401 && (await refreshSession())) {
    res = await doFetch();
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) {
      clearSession();
      window.location.href = '/login';
    }
    throw new Error(body?.detail ?? `Request failed (${res.status})`);
  }
  return body as T;
}

/** Revokes the presenting session server-side, then clears local state. */
export async function logout(): Promise<void> {
  try {
    await api('/auth/logout', { method: 'POST' });
  } catch {
    // Best effort — local state is cleared regardless.
  }
  clearSession();
  window.location.href = '/login';
}
