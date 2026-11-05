'use client';

/**
 * Control-plane API client for the M0 slice.
 *
 * Token posture (C3): the 15-minute access token lives in memory +
 * sessionStorage; the 7-day rotating refresh token in localStorage. P2 moves
 * refresh storage to an httpOnly, SameSite=Strict cookie set by the control
 * plane (with CSRF double-submit) — tracked in docs/plan/BUILD_PLAN.md.
 *
 * A stable per-browser device fingerprint is sent on login/refresh so the
 * backend can bind sessions to the device (C3).
 */

const BASE = '/api/v1';
const ACCESS_KEY = 'nexuspanel.access';
const REFRESH_KEY = 'nexuspanel.refresh';
const USER_KEY = 'nexuspanel.user';
const FP_KEY = 'nexuspanel.fp';

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

function store(access: string, refresh: string, user: SessionUser): void {
  sessionStorage.setItem(ACCESS_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession(): void {
  sessionStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(USER_KEY);
}

export async function login(email: string, password: string): Promise<SessionUser> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Device-Fingerprint': deviceFingerprint() },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body?.detail ?? 'Login failed.');
  }
  store(body.access_token, body.refresh_token, body.user);
  return body.user as SessionUser;
}

let refreshInFlight: Promise<boolean> | null = null;

/** Single-flight refresh: N concurrent 401s trigger exactly one rotation. */
async function refreshSession(): Promise<boolean> {
  refreshInFlight ??= (async () => {
    try {
      const refresh = localStorage.getItem(REFRESH_KEY);
      if (!refresh) return false;
      const res = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Device-Fingerprint': deviceFingerprint() },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      if (!res.ok) {
        clearSession();
        return false;
      }
      const body = await res.json();
      store(body.access_token, body.refresh_token, body.user);
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
