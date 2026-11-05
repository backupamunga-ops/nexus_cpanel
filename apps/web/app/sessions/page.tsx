'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, clearSession, getUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Sessions screen (C3 device inventory, API spec §4.1 GET /auth/sessions).
 * Lists the caller's own live sessions, marks the presenting one, and offers
 * per-device revocation. Revoking the CURRENT session signs the user out —
 * the screen detects that and routes to /login like a logout.
 */

interface SessionRow {
  id: string;
  ip: string | null;
  user_agent: string | null;
  device_fingerprint: string | null;
  created_at: string;
  last_used_at: string;
  expires_at: string;
  current: boolean;
}

function short(id: string): string {
  return id.slice(0, 8);
}

function when(iso: string): string {
  return new Date(iso).toLocaleString();
}

/** First meaningful token of a user-agent string ("Firefox", "Chrome", "Safari"). */
function browser(ua: string | null): string {
  if (!ua) return 'unknown client';
  const m = ua.match(/(Firefox|Edg|OPR|Chrome|Safari)\/[\d.]+/);
  return m ? m[1].replace(/\/[\d.]+/, '') : ua.slice(0, 32);
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [user, setUser] = useState<ReturnType<typeof getUser>>(null);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async (): Promise<SessionRow[]> => {
    try {
      const rows = await api<SessionRow[]>('/auth/sessions');
      setSessions(rows);
      return rows;
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'control plane unreachable');
      return [];
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function revoke(row: SessionRow) {
    setBusyId(row.id);
    setMessage(null);
    try {
      await api(`/auth/sessions/${row.id}`, { method: 'DELETE' });
      if (row.current) {
        // Revoked the session under our feet — behave like logout.
        clearSession();
        window.location.href = '/login';
        return;
      }
      setMessage(`session ${short(row.id)} revoked — audit entry chained`);
      await refresh();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'revoke failed');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Shell active="/sessions" user={user}>
      <h1 className="np-title">Sessions &amp; devices</h1>
      <p className="np-subtitle">
        Every login mints its own 7-day rotating refresh secret (SHA-256 at rest,
        device-bound). Revoke a device to kill its session immediately; reuse of a
        revoked token already revokes everything (C3).
      </p>

      <div style={{ marginTop: 24, display: 'grid', gap: 12 }}>
        {sessions.length === 0 && (
          <p style={{ color: 'var(--np-muted)' }}>No active sessions.</p>
        )}
        {sessions.map((s) => (
          <div
            key={s.id}
            className="np-card"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}
          >
            <div>
              <strong>{browser(s.user_agent)}</strong>{' '}
              {s.current && <span className="np-badge">this device</span>}
              <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                session {short(s.id)}… · ip {s.ip ?? '—'} · fp {s.device_fingerprint ? short(s.device_fingerprint) : '—'}
              </div>
              <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                started {when(s.created_at)} · last used {when(s.last_used_at)}
              </div>
            </div>
            <button
              className="np-button"
              onClick={() => void revoke(s)}
              disabled={busyId === s.id}
              aria-label={s.current ? 'Sign out this device' : `Revoke session ${short(s.id)}`}
            >
              {busyId === s.id ? 'Revoking…' : s.current ? 'Sign out' : 'Revoke'}
            </button>
          </div>
        ))}
      </div>
      {message && (
        <p role="status" style={{ marginTop: 12, color: 'var(--np-muted)' }}>
          {message}
        </p>
      )}
    </Shell>
  );
}
