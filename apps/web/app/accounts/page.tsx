'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { api, clearSession, getAccessToken, getUser } from '../../lib/api';
import { EventsStream, UsageSample } from '../../lib/events';
import Shell from '../shell';

interface Account {
  id: string;
  username: string;
  package_id: string;
  status: string;
  uid?: number;
  homedir?: string;
  created_at: string;
}

function fmtBytes(n?: number): string {
  if (n === undefined || n === null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}

/** M0 accounts surface: create test account + LIVE usage over WebSocket. */
export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [usage, setUsage] = useState<Record<string, UsageSample>>({});
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState(false);
  // Hydration-safe: the session user exists only client-side (localStorage).
  const [user, setUser] = useState<ReturnType<typeof getUser>>(null);
  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);
  const streamRef = useRef<EventsStream | null>(null);

  const refresh = useCallback(async (): Promise<Account[]> => {
    try {
      const j = await api<{ data: Account[] }>('/accounts');
      setAccounts(j.data ?? []);
      return j.data ?? [];
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'control plane unreachable');
      return [];
    }
  }, []);

  // Live usage over WebSocket — the M0 contract surface.
  useEffect(() => {
    if (!getAccessToken()) return;
    const stream = new EventsStream(getAccessToken, {
      onUsage: (accountId, sample) => setUsage((u) => ({ ...u, [accountId]: sample })),
      onError: (accountId, error) =>
        setUsage((u) => ({ ...u, [accountId]: { error } })),
      onReady: () => setLive(true),
    });
    streamRef.current = stream;
    stream.start();
    void refresh().then((list) => {
      for (const a of list) stream.subscribe(a.id);
    });
    return () => {
      stream.stop();
      streamRef.current = null;
    };
  }, [refresh]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const created = await api<Account>('/accounts', {
        method: 'POST',
        body: JSON.stringify({ username, package_id: 'pkg-default' }),
      });
      setMessage(`created ${created.username} (uid ${created.uid}) — audit entry chained`);
      setUsername('');
      const list = await refresh();
      streamRef.current?.subscribe(created.id ?? list.find((a) => a.username === created.username)?.id ?? '');
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'create failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell
      active="/accounts"
      user={user}
      onLogout={() => {
        clearSession();
        window.location.href = '/login';
      }}
    >
      <h1 className="np-title">Hosting accounts</h1>
      <p className="np-subtitle">
        NestJS → signed command → Go agent → live cgroup usage. Account rows and
        hash-chained audit entries commit in one transaction.{' '}
        <span className="np-badge">{live ? 'live stream connected' : 'connecting…'}</span>
      </p>

      <form onSubmit={create} style={{ display: 'flex', gap: 8, marginTop: 20, maxWidth: 480 }}>
        <input
          className="np-input"
          placeholder="username (e.g. alice)"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          pattern="[a-z][a-z0-9-]{0,31}"
          required
          aria-label="New account username"
        />
        <button className="np-button" type="submit" disabled={busy}>
          {busy ? 'Creating…' : 'Create test account'}
        </button>
      </form>
      {message && (
        <p role="status" style={{ marginTop: 12, color: 'var(--np-muted)' }}>
          {message}
        </p>
      )}

      <div style={{ marginTop: 24, display: 'grid', gap: 12 }}>
        {accounts.length === 0 && (
          <p style={{ color: 'var(--np-muted)' }}>No accounts yet. Create the first one above.</p>
        )}
        {accounts.map((a) => {
          const u = usage[a.id];
          return (
            <div
              key={a.id}
              className="np-card"
              style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}
            >
              <div>
                <strong>{a.username}</strong> <span className="np-badge">{a.status}</span>
                <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                  uid {a.uid ?? '?'} · {a.homedir ?? ''}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--np-muted)', textAlign: 'right' }}>
                <span>
                  <strong style={{ color: 'var(--np-fg)' }}>{u?.procs ?? '—'}</strong> procs
                </span>
                <span>
                  <strong style={{ color: 'var(--np-fg)' }}>{fmtBytes(u?.mem_bytes)}</strong> mem
                </span>
                <span>
                  <strong style={{ color: 'var(--np-fg)' }}>{fmtBytes(u?.disk_bytes)}</strong> disk
                </span>
                <code>{a.package_id.slice(0, 8)}…</code>
              </div>
            </div>
          );
        })}
      </div>
    </Shell>
  );
}
