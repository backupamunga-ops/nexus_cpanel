'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, clearSession, getUser } from '../../lib/api';
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

/** M0 accounts surface: create test account + live usage from the agent. */
export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [user, setUser] = useState(getUser());

  useEffect(() => {
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const j = await api<{ data: Account[] }>('/accounts');
      setAccounts(j.data ?? []);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
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
      await refresh();
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
        M0 vertical slice: NestJS → signed command → Go agent → live cgroup usage,
        with the account row + hash-chained audit entry committed in one transaction.
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
        {accounts.map((a) => (
          <div
            key={a.id}
            className="np-card"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          >
            <div>
              <strong>{a.username}</strong> <span className="np-badge">{a.status}</span>
              <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                uid {a.uid ?? '?'} · {a.homedir ?? ''}
              </div>
            </div>
            <code style={{ color: 'var(--np-muted)', fontSize: 12 }}>
              {a.package_id.slice(0, 8)}…
            </code>
          </div>
        ))}
      </div>
    </Shell>
  );
}
