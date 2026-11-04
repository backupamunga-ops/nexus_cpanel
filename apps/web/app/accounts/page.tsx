'use client';

import { useCallback, useEffect, useState } from 'react';
import Shell from '../shell';

interface Account {
  username: string;
  package_id: string;
  status: string;
  uid?: number;
  homedir?: string;
}

/** M0 accounts surface: create test account + live usage from the agent. */
export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const r = await fetch('/api/v1/accounts');
      const j = await r.json();
      setAccounts(j.data ?? []);
    } catch {
      setMessage('control plane unreachable');
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
      const r = await fetch('/api/v1/accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, package_id: 'pkg-m0-test' }),
      });
      const j = await r.json();
      if (!r.ok) {
        setMessage(j.detail ?? 'create failed');
      } else {
        setMessage(`created ${j.username} (uid ${j.uid}) — audit entry chained`);
        setUsername('');
        await refresh();
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/accounts">
      <h1 className="np-title">Hosting accounts</h1>
      <p className="np-subtitle">M0 vertical slice: NestJS → signed command → Go agent → live cgroup usage.</p>

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
          <div key={a.username} className="np-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong>{a.username}</strong> <span className="np-badge">{a.status}</span>
              <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                uid {a.uid ?? '?'} · {a.homedir ?? ''}
              </div>
            </div>
            <code style={{ color: 'var(--np-muted)', fontSize: 12 }}>package {a.package_id}</code>
          </div>
        ))}
      </div>
    </Shell>
  );
}
