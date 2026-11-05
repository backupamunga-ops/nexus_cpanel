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
  /** The CALLER's role on this account — gates the sharing controls. */
  my_role?: string;
}

interface ShareView {
  id: string;
  user: { id: string; email: string; display_name: string };
  role: string;
  granted_by: { id: string; email: string } | null;
  created_at: string;
}

const SHAREABLE_ROLES = ['admin', 'member', 'readonly'] as const;

function fmtBytes(n?: number): string {
  if (n === undefined || n === null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}

/** Sharing is a trust-level decision: owner/admin/super-admin only (server enforces too). */
function canShare(account: Account): boolean {
  return account.my_role === 'owner' || account.my_role === 'admin' || account.my_role === 'super-admin';
}

/**
 * Access-sharing panel for one account: the active rows of
 * user_hosting_account_access — the exact rows the control plane's
 * PermissionsGuard enforces on every account-scoped route. Listing needs
 * only account:read; grant/revoke need account:share (owner/admin).
 */
function SharingPanel({
  account,
  me,
}: {
  account: Account;
  me: { id: string; email: string } | null;
}) {
  const [shares, setShares] = useState<ShareView[] | null>(null);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<string>('member');
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async (): Promise<ShareView[]> => {
    try {
      const j = await api<{ data: ShareView[] }>(`/accounts/${account.id}/shares`);
      setShares(j.data ?? []);
      return j.data ?? [];
    } catch (err) {
      setShares([]);
      setMsg(err instanceof Error ? err.message : 'failed to load shares');
      return [];
    }
  }, [account.id]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function grant(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const created = await api<ShareView>(`/accounts/${account.id}/shares`, {
        method: 'POST',
        body: JSON.stringify({ email, role }),
      });
      setMsg(`granted '${created.role}' to ${created.user.email} — audit entry chained`);
      setEmail('');
      await refresh();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'grant failed');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(s: ShareView) {
    setBusy(true);
    setMsg(null);
    try {
      await api(`/accounts/${account.id}/shares/${s.id}`, { method: 'DELETE' });
      setMsg(`revoked ${s.user.email}'s '${s.role}' access — audit entry chained`);
      await refresh();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'revoke failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      style={{
        marginTop: 12,
        paddingTop: 12,
        borderTop: '1px solid var(--np-border, #2a2a35)',
        display: 'grid',
        gap: 10,
      }}
    >
      <div style={{ fontSize: 12, color: 'var(--np-muted)' }}>
        Delegated access — every row here is enforced server-side on ALL account
        routes; grant/revoke writes hash-chained audit entries.
      </div>

      {shares === null && <p style={{ color: 'var(--np-muted)', margin: 0 }}>loading shares…</p>}

      {shares !== null && shares.length === 0 && (
        <p style={{ color: 'var(--np-muted)', margin: 0 }}>
          No access rows yet — nobody (not even you) is listed. The panel owner
          row is seeded out-of-band; grant access to collaborators below.
        </p>
      )}

      {shares?.map((s) => (
        <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <code style={{ fontSize: 12 }}>{s.user.email || s.user.id}</code>
          {s.user.id === me?.id && <span style={{ fontSize: 11, color: 'var(--np-muted)' }}>(you)</span>}
          <span className="np-badge">{s.role}</span>
          <span style={{ fontSize: 11, color: 'var(--np-muted)', flex: 1 }}>
            {s.granted_by ? `granted by ${s.granted_by.email}` : 'granted out-of-band'}
          </span>
          {canShare(account) && s.role !== 'owner' && (
            <button
              className="np-button"
              style={{ padding: '2px 10px', fontSize: 12 }}
              disabled={busy}
              onClick={() => void revoke(s)}
              aria-label={`Revoke ${s.user.email}'s ${s.role} access`}
            >
              Revoke
            </button>
          )}
        </div>
      ))}

      {canShare(account) && (
        <form onSubmit={grant} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
          <input
            className="np-input"
            type="email"
            placeholder="user@email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            aria-label="Email of the user to grant access"
            style={{ maxWidth: 240 }}
          />
          <select
            className="np-input"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            aria-label="Role to grant"
            style={{ maxWidth: 140 }}
          >
            {SHAREABLE_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <button className="np-button" type="submit" disabled={busy || !email}>
            {busy ? 'Working…' : 'Grant access'}
          </button>
        </form>
      )}

      {!canShare(account) && (
        <div style={{ fontSize: 12, color: 'var(--np-muted)' }}>
          Your role ({account.my_role ?? 'unknown'}) can view but not delegate access — grants
          require the owner or an admin.
        </div>
      )}

      {msg && (
        <p role="status" style={{ margin: 0, fontSize: 12, color: 'var(--np-muted)' }}>
          {msg}
        </p>
      )}
    </div>
  );
}

/** M0 accounts surface: create test account + LIVE usage over WebSocket + access sharing. */
export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [usage, setUsage] = useState<Record<string, UsageSample>>({});
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
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
          const open = expanded === a.id;
          return (
            <div key={a.id} className="np-card">
              <div
                style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}
              >
                <div>
                  <strong>{a.username}</strong> <span className="np-badge">{a.status}</span>
                  {a.my_role && (
                    <span className="np-badge" style={{ marginLeft: 6 }}>
                      you: {a.my_role}
                    </span>
                  )}
                  <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                    uid {a.uid ?? '?'} · {a.homedir ?? ''}
                  </div>
                </div>
                <div
                  style={{
                    display: 'flex',
                    gap: 16,
                    fontSize: 12,
                    color: 'var(--np-muted)',
                    textAlign: 'right',
                    alignItems: 'center',
                  }}
                >
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
                  <button
                    className="np-button"
                    style={{ padding: '4px 12px', fontSize: 12 }}
                    onClick={() => setExpanded(open ? null : a.id)}
                    aria-expanded={open}
                    aria-controls={`sharing-${a.id}`}
                  >
                    {open ? 'Hide sharing' : 'Sharing'}
                  </button>
                </div>
              </div>
              {open && (
                <div id={`sharing-${a.id}`}>
                  <SharingPanel
                    account={a}
                    me={user ? { id: user.id, email: user.email } : null}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Shell>
  );
}
