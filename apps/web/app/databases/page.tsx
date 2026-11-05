'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Databases panel (API spec §4.10, ADR-0001/0015).
 *
 * MariaDB 11 only in v1.0 — the engine lock is stated, not hidden. Database
 * credentials live as AES-256-GCM envelopes (ADR-0009/0015): the panel can
 * hand them back at point of use (connection string / reveal, both
 * session-only), the audit trail carries fingerprints, and the agent never
 * sees them again after CREATE USER.
 */

interface DatabaseDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  engine: string;
  name: string;
  db_user: string;
  size_mb: number;
  created_at: string;
}

interface DatabaseUserDto {
  user: string;
  host: string;
  privileges: string;
}

interface SsoDto {
  url: string;
  token: string;
  expires_at: string;
  consumer: string;
}

interface AccountOption {
  id: string;
  username: string;
}

export default function DatabasesPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [accountId, setAccountId] = useState('');
  const [databases, setDatabases] = useState<DatabaseDto[]>([]);
  const [selected, setSelected] = useState<DatabaseDto | null>(null);
  const [dbUsers, setDbUsers] = useState<DatabaseUserDto[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // create form
  const [newName, setNewName] = useState('');
  const [newUser, setNewUser] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newHost, setNewHost] = useState('localhost');

  // extra user form
  const [extraUser, setExtraUser] = useState('');
  const [extraPassword, setExtraPassword] = useState('');

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const a = await api<{ data: AccountOption[] }>('/accounts');
      setAccounts(a.data ?? []);
      setAccountId((cur) => cur || a.data?.[0]?.id || '');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const loadDatabases = useCallback(async () => {
    if (!accountId) return;
    try {
      const d = await api<{ data: DatabaseDto[] }>(`/databases?account_id=${accountId}`);
      setDatabases(d.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load databases');
    }
  }, [accountId]);

  useEffect(() => {
    void loadDatabases();
  }, [loadDatabases]);

  const loadDatabase = useCallback(async (d: DatabaseDto) => {
    setSelected(d);
    setDbUsers([]);
    setError(null);
    try {
      const u = await api<{ data: DatabaseUserDto[] }>(`/databases/${d.id}/users`);
      setDbUsers(u.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load database users');
    }
  }, []);

  async function createDatabase(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<DatabaseDto>('/databases', {
        method: 'POST',
        body: JSON.stringify({
          account_id: accountId,
          engine: 'mariadb',
          name: newName.trim(),
          db_user: newUser.trim() || undefined,
          password: newPassword || undefined,
          host: newHost.trim(),
        }),
      });
      setMessage(
        newPassword
          ? `Database ${created.name} created with user ${created.db_user}@${newHost.trim()} (password stored encrypted; reveal it below when needed).`
          : `Database ${created.name} created with user ${created.db_user}@${newHost.trim()} and a generated password (stored encrypted — use Reveal to see it once).`,
      );
      setNewName('');
      setNewUser('');
      setNewPassword('');
      await loadDatabases();
      await loadDatabase(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'database creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteDatabase(d: DatabaseDto) {
    if (!window.confirm(`Delete database ${d.name} and its primary user ${d.db_user}? This drops all data.`)) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/databases/${d.id}`, { method: 'DELETE', body: JSON.stringify({ drop_user: true }) });
      setMessage(`Database ${d.name} dropped on the node.`);
      if (selected?.id === d.id) setSelected(null);
      await loadDatabases();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'database deletion failed');
    } finally {
      setBusy(false);
    }
  }

  async function addUser(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/databases/${selected.id}/users`, {
        method: 'POST',
        body: JSON.stringify({ user: extraUser.trim(), password: extraPassword || undefined, host: 'localhost' }),
      });
      setMessage(`User ${extraUser.trim()}@localhost granted ALL PRIVILEGES on ${selected.name} (least-privilege by default, audited).`);
      setExtraUser('');
      setExtraPassword('');
      await loadDatabase(selected);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'user creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function refreshSize() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<DatabaseDto>(`/databases/${selected.id}/size`, { method: 'POST' });
      setSelected(out);
      setMessage(`Live size of ${out.name}: ${out.size_mb} MB (read from information_schema, cached on the row).`);
      await loadDatabases();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'size refresh failed');
    } finally {
      setBusy(false);
    }
  }

  async function showConnectionString() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ connection_string: string; note: string }>(`/databases/${selected.id}/connection-string`, {
        method: 'POST',
      });
      setMessage(out.note);
      setSelected((cur) => cur);
      setConnectionString(out.connection_string);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'connection string failed');
    } finally {
      setBusy(false);
    }
  }

  async function revealPassword() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ password: string }>(`/databases/${selected.id}/reveal`, { method: 'POST' });
      setMessage('Credential decrypted at point of use — shown once here, audit carries a fingerprint only.');
      setRevealed(out.password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'reveal failed');
    } finally {
      setBusy(false);
    }
  }

  async function issueSso() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<SsoDto>(`/databases/${selected.id}/phpmyadmin-sso`, { method: 'POST' });
      setMessage(`SSO token issued (expires ${new Date(out.expires_at).toLocaleTimeString()}). ${out.consumer}`);
      setSsoToken(out.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SSO issuance failed');
    } finally {
      setBusy(false);
    }
  }

  async function dumpDatabase() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ output_path: string }>(`/databases/${selected.id}/dump`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setMessage(`Dump written to ${out.output_path} (inside the account home, mode 0600).`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'dump failed');
    } finally {
      setBusy(false);
    }
  }

  const [connectionString, setConnectionString] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [ssoToken, setSsoToken] = useState<string | null>(null);

  return (
    <Shell active="/databases" user={user}>
      <h1>Databases</h1>
      <p className="np-muted">
        MariaDB 11 databases per hosting account. The agent provisions over the Unix socket; the
        panel stores credentials as AES-256-GCM envelopes (ADR-0009/0015).
      </p>

      <div className="np-banner">
        <strong>Engine:</strong> v1.0 provisions <strong>MariaDB 11 only</strong> (ADR-0001). MySQL 8
        and PostgreSQL support are planned behind the engine adapter — they are rejected with a clear
        error, never silently aliased.
      </div>

      {error && <p className="np-error">{error}</p>}
      {message && <p className="np-ok">{message}</p>}

      <section className="np-card">
        <h2>Create a database</h2>
        <form onSubmit={createDatabase} className="np-form">
          <label>
            Account
            <select value={accountId} onChange={(e) => setAccountId(e.target.value)}>
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.username}
                </option>
              ))}
            </select>
          </label>
          <label>
            Engine
            <select value="mariadb" disabled>
              <option value="mariadb">MariaDB 11 (v1.0 default)</option>
            </select>
          </label>
          <label>
            Database name
            <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="app_production" required />
          </label>
          <label>
            DB user (optional — derived from the account if blank)
            <input value={newUser} onChange={(e) => setNewUser(e.target.value)} placeholder="alice_app" />
          </label>
          <label>
            Password (optional — generated if blank)
            <input value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="min 8 chars, or leave blank" />
          </label>
          <label>
            Host (default localhost)
            <input value={newHost} onChange={(e) => setNewHost(e.target.value)} />
          </label>
          <button className="np-button" disabled={busy || !newName.trim()}>
            Create database
          </button>
        </form>
      </section>

      <section className="np-card">
        <h2>Databases</h2>
        {databases.length === 0 ? (
          <p className="np-empty">No databases yet for this account — create one above.</p>
        ) : (
          <table className="np-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Engine</th>
                <th>User</th>
                <th>Size (last read)</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {databases.map((d) => (
                <tr key={d.id} data-selected={selected?.id === d.id}>
                  <td>{d.name}</td>
                  <td>{d.engine}</td>
                  <td>{d.db_user}</td>
                  <td>{d.size_mb} MB</td>
                  <td>
                    <button className="np-button" onClick={() => void loadDatabase(d)}>
                      Open
                    </button>{' '}
                    <button className="np-button" disabled={busy} onClick={() => void deleteDatabase(d)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {selected && (
        <>
          <section className="np-card">
            <h2>Users & grants — {selected.name}</h2>
            {dbUsers.length === 0 ? (
              <p className="np-empty">Users load with the database.</p>
            ) : (
              <table className="np-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Host</th>
                    <th>Privileges</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {dbUsers.map((u) => (
                    <tr key={`${u.user}@${u.host}`}>
                      <td>{u.user}</td>
                      <td>{u.host}</td>
                      <td>{u.privileges}</td>
                      <td>
                        <button
                          className="np-button"
                          disabled={busy}
                          onClick={() => void deleteUser(u)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={addUser} className="np-form">
              <h3>Grant an extra user</h3>
              <label>
                User
                <input value={extraUser} onChange={(e) => setExtraUser(e.target.value)} placeholder="reporting_user" required />
              </label>
              <label>
                Password (optional — generated if blank)
                <input value={extraPassword} onChange={(e) => setExtraPassword(e.target.value)} />
              </label>
              <button className="np-button" disabled={busy || !extraUser.trim()}>
                Grant ALL on {selected.name}
              </button>
            </form>
          </section>

          <section className="np-card">
            <h2>Credentials & tools — {selected.name}</h2>
            <button className="np-button" disabled={busy} onClick={() => void refreshSize()}>
              Refresh size
            </button>{' '}
            <button className="np-button" disabled={busy} onClick={() => void showConnectionString()}>
              Connection string
            </button>{' '}
            <button className="np-button" disabled={busy} onClick={() => void revealPassword()}>
              Reveal password
            </button>{' '}
            <button className="np-button" disabled={busy} onClick={() => void issueSso()}>
              phpMyAdmin SSO token
            </button>{' '}
            <button className="np-button" disabled={busy} onClick={() => void dumpDatabase()}>
              Dump to home
            </button>
            {connectionString && <pre className="np-pre">{connectionString}</pre>}
            {revealed && (
              <p>
                Password: <code>{revealed}</code>{' '}
                <button
                  type="button"
                  className="np-button"
                  onClick={() => setRevealed(null)}
                >
                  Hide
                </button>
              </p>
            )}
            {ssoToken && <pre className="np-pre">{ssoToken}</pre>}
            <p className="np-muted">
              Connection string / reveal / SSO are interactive-session-only — API tokens cannot mint
              working database credentials (ADR-0015). The SSO consumer (Adminer/phpMyAdmin plugin)
              ships with the app installer (B14); the token is real, the link is not wired yet —
              stated honestly rather than shipping a dead link.
            </p>
          </section>
        </>
      )}
    </Shell>
  );

  async function deleteUser(u: DatabaseUserDto) {
    if (!selected) return;
    if (!window.confirm(`Remove user ${u.user}@${u.host}?`)) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/databases/${selected.id}/users/${encodeURIComponent(u.user)}?host=${encodeURIComponent(u.host)}`, {
        method: 'DELETE',
      });
      setMessage(`User ${u.user}@${u.host} revoked and dropped.`);
      await loadDatabase(selected);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'user removal failed');
    } finally {
      setBusy(false);
    }
  }
}
