'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Email panel (API spec §4.8, ADR-0013).
 *
 * Every state shown here is real: mailboxes/aliases/autoresponders come from
 * the panel registry that the agent mirrors onto the node. The relay banner
 * states the constitutional default (ADR-0002) — outbound mail hands off to
 * the server-wide SMTP relay, and a self-hosted MTA is an explicit opt-in
 * whose wizard lands with B08.
 */

interface MailDomainDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  name: string;
  is_active: boolean;
  mailbox_count: number;
  created_at: string;
}

interface MailboxDto {
  id: string;
  mail_domain_id: string;
  address: string;
  quota_mb: number;
  used_mb: number;
  is_active: boolean;
  created_at: string;
}

interface MailAliasDto {
  id: string;
  source_address: string;
  destination_address: string;
  is_catchall: boolean;
}

interface AutoresponderDto {
  id: string;
  mailbox_id: string;
  address: string;
  subject: string;
  starts_at: string | null;
  ends_at: string | null;
  schedule_state: 'active' | 'scheduled' | 'expired';
}

interface AccountOption {
  id: string;
  username: string;
}

export default function MailPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [accountId, setAccountId] = useState('');
  const [domains, setDomains] = useState<MailDomainDto[]>([]);
  const [selected, setSelected] = useState<MailDomainDto | null>(null);
  const [mailboxes, setMailboxes] = useState<MailboxDto[]>([]);
  const [aliases, setAliases] = useState<MailAliasDto[]>([]);
  const [autoresponders, setAutoresponders] = useState<AutoresponderDto[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // create forms
  const [newDomain, setNewDomain] = useState('');
  const [boxLocal, setBoxLocal] = useState('');
  const [boxPassword, setBoxPassword] = useState('');
  const [boxQuota, setBoxQuota] = useState('1024');
  const [aliasSource, setAliasSource] = useState('');
  const [aliasDest, setAliasDest] = useState('');
  const [arMailbox, setArMailbox] = useState('');
  const [arSubject, setArSubject] = useState('');
  const [arBody, setArBody] = useState('');

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

  const loadDomains = useCallback(async () => {
    if (!accountId) return;
    try {
      const d = await api<{ data: MailDomainDto[] }>(`/mail/domains?account_id=${accountId}`);
      setDomains(d.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load mail domains');
    }
  }, [accountId]);

  useEffect(() => {
    void loadDomains();
  }, [loadDomains]);

  const loadDomain = useCallback(async (d: MailDomainDto) => {
    setSelected(d);
    setError(null);
    setMailboxes([]);
    setAliases([]);
    setAutoresponders([]);
    try {
      const [b, a, r] = await Promise.all([
        api<{ data: MailboxDto[] }>(`/mail/domains/${d.id}/mailboxes`),
        api<{ data: MailAliasDto[] }>(`/mail/domains/${d.id}/aliases`),
        api<{ data: AutoresponderDto[] }>(`/mail/domains/${d.id}/autoresponders`),
      ]);
      setMailboxes(b.data ?? []);
      setAliases(a.data ?? []);
      setAutoresponders(r.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load mail domain detail');
    }
  }, []);

  async function createDomain(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<MailDomainDto>('/mail/domains', {
        method: 'POST',
        body: JSON.stringify({ account_id: accountId, name: newDomain.trim() }),
      });
      setMessage(`Mail domain ${created.name} registered on the node (postfix virtual domain map updated).`);
      setNewDomain('');
      await loadDomains();
      await loadDomain(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'mail domain creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteMailDomain(d: MailDomainDto) {
    if (!window.confirm(`Delete mail domain ${d.name}? It must have no mailboxes or aliases.`)) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/mail/domains/${d.id}`, { method: 'DELETE' });
      setMessage(`Mail domain ${d.name} removed from the node.`);
      if (selected?.id === d.id) setSelected(null);
      await loadDomains();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'mail domain deletion failed');
    } finally {
      setBusy(false);
    }
  }

  async function createMailbox(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<MailboxDto>(`/mail/domains/${selected.id}/mailboxes`, {
        method: 'POST',
        body: JSON.stringify({ local_part: boxLocal.trim(), password: boxPassword, quota_mb: Number(boxQuota) || 1024 }),
      });
      setMessage(
        `Mailbox ${created.address} created (${created.quota_mb} MB). The password is stored hashed (SSHA512) — Dovecot verifies it against the panel DB.`,
      );
      setBoxLocal('');
      setBoxPassword('');
      await loadDomain(selected);
      await loadDomains();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'mailbox creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function rotatePassword(box: MailboxDto) {
    if (!selected) return;
    const next = window.prompt(`New password for ${box.address} (min 8 chars)`);
    if (!next) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/mail/domains/${selected.id}/mailboxes/${box.id}/password`, {
        method: 'POST',
        body: JSON.stringify({ password: next }),
      });
      setMessage(`Password rotated for ${box.address} — stored hashed in the panel DB; Dovecot picks it up on next login.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'password rotation failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteMailbox(box: MailboxDto) {
    if (!selected) return;
    if (!window.confirm(`Delete ${box.address}? The maildir is removed from the node.`)) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/mail/domains/${selected.id}/mailboxes/${box.id}`, {
        method: 'DELETE',
        body: JSON.stringify({ preserve_mail: false }),
      });
      setMessage(`Mailbox ${box.address} deleted.`);
      await loadDomain(selected);
      await loadDomains();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'mailbox deletion failed');
    } finally {
      setBusy(false);
    }
  }

  async function createAlias(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<MailAliasDto>(`/mail/domains/${selected.id}/aliases`, {
        method: 'POST',
        body: JSON.stringify({ source: aliasSource.trim(), destination: aliasDest.trim() }),
      });
      setMessage(`Alias ${created.source_address} → ${created.destination_address} applied on the node.`);
      setAliasSource('');
      setAliasDest('');
      await loadDomain(selected);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'alias creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteAlias(a: MailAliasDto) {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/mail/domains/${selected.id}/aliases/${a.id}`, { method: 'DELETE' });
      setMessage(`Alias ${a.source_address} removed.`);
      await loadDomain(selected);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'alias removal failed');
    } finally {
      setBusy(false);
    }
  }

  async function createResponder(e: FormEvent) {
    e.preventDefault();
    if (!selected || !arMailbox) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/mail/domains/${selected.id}/autoresponders`, {
        method: 'POST',
        body: JSON.stringify({ mailbox_id: arMailbox, subject: arSubject.trim(), body: arBody }),
      });
      setMessage('Autoresponder saved — the Sieve vacation script is live on the node.');
      setArSubject('');
      setArBody('');
      await loadDomain(selected);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'autoresponder creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteResponder(r: AutoresponderDto) {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/mail/domains/${selected.id}/autoresponders/${r.id}`, { method: 'DELETE' });
      setMessage(`Autoresponder for ${r.address} removed from the node.`);
      await loadDomain(selected);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'autoresponder removal failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/mail" user={user}>
      <h1>Email</h1>
      <p className="np-muted">
        Mailboxes, aliases and autoresponders per mail domain. Dovecot authenticates against
        the panel database; the agent provisions the node-side files.
      </p>

      <div className="np-banner">
        <strong>Delivery default:</strong> outbound mail from your applications hands off to the
        server-wide SMTP relay (ADR-0002). A self-hosted MTA receiving mail for these domains is an
        explicit opt-in — the deliverability wizard (DKIM / SPF / DMARC) lands in the next batch and
        is marked as it becomes real. Nothing on this page claims routing that is not configured.
      </div>

      {error && <p className="np-error">{error}</p>}
      {message && <p className="np-ok">{message}</p>}

      <section className="np-card">
        <h2>Add a mail domain</h2>
        <form onSubmit={createDomain} className="np-form">
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
            Domain
            <input value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="example.com" required />
          </label>
          <button className="np-button" disabled={busy || !newDomain.trim()}>
            Register mail domain
          </button>
        </form>
      </section>

      <section className="np-card">
        <h2>Mail domains</h2>
        {domains.length === 0 ? (
          <p className="np-empty">No mail domains yet — register one above.</p>
        ) : (
          <table className="np-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Mailboxes</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {domains.map((d) => (
                <tr key={d.id} data-selected={selected?.id === d.id}>
                  <td>{d.name}</td>
                  <td>{d.mailbox_count}</td>
                  <td>
                    <button className="np-button" onClick={() => void loadDomain(d)}>
                      Open
                    </button>{' '}
                    <button className="np-button" disabled={busy} onClick={() => void deleteMailDomain(d)}>
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
            <h2>Mailboxes — {selected.name}</h2>
            {mailboxes.length === 0 ? (
              <p className="np-empty">No mailboxes on this domain yet — add the first one below.</p>
            ) : (
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Address</th>
                    <th>Quota</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {mailboxes.map((b) => (
                    <tr key={b.id}>
                      <td>{b.address}</td>
                      <td>
                        <div className="np-quotabar">
                          <div
                            className="np-quotabar-fill"
                            style={{ width: `${Math.min(100, Math.round((b.used_mb / Math.max(1, b.quota_mb)) * 100))}%` }}
                          />
                        </div>
                        <span className="np-muted">
                          {' '}
                          {b.used_mb} / {b.quota_mb} MB
                        </span>
                      </td>
                      <td>
                        <button className="np-button" disabled={busy} onClick={() => void rotatePassword(b)}>
                          Set password
                        </button>{' '}
                        <button className="np-button" disabled={busy} onClick={() => void deleteMailbox(b)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={createMailbox} className="np-form">
              <h3>Add a mailbox</h3>
              <label>
                Address (local part on {selected.name})
                <input value={boxLocal} onChange={(e) => setBoxLocal(e.target.value)} placeholder="hello" required />
              </label>
              <label>
                Password
                <input
                  type="password"
                  value={boxPassword}
                  onChange={(e) => setBoxPassword(e.target.value)}
                  placeholder="min 8 chars — hashed SSHA512, never stored in clear"
                  required
                />
              </label>
              <label>
                Quota (MB)
                <input value={boxQuota} onChange={(e) => setBoxQuota(e.target.value)} />
              </label>
              <button className="np-button" disabled={busy || !boxLocal.trim() || !boxPassword}>
                Create mailbox
              </button>
            </form>
          </section>

          <section className="np-card">
            <h2>Aliases — {selected.name}</h2>
            {aliases.length === 0 ? (
              <p className="np-empty">No aliases on this domain yet.</p>
            ) : (
              <table className="np-table">
                <thead>
                  <tr>
                    <th>From</th>
                    <th>To</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {aliases.map((a) => (
                    <tr key={a.id}>
                      <td>
                        {a.source_address} {a.is_catchall && <span className="np-badge">catch-all</span>}
                      </td>
                      <td>{a.destination_address}</td>
                      <td>
                        <button className="np-button" disabled={busy} onClick={() => void deleteAlias(a)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={createAlias} className="np-form">
              <h3>Add an alias</h3>
              <label>
                Source (local part, or @{selected.name} for a catch-all)
                <input value={aliasSource} onChange={(e) => setAliasSource(e.target.value)} placeholder="info" required />
              </label>
              <label>
                Destination (full address)
                <input value={aliasDest} onChange={(e) => setAliasDest(e.target.value)} placeholder="hello@example.com" required />
              </label>
              <button className="np-button" disabled={busy || !aliasSource.trim() || !aliasDest.trim()}>
                Add alias
              </button>
            </form>
          </section>

          <section className="np-card">
            <h2>Autoresponders — {selected.name}</h2>
            {autoresponders.length === 0 ? (
              <p className="np-empty">No autoresponders on this domain.</p>
            ) : (
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Address</th>
                    <th>Subject</th>
                    <th>Schedule</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {autoresponders.map((r) => (
                    <tr key={r.id}>
                      <td>{r.address}</td>
                      <td>{r.subject}</td>
                      <td>
                        <span className={`np-badge ${r.schedule_state === 'active' ? 'ok' : ''}`}>
                          {r.schedule_state}
                        </span>
                      </td>
                      <td>
                        <button className="np-button" disabled={busy} onClick={() => void deleteResponder(r)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={createResponder} className="np-form">
              <h3>Add an autoresponder</h3>
              <label>
                Mailbox
                <select value={arMailbox} onChange={(e) => setArMailbox(e.target.value)}>
                  <option value="">— pick a mailbox —</option>
                  {mailboxes.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.address}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Subject
                <input value={arSubject} onChange={(e) => setArSubject(e.target.value)} placeholder="Out of office" required />
              </label>
              <label>
                Message
                <textarea value={arBody} onChange={(e) => setArBody(e.target.value)} rows={4} required />
              </label>
              <button className="np-button" disabled={busy || !arMailbox || !arSubject.trim() || !arBody.trim()}>
                Save autoresponder
              </button>
            </form>
            <p className="np-muted">
              Scheduled windows (starts/ends) are stored and shown honestly as &quot;scheduled&quot; or
              &quot;expired&quot;; flipping the Sieve file at window edges arrives with the job
              framework (B13).
            </p>
          </section>
        </>
      )}
    </Shell>
  );
}
