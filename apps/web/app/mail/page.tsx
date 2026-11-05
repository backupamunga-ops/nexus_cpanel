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

interface DkimStateDto {
  mail_domain_id: string;
  domain: string;
  selector: string | null;
  rotated_at: string | null;
  created_at: string | null;
  dns_record_present: boolean;
  signing: boolean;
  signing_note: string | null;
}

interface DkimApplyResult extends DkimStateDto {
  dns_record: string;
}

interface QueueEntry {
  queue_id: string;
  size: number;
  arrival: string;
  sender: string;
  recipient?: string;
  reason?: string;
}

interface QueueResult {
  queue: QueueEntry[];
  total: number;
  source: string;
}

interface RelayDto {
  provider: string;
  smtp_host: string;
  smtp_port: number;
  username: string;
  has_credentials: boolean;
  is_active: boolean;
  updated_at: string;
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

  // B08 deliverability
  const [dkim, setDkim] = useState<DkimStateDto | null>(null);
  const [dkimRecord, setDkimRecord] = useState<string | null>(null);
  const [dmarcPolicy, setDmarcPolicy] = useState('quarantine');
  const [dmarcRua, setDmarcRua] = useState('');
  const [queue, setQueue] = useState<QueueResult | null>(null);
  const [relay, setRelay] = useState<RelayDto | null>(null);
  const [relayProvider, setRelayProvider] = useState('custom');
  const [relayHost, setRelayHost] = useState('');
  const [relayPort, setRelayPort] = useState('587');
  const [relayUser, setRelayUser] = useState('');
  const [relayPassword, setRelayPassword] = useState('');

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
    setDkim(null);
    setDkimRecord(null);
    try {
      const [b, a, r, k] = await Promise.all([
        api<{ data: MailboxDto[] }>(`/mail/domains/${d.id}/mailboxes`),
        api<{ data: MailAliasDto[] }>(`/mail/domains/${d.id}/aliases`),
        api<{ data: AutoresponderDto[] }>(`/mail/domains/${d.id}/autoresponders`),
        api<DkimStateDto>(`/mail/domains/${d.id}/dkim`),
      ]);
      setMailboxes(b.data ?? []);
      setAliases(a.data ?? []);
      setAutoresponders(r.data ?? []);
      setDkim(k);
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

  // ---- B08 deliverability ---------------------------------------------------

  async function enableDkim() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<DkimApplyResult>(`/mail/domains/${selected.id}/dkim`, { method: 'POST', body: JSON.stringify({}) });
      setDkim(out);
      setDkimRecord(out.dns_record);
      setMessage(
        out.signing
          ? `DKIM enabled (selector ${out.selector}) — key stored, DNS published, opendkim signing active.`
          : `DKIM key stored and DNS published (selector ${out.selector}), but signing is NOT active yet: ${out.signing_note}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'DKIM enable failed');
    } finally {
      setBusy(false);
    }
  }

  async function rotateDkim() {
    if (!selected) return;
    if (!window.confirm('Rotate the DKIM key? The old selector stays published until you remove its TXT record.')) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<DkimApplyResult>(`/mail/domains/${selected.id}/dkim/rotate`, { method: 'POST', body: JSON.stringify({}) });
      setDkim(out);
      setDkimRecord(out.dns_record);
      setMessage(`DKIM rotated to selector ${out.selector}. The old TXT record stays published — remove it after the transition window.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'DKIM rotation failed');
    } finally {
      setBusy(false);
    }
  }

  async function applySpf() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ domain: string; record: string }>(`/mail/domains/${selected.id}/spf`, { method: 'POST', body: JSON.stringify({}) });
      setMessage(`SPF published for ${out.domain}: "${out.record}"`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SPF apply failed');
    } finally {
      setBusy(false);
    }
  }

  async function applyDmarc(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ domain: string; record: string }>(`/mail/domains/${selected.id}/dmarc`, {
        method: 'POST',
        body: JSON.stringify({ policy: dmarcPolicy, rua: dmarcRua.trim() || undefined }),
      });
      setMessage(`DMARC published for ${out.domain}: "${out.record}"`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'DMARC apply failed');
    } finally {
      setBusy(false);
    }
  }

  async function loadQueue() {
    setBusy(true);
    setError(null);
    try {
      setQueue(await api<QueueResult>('/mail/queue'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'queue read failed — the node must have postqueue for an honest answer');
    } finally {
      setBusy(false);
    }
  }

  async function flushQueue(id?: string) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api('/mail/queue/flush', { method: 'POST', body: JSON.stringify(id ? { queue_id: id } : {}) });
      setMessage(id ? `Flush requested for ${id}.` : 'Flush requested for the whole queue.');
      await loadQueue();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'queue flush failed');
    } finally {
      setBusy(false);
    }
  }

  async function retryMessage(id: string) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/mail/queue/${id}/retry`, { method: 'POST' });
      setMessage(`${id} requeued.`);
      await loadQueue();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'requeue failed');
    } finally {
      setBusy(false);
    }
  }

  async function loadRelay() {
    setBusy(true);
    setError(null);
    try {
      const r = await api<RelayDto>('/mail/relay');
      setRelay(r);
      setRelayProvider(r.provider === 'none' ? 'custom' : r.provider);
      setRelayHost(r.smtp_host);
      setRelayPort(String(r.smtp_port));
      setRelayUser(r.username);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'relay profile read failed');
    } finally {
      setBusy(false);
    }
  }

  async function saveRelay(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<RelayDto>('/mail/relay', {
        method: 'PUT',
        body: JSON.stringify({
          provider: relayProvider,
          smtp_host: relayHost.trim(),
          smtp_port: Number(relayPort) || 587,
          username: relayUser.trim(),
          password: relayPassword,
        }),
      });
      setRelay(out);
      setRelayPassword('');
      setMessage(
        'Relay profile stored (credentials encrypted at rest). Honest note: the node transport wiring is NOT applied yet — delivery still follows the current relay configuration until the config-engine Postfix pipeline lands.',
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'relay save failed');
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

          <section className="np-card">
            <h2>Deliverability — {selected.name}</h2>
            {dkim ? (
              <>
                <p>
                  DKIM:{' '}
                  <span className={`np-badge ${dkim.signing ? 'ok' : ''}`}>
                    {dkim.signing ? 'signing active' : dkim.selector ? 'stored — not signing' : 'not enabled'}
                  </span>{' '}
                  {dkim.selector && <>selector <code>{dkim.selector}</code>{dkim.rotated_at && <> (rotated {new Date(dkim.rotated_at).toLocaleString()})</>}</>}
                </p>
                {dkim.signing_note && <p className="np-muted">{dkim.signing_note}</p>}
              </>
            ) : (
              <p className="np-muted">DKIM state loads with the domain.</p>
            )}
            <button className="np-button" disabled={busy} onClick={() => void enableDkim()}>
              Enable DKIM (mint key + publish DNS)
            </button>{' '}
            {dkim?.selector && (
              <button className="np-button" disabled={busy} onClick={() => void rotateDkim()}>
                Rotate key
              </button>
            )}
            {dkimRecord && <pre className="np-pre">{dkimRecord}</pre>}

            <h3>SPF</h3>
            <p className="np-muted">
              Publishes <code>v=spf1 mx a ~all</code> at the zone apex (idempotent — replaces an
              earlier panel-written SPF record). Custom records can be set via the API.
            </p>
            <button className="np-button" disabled={busy} onClick={() => void applySpf()}>
              Publish SPF record
            </button>

            <h3>DMARC</h3>
            <form onSubmit={applyDmarc} className="np-form">
              <label>
                Policy
                <select value={dmarcPolicy} onChange={(e) => setDmarcPolicy(e.target.value)}>
                  <option value="none">none — monitor only</option>
                  <option value="quarantine">quarantine — receivers may junk failures</option>
                  <option value="reject">reject — receivers drop failures</option>
                </select>
              </label>
              <label>
                Reports to (rua, optional)
                <input value={dmarcRua} onChange={(e) => setDmarcRua(e.target.value)} placeholder="dmarc-reports@example.com" />
              </label>
              <button className="np-button" disabled={busy}>
                Publish DMARC record
              </button>
            </form>
            <p className="np-muted">
              DKIM/SPF/DMARC writes go through the panel&apos;s DNS module — they require a managed
              zone for this domain (create it on the DNS page first). Without one, the endpoints
              return the record for manual publishing instead of pretending it was done.
            </p>
          </section>
        </>
      )}

      <section className="np-card">
        <h2>Mail queue (server-wide)</h2>
        <button className="np-button" disabled={busy} onClick={() => void loadQueue()}>
          Read queue
        </button>{' '}
        <button className="np-button" disabled={busy || !queue} onClick={() => void flushQueue()}>
          Flush all
        </button>
        {queue ? (
          queue.total === 0 ? (
            <p className="np-empty">Queue is empty ({queue.source}).</p>
          ) : (
            <table className="np-table">
              <thead>
                <tr>
                  <th>Queue ID</th>
                  <th>Size</th>
                  <th>Arrived</th>
                  <th>Sender → Recipient</th>
                  <th>Reason</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {queue.queue.map((q) => (
                  <tr key={q.queue_id}>
                    <td className="np-mono">{q.queue_id}</td>
                    <td>{q.size}</td>
                    <td>{q.arrival}</td>
                    <td>
                      {q.sender} → {q.recipient ?? '—'}
                    </td>
                    <td className="np-muted">{q.reason ?? '—'}</td>
                    <td>
                      <button className="np-button" disabled={busy} onClick={() => void flushQueue(q.queue_id)}>
                        Flush
                      </button>{' '}
                      <button className="np-button" disabled={busy} onClick={() => void retryMessage(q.queue_id)}>
                        Requeue
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : (
          <p className="np-muted">Queue state comes straight from postqueue — nothing cached, nothing assumed.</p>
        )}
      </section>

      <section className="np-card">
        <h2>SMTP relay (server-wide)</h2>
        {relay ? (
          <p>
            Current: <span className={`np-badge ${relay.is_active ? 'ok' : ''}`}>{relay.is_active ? 'profile active' : 'not configured'}</span>{' '}
            {relay.provider !== 'none' && (
              <>
                {relay.provider} via {relay.smtp_host}:{relay.smtp_port} as {relay.username || '—'}{' '}
                ({relay.has_credentials ? 'credentials stored encrypted' : 'no credentials stored'})
              </>
            )}
          </p>
        ) : (
          <p className="np-muted">Relay profile loads on demand.</p>
        )}
        <button className="np-button" disabled={busy} onClick={() => void loadRelay()}>
          Load relay profile
        </button>
        <form onSubmit={saveRelay} className="np-form">
          <h3>Configure</h3>
          <label>
            Provider
            <select value={relayProvider} onChange={(e) => setRelayProvider(e.target.value)}>
              <option value="ses">Amazon SES</option>
              <option value="mailgun">Mailgun</option>
              <option value="postmark">Postmark</option>
              <option value="custom">Custom SMTP</option>
            </select>
          </label>
          <label>
            SMTP host
            <input value={relayHost} onChange={(e) => setRelayHost(e.target.value)} placeholder="smtp.provider.example" required />
          </label>
          <label>
            Port
            <input value={relayPort} onChange={(e) => setRelayPort(e.target.value)} />
          </label>
          <label>
            Username
            <input value={relayUser} onChange={(e) => setRelayUser(e.target.value)} />
          </label>
          <label>
            Password (leave blank to keep stored credentials)
            <input type="password" value={relayPassword} onChange={(e) => setRelayPassword(e.target.value)} />
          </label>
          <button className="np-button" disabled={busy || !relayHost.trim()}>
            Save relay profile
          </button>
        </form>
        <p className="np-muted">
          Per ADR-0002 this is the server-wide relay — the delivery default for every account.
          The profile is stored with AES-256-GCM encryption (ADR-0009); the Postfix transport
          wiring lands with the config-engine pipeline and the badge above stays honest until then.
          Per-account overrides ship in v1.2.
        </p>
      </section>
    </Shell>
  );
}
