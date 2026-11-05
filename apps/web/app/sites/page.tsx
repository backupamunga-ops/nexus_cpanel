'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Sites & domains console (API spec §4.7).
 *
 * The server owns the rules: FQDN validation, package PHP allowlists,
 * docroot confinement, redirect value allowlists (they are embedded into
 * nginx config — directive injection is rejected, not escaped). Errors are
 * shown verbatim. Provisioning is agent-first: a failed agent call leaves
 * no row, and the error surfaces here exactly as the server returned it.
 */

interface DomainDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  name: string;
  type: string;
  document_root: string;
  php_version: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface SubdomainDto {
  id: string;
  name: string;
  fqdn: string;
  document_root: string;
}

interface AliasDto {
  id: string;
  alias_name: string;
}

interface RedirectDto {
  id: string;
  source_path: string;
  destination_url: string;
  status_code: number;
  is_wildcard: boolean;
}

interface AccountOption {
  id: string;
  username: string;
}

const DOMAIN_TYPES = ['primary', 'addon', 'parked'];
const PHP_VERSIONS = ['8.1', '8.2', '8.3', '8.4'];

export default function SitesPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [domains, setDomains] = useState<DomainDto[]>([]);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [selected, setSelected] = useState<DomainDto | null>(null);
  const [subdomains, setSubdomains] = useState<SubdomainDto[]>([]);
  const [aliases, setAliases] = useState<AliasDto[]>([]);
  const [redirects, setRedirects] = useState<RedirectDto[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // create form state
  const [newName, setNewName] = useState('');
  const [newAccount, setNewAccount] = useState('');
  const [newType, setNewType] = useState('primary');
  const [newPhp, setNewPhp] = useState('');

  // detail form state
  const [subLabel, setSubLabel] = useState('');
  const [aliasName, setAliasName] = useState('');
  const [redSource, setRedSource] = useState('');
  const [redDest, setRedDest] = useState('');
  const [redCode, setRedCode] = useState('301');
  const [redWildcard, setRedWildcard] = useState(false);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const j = await api<{ data: DomainDto[] }>('/domains');
      setDomains(j.data ?? []);
      const a = await api<{ data: AccountOption[] }>('/accounts');
      setAccounts(a.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const loadDetail = useCallback(async (d: DomainDto) => {
    setSelected(d);
    setSubdomains([]);
    setAliases([]);
    setRedirects([]);
    try {
      const [s, a, r] = await Promise.all([
        api<{ data: SubdomainDto[] }>(`/domains/${d.id}/subdomains`),
        api<{ data: AliasDto[] }>(`/domains/${d.id}/aliases`),
        api<{ data: RedirectDto[] }>(`/domains/${d.id}/redirects`),
      ]);
      setSubdomains(s.data ?? []);
      setAliases(a.data ?? []);
      setRedirects(r.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load site detail');
    }
  }, []);

  async function createDomain(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<DomainDto>('/domains', {
        method: 'POST',
        body: JSON.stringify({
          name: newName.trim(),
          hosting_account_id: newAccount,
          type: newType,
          ...(newPhp ? { php_version: newPhp } : {}),
        }),
      });
      setMessage(`site “${created.name}” created — docroot provisioned, vhost applied.`);
      setNewName('');
      setNewPhp('');
      await refresh();
      await loadDetail(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'create failed');
    } finally {
      setBusy(false);
    }
  }

  async function mutate(fn: () => Promise<unknown>, ok: string) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await fn();
      setMessage(ok);
      await refresh();
      if (selected) {
        const fresh = await api<DomainDto>(`/domains/${selected.id}`);
        await loadDetail(fresh);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'operation failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/sites" user={user}>
      <h1 className="np-title">Sites</h1>
      <p className="np-subtitle">
        Domains, subdomains, aliases and redirects (§4.7). Every serving change is applied
        to the node first (staging write → atomic swap → health check → auto-rollback) and
        only then recorded — with a full config history per site.
      </p>

      {message && <p role="status" style={{ color: 'var(--np-muted)', marginTop: 12 }}>{message}</p>}
      {error && <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>{error}</p>}

      <form onSubmit={createDomain} className="np-card" style={{ marginTop: 20, maxWidth: 720 }}>
        <h2 style={{ marginTop: 0 }}>New site</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: 8 }}>
          <label style={{ fontSize: 13 }}>
            Domain (FQDN)
            <input
              className="np-input"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="example.com"
              required
              maxLength={253}
              style={{ marginTop: 2 }}
            />
          </label>
          <label style={{ fontSize: 13 }}>
            Hosting account
            <select
              className="np-input"
              value={newAccount}
              onChange={(e) => setNewAccount(e.target.value)}
              required
              style={{ marginTop: 2 }}
            >
              <option value="">— select —</option>
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>{a.username}</option>
              ))}
            </select>
          </label>
          <label style={{ fontSize: 13 }}>
            Type
            <select
              className="np-input"
              value={newType}
              onChange={(e) => setNewType(e.target.value)}
              style={{ marginTop: 2 }}
            >
              {DOMAIN_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </label>
          <label style={{ fontSize: 13 }}>
            PHP (optional)
            <select
              className="np-input"
              value={newPhp}
              onChange={(e) => setNewPhp(e.target.value)}
              style={{ marginTop: 2 }}
            >
              <option value="">none</option>
              {PHP_VERSIONS.map((v) => (
                <option key={v} value={v}>{v}</option>
              ))}
            </select>
          </label>
        </div>
        <button className="np-button" type="submit" disabled={busy} style={{ marginTop: 12 }}>
          {busy ? 'Working…' : 'Create site'}
        </button>
      </form>

      <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: '1fr 1.4fr', gap: 16 }}>
        {/* ── domain list ──────────────────────────────────────────── */}
        <div style={{ display: 'grid', gap: 10, alignContent: 'start' }}>
          {domains.length === 0 && <p style={{ color: 'var(--np-muted)' }}>No sites yet.</p>}
          {domains.map((d) => (
            <div
              key={d.id}
              className="np-card"
              style={{
                cursor: 'pointer',
                outline: selected?.id === d.id ? '2px solid #6366f1' : 'none',
              }}
              onClick={() => void loadDetail(d)}
            >
              <strong>{d.name}</strong>{' '}
              {!d.is_active && <span className="np-badge">inactive</span>}
              {d.type !== 'primary' && <span className="np-badge">{d.type}</span>}
              <div style={{ color: 'var(--np-muted)', fontSize: 12, marginTop: 2 }}>
                account {d.account_username} · php {d.php_version ?? '—'}
              </div>
              <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>{d.document_root}</div>
            </div>
          ))}
        </div>

        {/* ── detail panel ─────────────────────────────────────────── */}
        <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
          {!selected && <p style={{ color: 'var(--np-muted)' }}>Select a site to manage it.</p>}
          {selected && (
            <>
              <div className="np-card">
                <h2 style={{ marginTop: 0 }}>{selected.name}</h2>
                <div style={{ color: 'var(--np-muted)', fontSize: 13 }}>
                  docroot {selected.document_root}
                  <br />
                  php {selected.php_version ?? '—'} · type {selected.type} ·{' '}
                  {selected.is_active ? 'active' : 'inactive'}
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                  <button
                    className="np-button"
                    disabled={busy || selected.is_active}
                    onClick={() =>
                      void mutate(
                        () => api(`/domains/${selected.id}`, { method: 'PATCH', body: JSON.stringify({ is_active: true }) }),
                        'site activated.',
                      )
                    }
                  >
                    Activate
                  </button>
                  <button
                    className="np-button"
                    disabled={busy || !selected.is_active}
                    onClick={() =>
                      void mutate(
                        () => api(`/domains/${selected.id}`, { method: 'PATCH', body: JSON.stringify({ is_active: false }) }),
                        'site deactivated.',
                      )
                    }
                  >
                    Deactivate
                  </button>
                  <button
                    className="np-button"
                    disabled={busy}
                    onClick={() => {
                      if (!window.confirm(`Delete site ${selected.name}? The vhost is removed from the node.`)) return;
                      void mutate(
                        () => api(`/domains/${selected.id}`, { method: 'DELETE' }),
                        'site deleted.',
                      ).then(() => setSelected(null));
                    }}
                  >
                    Delete site
                  </button>
                </div>
              </div>

              <div className="np-card">
                <h3 style={{ marginTop: 0 }}>Subdomains</h3>
                {subdomains.length === 0 && <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>None.</p>}
                {subdomains.map((s) => (
                  <div key={s.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 13 }}>
                      <strong>{s.fqdn}</strong> <span style={{ color: 'var(--np-muted)' }}>→ {s.document_root}</span>
                    </span>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() =>
                        void mutate(
                          () => api(`/domains/${selected.id}/subdomains/${s.id}`, { method: 'DELETE' }),
                          `subdomain ${s.fqdn} deleted.`,
                        )
                      }
                    >
                      Remove
                    </button>
                  </div>
                ))}
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <input
                    className="np-input"
                    value={subLabel}
                    onChange={(e) => setSubLabel(e.target.value)}
                    placeholder="blog  (→ blog.example.com)"
                    style={{ maxWidth: 260 }}
                    aria-label="New subdomain label"
                  />
                  <button
                    className="np-button"
                    disabled={busy || subLabel.trim() === ''}
                    onClick={() => {
                      const label = subLabel.trim();
                      void mutate(
                        () => api(`/domains/${selected.id}/subdomains`, { method: 'POST', body: JSON.stringify({ name: label }) }),
                        `subdomain created.`,
                      ).then(() => setSubLabel(''));
                    }}
                  >
                    Add subdomain
                  </button>
                </div>
              </div>

              <div className="np-card">
                <h3 style={{ marginTop: 0 }}>Aliases</h3>
                {aliases.length === 0 && <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>None.</p>}
                {aliases.map((a) => (
                  <div key={a.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 13 }}>{a.alias_name}</span>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() =>
                        void mutate(
                          () => api(`/domains/${selected.id}/aliases/${a.id}`, { method: 'DELETE' }),
                          `alias removed.`,
                        )
                      }
                    >
                      Remove
                    </button>
                  </div>
                ))}
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <input
                    className="np-input"
                    value={aliasName}
                    onChange={(e) => setAliasName(e.target.value)}
                    placeholder="mirror.example.org"
                    style={{ maxWidth: 260 }}
                    aria-label="New alias FQDN"
                  />
                  <button
                    className="np-button"
                    disabled={busy || aliasName.trim() === ''}
                    onClick={() => {
                      const alias = aliasName.trim();
                      void mutate(
                        () => api(`/domains/${selected.id}/aliases`, { method: 'POST', body: JSON.stringify({ alias_name: alias }) }),
                        `alias added — vhost re-applied.`,
                      ).then(() => setAliasName(''));
                    }}
                  >
                    Add alias
                  </button>
                </div>
              </div>

              <div className="np-card">
                <h3 style={{ marginTop: 0 }}>Redirects</h3>
                {redirects.length === 0 && <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>None.</p>}
                {redirects.map((r) => (
                  <div key={r.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 13 }}>
                      <code>{r.source_path}</code>{r.is_wildcard ? ' (wildcard)' : ''} → {r.status_code} {r.destination_url}
                    </span>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() =>
                        void mutate(
                          () => api(`/domains/${selected.id}/redirects/${r.id}`, { method: 'DELETE' }),
                          `redirect removed.`,
                        )
                      }
                    >
                      Remove
                    </button>
                  </div>
                ))}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr auto auto', gap: 8, marginTop: 8, alignItems: 'end' }}>
                  <label style={{ fontSize: 13 }}>
                    Path
                    <input
                      className="np-input"
                      value={redSource}
                      onChange={(e) => setRedSource(e.target.value)}
                      placeholder="/old-page"
                      style={{ marginTop: 2 }}
                      aria-label="Redirect source path"
                    />
                  </label>
                  <label style={{ fontSize: 13 }}>
                    Destination URL
                    <input
                      className="np-input"
                      value={redDest}
                      onChange={(e) => setRedDest(e.target.value)}
                      placeholder="https://example.net/new"
                      style={{ marginTop: 2 }}
                      aria-label="Redirect destination URL"
                    />
                  </label>
                  <label style={{ fontSize: 13 }}>
                    Code
                    <select
                      className="np-input"
                      value={redCode}
                      onChange={(e) => setRedCode(e.target.value)}
                      style={{ marginTop: 2 }}
                    >
                      {['301', '302', '307', '308'].map((c) => (
                        <option key={c} value={c}>{c}</option>
                      ))}
                    </select>
                  </label>
                  <label style={{ fontSize: 13, display: 'flex', gap: 4, alignItems: 'center' }}>
                    <input
                      type="checkbox"
                      checked={redWildcard}
                      onChange={(e) => setRedWildcard(e.target.checked)}
                    />
                    wildcard
                  </label>
                </div>
                <button
                  className="np-button"
                  disabled={busy || redSource.trim() === '' || redDest.trim() === ''}
                  style={{ marginTop: 8 }}
                  onClick={() => {
                    const body = {
                      source_path: redSource.trim(),
                      destination_url: redDest.trim(),
                      status_code: Number(redCode),
                      is_wildcard: redWildcard,
                    };
                    void mutate(
                      () => api(`/domains/${selected.id}/redirects`, { method: 'POST', body: JSON.stringify(body) }),
                      `redirect added — vhost re-applied.`,
                    ).then(() => {
                      setRedSource('');
                      setRedDest('');
                      setRedWildcard(false);
                    });
                  }}
                >
                  Add redirect
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </Shell>
  );
}
