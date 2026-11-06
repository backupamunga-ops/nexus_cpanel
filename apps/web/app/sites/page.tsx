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

interface ServingStatus {
  installed: boolean;
  healthy: boolean;
  detail: string | null;
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

interface SslCertDto {
  id: string;
  domain_name: string;
  issuer: string;
  common_name: string;
  san_names: string[];
  expires_at: string;
  last_renewed_at: string | null;
  auto_renew: boolean;
}

interface ConfigVersion {
  id: string;
  version: number;
  is_active: boolean;
  size_bytes: number;
  created_at: string;
}

interface DriftEvent {
  id: string;
  target_type: string;
  target_id: string;
  detected_at: string;
  resolved_at: string | null;
}

interface PhpView {
  domain_id: string;
  php_version: string | null;
  pool: { version: string; config: Record<string, unknown>; conf_content: string } | null;
  offered_by_package: string[];
}

interface DomainLogDto {
  domain_id: string;
  kind: 'access' | 'error';
  file: string;
  exists: boolean;
  file_size_bytes: number;
  file_truncated: boolean;
  total_lines: number;
  lines: string[];
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
  const [cert, setCert] = useState<SslCertDto | null>(null);
  const [acmeEmail, setAcmeEmail] = useState('');
  const [php, setPhp] = useState<PhpView | null>(null);
  const [phpVersion, setPhpVersion] = useState('');
  const [phpMaxChildren, setPhpMaxChildren] = useState('10');
  const [phpMemory, setPhpMemory] = useState('128M');
  const [phpUpload, setPhpUpload] = useState('32M');
  const [phpMaxExec, setPhpMaxExec] = useState('30');
  const [versions, setVersions] = useState<ConfigVersion[]>([]);
  const [drift, setDrift] = useState<DriftEvent[]>([]);
  const [logKind, setLogKind] = useState<'access' | 'error'>('access');
  const [logTail, setLogTail] = useState('200');
  const [log, setLog] = useState<DomainLogDto | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [serving, setServing] = useState<ServingStatus | null>(null);

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

  // Serving posture banner (best-effort): a fresh node has no nginx yet —
  // sites still record fine, they just don't serve until it is installed.
  useEffect(() => {
    api<ServingStatus>('/domains/serving-status')
      .then(setServing)
      .catch(() => setServing(null));
  }, []);

  const loadLogs = useCallback(async () => {
    if (!selected) return;
    try {
      const j = await api<DomainLogDto>(`/domains/${selected.id}/logs?type=${logKind}&lines=${logTail}`);
      setLog(j);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load logs');
    }
  }, [selected, logKind, logTail]);

  useEffect(() => {
    if (selected) void loadLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id, logKind, logTail]);

  const loadDetail = useCallback(async (d: DomainDto) => {
    setSelected(d);
    setSubdomains([]);
    setAliases([]);
    setRedirects([]);
    setCert(null);
    setLog(null);
    try {
      const [s, a, r, ssl] = await Promise.all([
        api<{ data: SubdomainDto[] }>(`/domains/${d.id}/subdomains`),
        api<{ data: AliasDto[] }>(`/domains/${d.id}/aliases`),
        api<{ data: RedirectDto[] }>(`/domains/${d.id}/redirects`),
        api<{ certificate: SslCertDto | null }>(`/domains/${d.id}/ssl`),
      ]);
      setSubdomains(s.data ?? []);
      setAliases(a.data ?? []);
      setRedirects(r.data ?? []);
      setCert(ssl.certificate ?? null);
      const pv = await api<PhpView>(`/domains/${d.id}/php`);
      setPhp(pv);
      setPhpVersion(pv.php_version ?? '');
      const cfg = pv.pool?.config ?? {};
      setPhpMaxChildren(String((cfg['pm.max_children'] as number) ?? 10));
      setPhpMemory((cfg['memory_limit'] as string) ?? '128M');
      setPhpUpload((cfg['upload_max_filesize'] as string) ?? '32M');
      setPhpMaxExec(String((cfg['max_execution_time'] as number) ?? 30));
      const cv = await api<{ data: ConfigVersion[] }>(`/config/nginx_vhost/${d.id}/versions`);
      setVersions(cv.data ?? []);
      const dv = await api<{ data: DriftEvent[] }>('/config/drift');
      setDrift((dv.data ?? []).filter((e) => e.target_id === d.id));
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

      {serving && !serving.installed && (
        <p
          role="status"
          style={{
            marginTop: 12,
            padding: '10px 14px',
            border: '1px solid var(--np-border)',
            borderLeft: '3px solid var(--np-warning)',
            background: 'var(--np-warning-soft)',
            borderRadius: 8,
            fontSize: 14,
          }}
        >
          The web server (nginx) is not installed on this machine yet. Sites you create here
          are saved safely and start serving automatically once nginx is installed on the
          server — you do not need to create them again. As root on the server:{' '}
          <code>apt install nginx</code>.
        </p>
      )}
      {serving && serving.installed && !serving.healthy && (
        <p
          role="alert"
          style={{
            marginTop: 12,
            padding: '10px 14px',
            border: '1px solid var(--np-border)',
            borderLeft: '3px solid var(--np-danger)',
            background: 'var(--np-danger-soft)',
            borderRadius: 8,
            fontSize: 14,
          }}
        >
          nginx is installed, but its configuration test is currently failing: {serving.detail}
        </p>
      )}

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

              <div className="np-card">
                <h3 style={{ marginTop: 0 }}>SSL certificate</h3>
                {!cert && (
                  <>
                    <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>
                      No certificate. ACME (Let&apos;s Encrypt) issues over http-01 with the
                      challenge served from this site&apos;s webroot; dns-01 is not yet available.
                    </p>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <input
                        className="np-input"
                        value={acmeEmail}
                        onChange={(e) => setAcmeEmail(e.target.value)}
                        placeholder="email for ACME registration"
                        style={{ maxWidth: 260 }}
                        aria-label="ACME email"
                      />
                      <button
                        className="np-button"
                        disabled={busy || acmeEmail.trim() === ''}
                        onClick={() =>
                          void mutate(
                            () =>
                              api(`/domains/${selected.id}/ssl/issue`, {
                                method: 'POST',
                                body: JSON.stringify({ email: acmeEmail.trim() }),
                              }),
                            `certificate issued for ${selected.name}.`,
                          )
                        }
                      >
                        Issue via ACME
                      </button>
                    </div>
                  </>
                )}
                {cert && (
                  <>
                    <div style={{ fontSize: 13 }}>
                      <strong>{cert.common_name}</strong> · issuer {cert.issuer}
                      {cert.auto_renew && <span className="np-badge">auto-renew</span>}
                      <br />
                      <span style={{ color: 'var(--np-muted)' }}>
                        expires {new Date(cert.expires_at).toLocaleDateString()}
                        {cert.last_renewed_at &&
                          ` · last renewed ${new Date(cert.last_renewed_at).toLocaleDateString()}`}
                      </span>
                      <br />
                      <span style={{ color: 'var(--np-muted)' }}>SANs: {cert.san_names.join(', ') || '—'}</span>
                    </div>
                    <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                      {cert.issuer !== 'manual' && (
                        <button
                          className="np-button"
                          disabled={busy}
                          onClick={() =>
                            void mutate(
                              () => api(`/domains/${selected.id}/ssl/renew`, { method: 'POST' }),
                              `certificate renewed for ${selected.name}.`,
                            )
                          }
                        >
                          Renew
                        </button>
                      )}
                      <button
                        className="np-button"
                        disabled={busy}
                        onClick={() => {
                          if (!window.confirm(`Revoke the certificate for ${selected.name}?`)) return;
                          void mutate(
                            () => api(`/domains/${selected.id}/ssl`, { method: 'DELETE' }),
                            'certificate revoked and removed.',
                          );
                        }}
                      >
                        Revoke
                      </button>
                    </div>
                  </>
                )}
              </div>

              <div className="np-card">
                <h3 style={{ marginTop: 0 }}>PHP</h3>
                <p style={{ color: 'var(--np-muted)', fontSize: 13, marginTop: 0 }}>
                  Per-site PHP-FPM pool. The version must be installed on the node and
                  offered by the account&apos;s package; pool values are enforced by the
                  agent (unknown keys are rejected, not ignored).
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 8, marginTop: 8 }}>
                  <label style={{ fontSize: 13 }}>
                    Version
                    <select
                      className="np-input"
                      value={phpVersion}
                      onChange={(e) => setPhpVersion(e.target.value)}
                      style={{ marginTop: 2 }}
                    >
                      <option value="">none</option>
                      {['8.1', '8.2', '8.3', '8.4'].map((v) => (
                        <option key={v} value={v}>
                          {v}
                          {php && !php.offered_by_package.includes(v) ? ' (not in package)' : ''}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label style={{ fontSize: 13 }}>
                    pm.max_children
                    <input className="np-input" type="number" min="1" max="500" value={phpMaxChildren}
                      onChange={(e) => setPhpMaxChildren(e.target.value)} style={{ marginTop: 2 }} />
                  </label>
                  <label style={{ fontSize: 13 }}>
                    memory_limit
                    <input className="np-input" value={phpMemory} onChange={(e) => setPhpMemory(e.target.value)}
                      placeholder="128M" style={{ marginTop: 2 }} />
                  </label>
                  <label style={{ fontSize: 13 }}>
                    upload_max_filesize
                    <input className="np-input" value={phpUpload} onChange={(e) => setPhpUpload(e.target.value)}
                      placeholder="32M" style={{ marginTop: 2 }} />
                  </label>
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
                  <button
                    className="np-button"
                    disabled={busy || phpVersion === ''}
                    onClick={() =>
                      void mutate(
                        () =>
                          api(`/domains/${selected.id}/php`, {
                            method: 'PATCH',
                            body: JSON.stringify({
                              php_version: phpVersion,
                              pool: {
                                'pm.max_children': Number(phpMaxChildren),
                                memory_limit: phpMemory.trim(),
                                upload_max_filesize: phpUpload.trim(),
                                max_execution_time: Number(phpMaxExec),
                              },
                            }),
                          }),
                        `PHP ${phpVersion} pool applied.`,
                      )
                    }
                  >
                    Apply PHP pool
                  </button>
                  {php?.pool && (
                    <button
                      className="np-button"
                      disabled={busy}
                      onClick={() => {
                        if (!window.confirm('Remove the PHP pool for this site?')) return;
                        void mutate(
                          () => api(`/domains/${selected.id}/php`, { method: 'PATCH', body: JSON.stringify({ php_version: null }) }),
                          'PHP pool removed.',
                        );
                      }}
                    >
                      Remove PHP
                    </button>
                  )}
                  {php?.pool && (
                    <span style={{ fontSize: 12, color: 'var(--np-muted)' }}>
                      active: php {php.pool.version}
                    </span>
                  )}
                </div>
              </div>

              <div className="np-card">
                <h3 style={{ marginTop: 0 }}>Config history &amp; drift</h3>
                <p style={{ color: 'var(--np-muted)', fontSize: 13, marginTop: 0 }}>
                  Every applied vhost is versioned. Rollback re-applies an old
                  version&apos;s bytes as a NEW version (history is append-only);
                  drift is reported, never silently reconciled.
                </p>
                <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                  <button
                    className="np-button"
                    disabled={busy}
                    onClick={() =>
                      void mutate(
                        () => api(`/config/nginx_vhost/${selected.id}/drift-check`, { method: 'POST' }),
                        'drift check complete — mismatches appear below.',
                      )
                    }
                  >
                    Check drift now
                  </button>
                </div>
                {drift.length > 0 && (
                  <div style={{ marginBottom: 10 }}>
                    {drift.map((e) => (
                      <div key={e.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                        <span style={{ fontSize: 12, color: 'var(--np-danger)' }}>
                          drift detected {new Date(e.detected_at).toLocaleString()}
                        </span>
                        <span style={{ display: 'flex', gap: 6 }}>
                          <button
                            className="np-button"
                            style={{ padding: '2px 8px', fontSize: 11 }}
                            disabled={busy}
                            onClick={() =>
                              void mutate(
                                () => api(`/config/drift/${e.id}/resolve`, { method: 'POST', body: JSON.stringify({ resolution: 'investigated' }) }),
                                'drift event marked investigated.',
                              )
                            }
                          >
                            Mark investigated
                          </button>
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                {versions.length === 0 && <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>No versions yet.</p>}
                {versions.map((v) => (
                  <div key={v.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 13 }}>
                      v{v.version}
                      {v.is_active && <span className="np-badge">active</span>}{' '}
                      <span style={{ color: 'var(--np-muted)' }}>
                        {v.size_bytes} B · {new Date(v.created_at).toLocaleString()}
                      </span>
                    </span>
                    {!v.is_active && (
                      <button
                        className="np-button"
                        style={{ padding: '2px 8px', fontSize: 11 }}
                        disabled={busy}
                        onClick={() => {
                          if (!window.confirm(`Roll back to v${v.version}? Its bytes are re-applied as a new version.`)) return;
                          void mutate(
                            () => api(`/config/nginx_vhost/${selected.id}/rollback/${v.id}`, { method: 'POST' }),
                            `rolled back to v${v.version} (applied as a new version).`,
                          );
                        }}
                      >
                        Roll back
                      </button>
                    )}
                  </div>
                ))}
              </div>

              <div className="np-card">
                <h3 style={{ marginTop: 0 }}>Logs</h3>
                <p style={{ color: 'var(--np-muted)', fontSize: 13, marginTop: 0 }}>
                  Per-domain nginx access/error logs, written into the account&apos;s
                  <code> logs/ </code> directory and tailed through the agent&apos;s confined
                  read path (10 MiB cap).
                </p>
                <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center' }}>
                  <select
                    className="np-input"
                    value={logKind}
                    onChange={(e) => setLogKind(e.target.value === 'error' ? 'error' : 'access')}
                    aria-label="Log type"
                    style={{ maxWidth: 140 }}
                  >
                    <option value="access">access log</option>
                    <option value="error">error log</option>
                  </select>
                  <select
                    className="np-input"
                    value={logTail}
                    onChange={(e) => setLogTail(e.target.value)}
                    aria-label="Lines to show"
                    style={{ maxWidth: 120 }}
                  >
                    {['100', '200', '500', '1000'].map((n) => (
                      <option key={n} value={n}>
                        {n} lines
                      </option>
                    ))}
                  </select>
                  <button className="np-button" onClick={() => void loadLogs()} disabled={!selected}>
                    Refresh
                  </button>
                </div>
                {log && !log.exists && (
                  <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>
                    No {logKind} log yet — the file appears after the first request to this site
                    following a vhost apply. Sites created before per-site logging get their log
                    directives on the next vhost re-apply (any site edit triggers one).
                  </p>
                )}
                {log && log.exists && (
                  <>
                    <p style={{ color: 'var(--np-muted)', fontSize: 12, marginTop: 0 }}>
                      {log.file} · last {log.lines.length} of {log.total_lines} lines
                      {log.file_truncated &&
                        ' · file exceeded the 10 MiB read cap — oldest bytes not shown'}
                    </p>
                    <pre
                      style={{
                        background: 'rgba(127,127,127,0.1)',
                        padding: 10,
                        fontSize: 12,
                        overflowX: 'auto',
                        overflowY: 'auto',
                        maxHeight: 320,
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {log.lines.join('\n') || '(empty)'}
                    </pre>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </Shell>
  );
}
