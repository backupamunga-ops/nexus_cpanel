'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, getUser } from '../../lib/api';
import Shell from '../shell';
import { Icon } from '../icons';

/**
 * Extensions (P7, ADR-0021) — install by manifest URL, review the
 * requested scopes, approve (credentials shown ONCE), enable/disable,
 * uninstall. DirectAdmin-simple: one card per extension, one obvious
 * action per state.
 */

interface ExtensionDto {
  id: string;
  slug: string;
  name: string;
  version: string;
  status: 'enabled' | 'disabled' | 'errored' | string;
  granted_scopes: string[];
  requested_scopes: string[];
  types: string[];
  last_error: string | null;
  last_heartbeat_at: string | null;
  callback_url: string | null;
  installed_at: string;
}

interface Credentials {
  extension_id: string;
  shared_secret: string;
  derived_token: string;
  panel_base_url: string;
  issued_at: string;
}

const STATUS_BADGE: Record<string, string> = {
  enabled: 'ok',
  disabled: 'info',
  errored: 'error',
};

function Scopes({ scopes }: { scopes: string[] }) {
  if (scopes.length === 0) return <span className="np-muted" style={{ fontSize: 12 }}>none granted yet</span>;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
      {scopes.map((s) => (
        <span key={s} className="np-badge info" style={{ fontSize: 10.5 }}>{s}</span>
      ))}
    </div>
  );
}

export default function ExtensionsPage() {
  const [items, setItems] = useState<ExtensionDto[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [manifestUrl, setManifestUrl] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [creds, setCreds] = useState<Credentials | null>(null);
  const [credsFor, setCredsFor] = useState<string>('');

  useEffect(() => {
    const user = getUser();
    if (!user?.is_super_admin) {
      window.location.href = '/';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const j = await api<{ data: ExtensionDto[] }>('/extensions');
      setItems(j.data ?? []);
    } catch {
      setItems([]);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function install(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api('/extensions', {
        method: 'POST',
        body: JSON.stringify({ manifest_url: manifestUrl }),
      });
      setManifestUrl('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'install failed');
    } finally {
      setBusy(false);
    }
  }

  async function act(ext: ExtensionDto, action: 'approve' | 'reject' | 'enable' | 'disable') {
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ data?: Credentials }>(`/extensions/${ext.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ action }),
      });
      if (action === 'approve' && res.data?.shared_secret) {
        setCreds(res.data);
        setCredsFor(ext.name);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : `${action} failed`);
    } finally {
      setBusy(false);
    }
  }

  async function uninstall(ext: ExtensionDto) {
    if (!window.confirm(`Uninstall "${ext.name}"? Its token stops working immediately.`)) return;
    setBusy(true);
    try {
      await api(`/extensions/${ext.id}`, { method: 'DELETE' });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'uninstall failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/extensions">
      <div className="np-stack">
        <div className="np-page-head">
          <div>
            <h1 className="np-title">Extensions</h1>
            <p className="lede">
              Add-ons that run outside the panel, talk over a signed protocol, and only ever
              see the scopes you approve. Nothing is granted until you say so.
            </p>
          </div>
        </div>

        {creds && (
          <section className="np-card" style={{ borderColor: 'var(--np-primary)' }}>
            <div className="np-card-head">
              <h3>
                <span className="ico">
                  <Icon name="key" />
                </span>
                One-time credentials — {credsFor}
              </h3>
              <button className="np-button np-button-ghost" onClick={() => setCreds(null)}>
                I saved it
              </button>
            </div>
            <p className="np-muted" style={{ fontSize: 12.5 }}>
              Shown <strong>only this once</strong>. Paste them into the extension now — the
              secret cannot be retrieved again (SDK spec §5.1).
            </p>
            <div className="np-form" style={{ marginTop: 8 }}>
              <label>
                Shared secret
                <input readOnly value={creds.shared_secret} onFocus={(e) => e.target.select()} />
              </label>
              <label>
                API token for /api/v1/ext/*
                <input readOnly value={creds.derived_token} onFocus={(e) => e.target.select()} />
              </label>
            </div>
          </section>
        )}

        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="plus" />
              </span>
              Install an extension
            </h3>
          </div>
          <p className="np-muted" style={{ fontSize: 12.5 }}>
            Point at the extension&apos;s manifest URL — the panel fetches{' '}
            <code>&lt;origin&gt;/nexuspanel-manifest.json</code>, validates it, and holds the
            extension <strong>disabled</strong> until you approve its scopes.
          </p>
          <form className="np-form" onSubmit={install} style={{ marginTop: 8 }}>
            <label>
              Manifest URL
              <input
                type="url"
                required
                placeholder="https://acme.example/nexuspanel-manifest.json"
                value={manifestUrl}
                onChange={(e) => setManifestUrl(e.target.value)}
              />
            </label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button className="np-button" type="submit" disabled={busy || !manifestUrl}>
                Fetch manifest
              </button>
              {error && <span style={{ color: 'var(--np-danger)', fontSize: 12.5 }}>{error}</span>}
            </div>
          </form>
        </section>

        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="store" />
              </span>
              Installed extensions
            </h3>
            <span className="np-badge">{items?.length ?? 0}</span>
          </div>
          {items === null ? (
            <p className="np-muted">Loading…</p>
          ) : items.length === 0 ? (
            <div className="np-empty">
              No extensions installed yet — paste a manifest URL above to add one.
            </div>
          ) : (
            <div className="np-table-wrap">
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Extension</th>
                    <th>Status</th>
                    <th>Granted scopes</th>
                    <th>Heartbeat</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((x) => (
                    <tr key={x.id}>
                      <td>
                        <b>{x.name}</b>
                        <div className="np-muted-2" style={{ fontSize: 11 }}>
                          {x.slug} · v{x.version} · {x.types.join(', ')}
                        </div>
                        {x.last_error && (
                          <div style={{ color: 'var(--np-danger)', fontSize: 11, marginTop: 2 }}>
                            {x.last_error}
                          </div>
                        )}
                      </td>
                      <td>
                        <span className={`np-badge ${STATUS_BADGE[x.status] ?? 'info'}`}>{x.status}</span>
                      </td>
                      <td>
                        <Scopes scopes={x.granted_scopes} />
                        {x.status === 'disabled' && x.requested_scopes.length > 0 && (
                          <div className="np-muted" style={{ fontSize: 11, marginTop: 4 }}>
                            requests: {x.requested_scopes.join(', ')}
                          </div>
                        )}
                      </td>
                      <td className="np-muted" style={{ fontSize: 12 }}>
                        {x.last_heartbeat_at ? new Date(x.last_heartbeat_at).toLocaleString() : '—'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {x.status === 'disabled' && x.granted_scopes.length === 0 && (
                            <>
                              <button className="np-button" disabled={busy} onClick={() => void act(x, 'approve')}>
                                Approve
                              </button>
                              <button className="np-button np-button-ghost" disabled={busy} onClick={() => void act(x, 'reject')}>
                                Reject
                              </button>
                            </>
                          )}
                          {x.status === 'disabled' && x.granted_scopes.length > 0 && (
                            <button className="np-button" disabled={busy} onClick={() => void act(x, 'enable')}>
                              Enable
                            </button>
                          )}
                          {x.status === 'enabled' && (
                            <button className="np-button np-button-ghost" disabled={busy} onClick={() => void act(x, 'disable')}>
                              Disable
                            </button>
                          )}
                          <button className="np-button np-button-danger" disabled={busy} onClick={() => void uninstall(x)}>
                            Uninstall
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </Shell>
  );
}
