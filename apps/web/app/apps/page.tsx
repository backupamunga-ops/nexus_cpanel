'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, getUser } from '../../lib/api';
import Shell from '../shell';
import { Icon } from '../icons';

/**
 * Apps & deploys (B14): install WordPress in one click (the database is
 * created for you), clone any install to a private staging address, and
 * deploy a site straight from a git repository — with history and
 * one-click rollback. Passwords and webhook secrets are shown ONCE.
 */

interface AppRow {
  id: string;
  domain: string;
  account_username: string;
  app_type: string;
  version: string | null;
  install_path: string;
  status: string;
  created_at: string;
}

interface GitRow {
  id: string;
  domain: string;
  provider: string;
  repo_url: string;
  branch: string;
  deploy_path: string;
  last_deployed_at: string | null;
  last_deployed_sha: string | null;
  webhook_url: string | null;
}

interface Release {
  release_id: string;
  sha: string;
  created_at: string;
  active: boolean;
}

interface DomainRow {
  id: string;
  name: string;
  is_active: boolean;
}

export default function AppsPage() {
  const [apps, setApps] = useState<AppRow[] | null>(null);
  const [gits, setGits] = useState<GitRow[] | null>(null);
  const [domains, setDomains] = useState<DomainRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [once, setOnce] = useState<string | null>(null); // shown-once secrets
  const [logView, setLogView] = useState<string | null>(null);
  const [historyFor, setHistoryFor] = useState<string | null>(null);
  const [history, setHistory] = useState<Release[] | null>(null);

  // install form
  const [fDomain, setFDomain] = useState('');
  const [fTitle, setFTitle] = useState('');
  const [fAdmin, setFAdmin] = useState('admin');
  const [fEmail, setFEmail] = useState('');

  // git form
  const [gDomain, setGDomain] = useState('');
  const [gRepo, setGRepo] = useState('');
  const [gBranch, setGBranch] = useState('main');
  const [gPath, setGPath] = useState('public_html');

  useEffect(() => {
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [a, g, d] = await Promise.all([
        api<{ data: AppRow[] }>('/apps'),
        api<{ data: GitRow[] }>('/git').catch(() => ({ data: [] as GitRow[] })),
        api<{ data: DomainRow[] }>('/domains').catch(() => ({ data: [] as DomainRow[] })),
      ]);
      setApps(a.data ?? []);
      setGits(g.data ?? []);
      setDomains((d.data ?? []).filter((x) => x.is_active));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function installWordPress(e: React.FormEvent) {
    e.preventDefault();
    if (!window.confirm(`Install WordPress on this website? A fresh database is created automatically.`)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    setOnce(null);
    try {
      const res = await api<AppRow & { admin_password?: string; log?: string }>('/apps/install', {
        method: 'POST',
        body: JSON.stringify({
          domain_id: fDomain, path: '', title: fTitle,
          admin_user: fAdmin, admin_email: fEmail,
        }),
      });
      setOnce(
        `WordPress ${res.version ?? ''} is live. Admin password (shown only once — save it now): ${res.admin_password ?? '(see the log)'}`,
      );
      setFTitle('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'install failed');
    } finally {
      setBusy(false);
    }
  }

  async function stageClone(a: AppRow) {
    if (!window.confirm(`Create a staging copy of ${a.domain}? A staging address and database are set up automatically.`)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    setOnce(null);
    try {
      const res = await api<{ staging_url: string; database: string }>(`/apps/${a.id}/staging`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setNotice(`Staging ready at ${res.staging_url} (database ${res.database}) — safe to experiment.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'staging clone failed');
    } finally {
      setBusy(false);
    }
  }

  async function updateApp(a: AppRow) {
    if (!window.confirm(`Update WordPress on ${a.domain}? Core files and the database are updated in place.`)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api<AppRow>(`/apps/${a.id}/update`, { method: 'POST' });
      setNotice(`WordPress updated on ${res.domain}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'update failed');
    } finally {
      setBusy(false);
    }
  }

  async function createGit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    setOnce(null);
    try {
      const res = await api<GitRow & { webhook_secret: string }>('/git', {
        method: 'POST',
        body: JSON.stringify({ domain_id: gDomain, repo_url: gRepo, branch: gBranch, deploy_path: gPath }),
      });
      setOnce(
        `Deployment connected. Webhook secret (shown only once — paste it into your repo's webhook settings): ${res.webhook_secret}`,
      );
      setGRepo('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not add the repository');
    } finally {
      setBusy(false);
    }
  }

  async function deployNow(g: GitRow) {
    if (!window.confirm(`Deploy the latest "${g.branch}" of ${g.repo_url} to ${g.domain}?`)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api<GitRow & { log?: string; release_id?: string; sha?: string }>(`/git/${g.id}/deploy`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setNotice(`Deployed ${res.sha?.slice(0, 7) ?? ''} to ${g.domain}.`);
      if (res.log) setLogView(res.log);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'deploy failed');
    } finally {
      setBusy(false);
    }
  }

  async function showHistory(g: GitRow) {
    if (historyFor === g.id) {
      setHistoryFor(null);
      setHistory(null);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ releases: Release[] }>(`/git/${g.id}/history`);
      setHistoryFor(g.id);
      setHistory(res.releases ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not load history');
    } finally {
      setBusy(false);
    }
  }

  async function rollback(g: GitRow, r: Release) {
    if (!window.confirm(`Roll ${g.domain} back to ${r.release_id}? The current version stays in the history.`)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(`/git/${g.id}/rollback`, { method: 'POST', body: JSON.stringify({ release_id: r.release_id }) });
      setNotice(`Rolled back to ${r.release_id}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'rollback failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/apps">
      <div className="np-stack">
        <div className="np-page-head">
          <div>
            <h1 className="np-title">Apps</h1>
            <p className="lede">
              Install WordPress in one click — the database is created for you. Clone any
              install to a private staging address to test changes safely.
            </p>
          </div>
          <span className="np-badge">wordpress first</span>
        </div>

        {error && <div className="np-error">{error}</div>}
        {notice && <div className="np-ok">{notice}</div>}
        {once && (
          <div className="np-ok" style={{ lineHeight: 1.6, wordBreak: 'break-all' }}>
            <Icon name="key" /> {once}
          </div>
        )}
        {logView && (
          <section className="np-card">
            <div className="np-card-head">
              <h3>Deploy log</h3>
              <button className="np-button np-button-ghost np-button-sm" onClick={() => setLogView(null)}>
                Close
              </button>
            </div>
            <pre className="np-pre">{logView}</pre>
          </section>
        )}

        {/* ---- install ---------------------------------------------------- */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="plus" />
              </span>
              Install WordPress
            </h3>
          </div>
          {domains.length === 0 ? (
            <div className="np-empty">
              Add a website first (under Websites) — then its WordPress install is one click here.
            </div>
          ) : (
            <form className="np-form" onSubmit={installWordPress}>
              <div className="np-row">
                <div className="np-field">
                  <label htmlFor="f-domain">Website</label>
                  <select id="f-domain" className="np-select" value={fDomain} onChange={(e) => setFDomain(e.target.value)} required>
                    <option value="" disabled>
                      choose a website…
                    </option>
                    {domains.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                  <span className="np-hint">WordPress fills the website&apos;s main folder.</span>
                </div>
                <div className="np-field">
                  <label htmlFor="f-title">Site title</label>
                  <input id="f-title" className="np-input" value={fTitle} onChange={(e) => setFTitle(e.target.value)} placeholder="My blog" required />
                </div>
              </div>
              <div className="np-row">
                <div className="np-field">
                  <label htmlFor="f-admin">Admin username</label>
                  <input id="f-admin" className="np-input" value={fAdmin} onChange={(e) => setFAdmin(e.target.value)} required />
                </div>
                <div className="np-field">
                  <label htmlFor="f-email">Admin email</label>
                  <input id="f-email" className="np-input" type="email" value={fEmail} onChange={(e) => setFEmail(e.target.value)} placeholder="you@example.com" required />
                </div>
              </div>
              <div>
                <button className="np-button" disabled={busy} type="submit">
                  <Icon name="rocket" /> Install WordPress
                </button>
                <span className="np-hint" style={{ marginLeft: 10 }}>
                  A strong admin password is generated for you and shown once.
                </span>
              </div>
            </form>
          )}
        </section>

        {/* ---- installed apps --------------------------------------------- */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="rocket" />
              </span>
              Your apps
            </h3>
            <span className="np-badge">{apps?.length ?? '…'}</span>
          </div>
          {apps === null ? (
            <p className="np-muted">Loading…</p>
          ) : apps.length === 0 ? (
            <div className="np-empty">No apps installed yet — use the form above.</div>
          ) : (
            <div className="np-table-wrap">
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Website</th>
                    <th>App</th>
                    <th>Version</th>
                    <th>Folder</th>
                    <th style={{ textAlign: 'right' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {apps.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <b style={{ color: 'var(--np-foreground)' }}>{a.domain}</b>
                        <small style={{ display: 'block', color: 'var(--np-muted)' }}>{a.account_username}</small>
                      </td>
                      <td>
                        <span className="np-badge ok">{a.app_type}</span>
                      </td>
                      <td className="np-mono">{a.version ?? '—'}</td>
                      <td className="np-mono">{a.install_path}</td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button className="np-button np-button-ghost np-button-sm" disabled={busy} onClick={() => void stageClone(a)}>
                          Staging copy
                        </button>{' '}
                        <button className="np-button np-button-ghost np-button-sm" disabled={busy} onClick={() => void updateApp(a)}>
                          Update
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ---- git -------------------------------------------------------- */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="git-branch" />
              </span>
              Deploy from git
            </h3>
            <span className="np-badge">{gits?.length ?? '…'}</span>
          </div>
          <p className="np-hint" style={{ marginTop: 0 }}>
            Connect a GitHub / GitLab / Bitbucket repository. Every push to your branch goes
            live; any earlier version stays one click away for rollback.
          </p>
          {domains.length > 0 && (
            <form className="np-form" onSubmit={createGit}>
              <div className="np-row">
                <div className="np-field">
                  <label htmlFor="g-domain">Website</label>
                  <select id="g-domain" className="np-select" value={gDomain} onChange={(e) => setGDomain(e.target.value)} required>
                    <option value="" disabled>
                      choose a website…
                    </option>
                    {domains.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="np-field">
                  <label htmlFor="g-repo">Repository URL</label>
                  <input id="g-repo" className="np-input" value={gRepo} onChange={(e) => setGRepo(e.target.value)} placeholder="https://github.com/you/site.git" required />
                </div>
              </div>
              <div className="np-row">
                <div className="np-field">
                  <label htmlFor="g-branch">Branch to deploy</label>
                  <input id="g-branch" className="np-input" value={gBranch} onChange={(e) => setGBranch(e.target.value)} required />
                </div>
                <div className="np-field">
                  <label htmlFor="g-path">Deploy to folder</label>
                  <input id="g-path" className="np-input" value={gPath} onChange={(e) => setGPath(e.target.value)} required />
                  <span className="np-hint">Relative to the account home; it becomes a link to the latest version.</span>
                </div>
              </div>
              <div>
                <button className="np-button" disabled={busy} type="submit">
                  Connect repository
                </button>
              </div>
            </form>
          )}

          {gits !== null && gits.length > 0 && (
            <div className="np-table-wrap" style={{ marginTop: 16 }}>
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Website</th>
                    <th>Repository</th>
                    <th>Branch</th>
                    <th>Last deploy</th>
                    <th style={{ textAlign: 'right' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {gits.map((g) => (
                    <tr key={g.id}>
                      <td>
                        <b style={{ color: 'var(--np-foreground)' }}>{g.domain}</b>
                        <small style={{ display: 'block', color: 'var(--np-muted)' }}>{g.deploy_path}</small>
                      </td>
                      <td className="np-mono" style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {g.repo_url}
                      </td>
                      <td className="np-mono">{g.branch}</td>
                      <td>
                        {g.last_deployed_at ? (
                          <>
                            {new Date(g.last_deployed_at).toLocaleString()}
                            <small className="np-mono" style={{ display: 'block', color: 'var(--np-muted)' }}>
                              {g.last_deployed_sha?.slice(0, 7)}
                            </small>
                          </>
                        ) : (
                          <span className="np-badge warn">never</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button className="np-button np-button-ghost np-button-sm" disabled={busy} onClick={() => void showHistory(g)}>
                          {historyFor === g.id ? 'Hide history' : 'History'}
                        </button>{' '}
                        <button className="np-button np-button-sm" disabled={busy} onClick={() => void deployNow(g)}>
                          Deploy now
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {historyFor && history !== null && (
            <div className="np-table-wrap" style={{ marginTop: 10 }}>
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Version</th>
                    <th>Commit</th>
                    <th>Deployed</th>
                    <th style={{ textAlign: 'right' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {history.length === 0 ? (
                    <tr>
                      <td colSpan={4}>
                        <div className="np-empty">No deploys yet — use “Deploy now” or push to your branch.</div>
                      </td>
                    </tr>
                  ) : (
                    history.map((r) => (
                      <tr key={r.release_id}>
                        <td className="np-mono">
                          {r.release_id} {r.active && <span className="np-badge ok">live</span>}
                        </td>
                        <td className="np-mono">{r.sha.slice(0, 7)}</td>
                        <td>{new Date(r.created_at).toLocaleString()}</td>
                        <td style={{ textAlign: 'right' }}>
                          {!r.active && (
                            <button
                              className="np-button np-button-ghost np-button-sm"
                              disabled={busy}
                              onClick={() => {
                                const g = gits?.find((x) => x.id === historyFor);
                                if (g) void rollback(g, r);
                              }}
                            >
                              Restore this version
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </Shell>
  );
}
