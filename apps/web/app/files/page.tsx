'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * File manager + SSH keys (API spec §4.11/§4.13, ADR-0008).
 *
 * The agent executes every byte operation under path confinement; the
 * control plane owns permissions, the trash ledger and the audit chain.
 * Downloads arrive base64-wrapped (JSON) with an explicit truncated flag —
 * the 10 MiB cap is honest, not silent. SSH keys are labeled "stored — not
 * yet deployed to the node" until the authorized_keys write path lands (P4).
 */

interface FileEntry {
  name: string;
  type: string;
  size_bytes: number;
  mode: string;
  modified_at: string;
}

interface TrashEntry {
  id: string;
  original_path: string;
  trash_path: string;
  size_bytes: number;
  deleted_at: string;
  purge_after: string;
}

interface SshKey {
  id: string;
  name: string;
  fingerprint: string;
  created_at: string;
}

interface SshDeployedView {
  file: string;
  exists: boolean;
  foreign_count: number;
  data: Array<{ ssh_key_id: string; name: string; fingerprint: string; on_node: boolean }>;
}

interface FtpAccount {
  id: string;
  username: string;
  root_dir: string;
  read_only: boolean;
  status: string;
  created_at: string;
}

interface AccountOption {
  id: string;
  username: string;
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

export default function FilesPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [accountId, setAccountId] = useState('');
  const [path, setPath] = useState('');
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [trash, setTrash] = useState<TrashEntry[]>([]);
  const [sshKeys, setSshKeys] = useState<SshKey[]>([]);
  const [sshDeployed, setSshDeployed] = useState<SshDeployedView | null>(null);
  const [ftpAccounts, setFtpAccounts] = useState<FtpAccount[]>([]);
  const [ftpUser, setFtpUser] = useState('');
  const [ftpPass, setFtpPass] = useState('');
  const [ftpRoot, setFtpRoot] = useState('');
  const [ftpRo, setFtpRo] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [newDir, setNewDir] = useState('');
  const [keyName, setKeyName] = useState('');
  const [keyBody, setKeyBody] = useState('');
  const [uploadName, setUploadName] = useState('');
  const [uploadContent, setUploadContent] = useState('');

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    if (!accountId) return;
    try {
      const j = await api<{ entries: FileEntry[] }>(
        `/files?account_id=${encodeURIComponent(accountId)}&path=${encodeURIComponent(path)}`,
      );
      setEntries(j.entries ?? []);
      const t = await api<{ data: TrashEntry[] }>(`/files/trash?account_id=${encodeURIComponent(accountId)}`);
      setTrash(t.data ?? []);
      const k = await api<{ data: SshKey[] }>(`/ssh/keys?account_id=${encodeURIComponent(accountId)}`);
      setSshKeys(k.data ?? []);
      const d = await api<SshDeployedView>(`/ssh/keys/deployed?account_id=${encodeURIComponent(accountId)}`);
      setSshDeployed(d);
      const f = await api<{ data: FtpAccount[] }>(`/ftp?account_id=${encodeURIComponent(accountId)}`);
      setFtpAccounts(f.data ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, [accountId, path]);

  useEffect(() => {
    api<{ data: AccountOption[] }>('/accounts')
      .then((a) => setAccounts(a.data ?? []))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  function join(base: string, name: string): string {
    if (!base || base === '' || base === '.') return name;
    return `${base.replace(/\/$/, '')}/${name}`;
  }

  async function run(fn: () => Promise<unknown>, ok: string) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await fn();
      setMessage(ok);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'operation failed');
    } finally {
      setBusy(false);
    }
  }

  function download(name: string) {
    void run(async () => {
      const res = await api<{ content_b64: string; truncated: boolean }>(
        `/files/download?account_id=${encodeURIComponent(accountId)}&path=${encodeURIComponent(join(path, name))}`,
      );
      const bytes = Uint8Array.from(atob(res.content_b64), (c) => c.charCodeAt(0));
      const url = URL.createObjectURL(new Blob([bytes]));
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
      if (res.truncated) {
        setError('file exceeded the 10 MiB read cap — download is partial.');
      }
    }, `downloaded ${name}.`);
  }

  function upload(e: FormEvent) {
    e.preventDefault();
    const file = uploadContent;
    const name = uploadName.trim();
    if (!name || !file) return;
    void run(async () => {
      await api('/files/upload', {
        method: 'POST',
        body: JSON.stringify({ account_id: accountId, path: join(path, name), content_b64: file }),
      });
    }, `uploaded ${name}.`).then(() => {
      setUploadName('');
      setUploadContent('');
    });
  }

  function onFilePicked(files: FileList | null) {
    const f = files?.[0];
    if (!f) return;
    if (f.size > 10 * 1024 * 1024) {
      setError('file exceeds the 10 MiB upload cap.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setUploadName(f.name);
      setUploadContent((reader.result as string).split(',')[1] ?? '');
    };
    reader.readAsDataURL(f);
  }

  return (
    <Shell active="/files" user={user}>
      <h1 className="np-title">Files</h1>
      <p className="np-subtitle">
        Browser file manager over the agent's confined filesystem commands
        (ADR-0008). Deletes go to a 30-day trash — restore or purge from the
        trash panel; nothing vanishes directly.
      </p>

      {message && <p role="status" style={{ color: 'var(--np-muted)', marginTop: 12 }}>{message}</p>}
      {error && <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>{error}</p>}

      <div className="np-card" style={{ marginTop: 20, display: 'flex', gap: 12, alignItems: 'end', flexWrap: 'wrap' }}>
        <label style={{ fontSize: 13 }}>
          Hosting account
          <select
            className="np-input"
            value={accountId}
            onChange={(e) => {
              setAccountId(e.target.value);
              setPath('');
            }}
            style={{ marginTop: 2, minWidth: 200 }}
          >
            <option value="">— select —</option>
            {accounts.map((a) => (
              <option key={a.id} value={a.id}>{a.username}</option>
            ))}
          </select>
        </label>
        <label style={{ fontSize: 13, flexGrow: 1 }}>
          Path (relative to the account home)
          <input
            className="np-input"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="domains/example.com/public_html"
            style={{ marginTop: 2 }}
          />
        </label>
        <button className="np-button" disabled={busy || !accountId} onClick={() => void refresh()}>
          Refresh
        </button>
      </div>

      {accountId && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 16, marginTop: 20 }}>
          {/* ── browser ─────────────────────────────────────────────── */}
          <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
            <div className="np-card">
              <h2 style={{ marginTop: 0 }}>
                {path === '' ? '/' : `/${path}`}
              </h2>
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Mode</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.length === 0 && (
                    <tr><td colSpan={5} style={{ color: 'var(--np-muted)' }}>Empty directory.</td></tr>
                  )}
                  {entries.map((e) => (
                    <tr key={e.name}>
                      <td>
                        {e.type === 'dir' ? (
                          <a
                            href="#"
                            onClick={(ev) => {
                              ev.preventDefault();
                              setPath(join(path, e.name));
                            }}
                          >
                            {e.name}/
                          </a>
                        ) : (
                          e.name
                        )}
                      </td>
                      <td>{e.type}</td>
                      <td>{fmtSize(e.size_bytes)}</td>
                      <td><code>{e.mode}</code></td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        {e.type === 'file' && (
                          <button className="np-button" style={{ padding: '2px 8px', fontSize: 11 }} disabled={busy} onClick={() => download(e.name)}>
                            Download
                          </button>
                        )}{' '}
                        <button
                          className="np-button"
                          style={{ padding: '2px 8px', fontSize: 11 }}
                          disabled={busy}
                          onClick={() => {
                            if (!window.confirm(`Move ${e.name} to trash?`)) return;
                            void run(
                              () =>
                                api('/files/delete', {
                                  method: 'POST',
                                  body: JSON.stringify({ account_id: accountId, path: join(path, e.name) }),
                                }),
                              `${e.name} moved to trash.`,
                            );
                          }}
                        >
                          Trash
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="np-card">
              <h3 style={{ marginTop: 0 }}>Create / upload in this directory</h3>
              <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                <input
                  className="np-input"
                  value={newDir}
                  onChange={(e) => setNewDir(e.target.value)}
                  placeholder="new-directory-name"
                  aria-label="New directory name"
                  style={{ maxWidth: 240 }}
                />
                <button
                  className="np-button"
                  disabled={busy || newDir.trim() === ''}
                  onClick={() =>
                    void run(
                      () =>
                        api('/files/mkdir', {
                          method: 'POST',
                          body: JSON.stringify({ account_id: accountId, path: join(path, newDir.trim()) }),
                        }),
                      `directory ${newDir.trim()} created.`,
                    ).then(() => setNewDir(''))
                  }
                >
                  Create directory
                </button>
              </div>
              <form onSubmit={upload}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                  <input type="file" onChange={(e) => onFilePicked(e.target.files)} aria-label="Pick file to upload" />
                  {uploadName && <span style={{ fontSize: 12, color: 'var(--np-muted)' }}>{uploadName} ready</span>}
                </div>
                <button className="np-button" type="submit" disabled={busy || !uploadContent}>
                  Upload to this directory
                </button>
              </form>
            </div>
          </div>

          {/* ── trash + ssh ─────────────────────────────────────────── */}
          <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
            <div className="np-card">
              <h3 style={{ marginTop: 0 }}>Trash (30-day retention)</h3>
              {trash.length === 0 && <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>Empty.</p>}
              {trash.map((t) => (
                <div key={t.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 12, wordBreak: 'break-all' }}>
                    {t.original_path} <span style={{ color: 'var(--np-muted)' }}>({fmtSize(t.size_bytes)}, until {new Date(t.purge_after).toLocaleDateString()})</span>
                  </span>
                  <span style={{ display: 'flex', gap: 6 }}>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() => void run(() => api(`/files/trash/${t.id}/restore`, { method: 'POST' }), 'restored.')}
                    >
                      Restore
                    </button>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() => {
                        if (!window.confirm('Delete this trash entry permanently?')) return;
                        void run(() => api(`/files/trash/${t.id}`, { method: 'DELETE' }), 'purged.');
                      }}
                    >
                      Purge
                    </button>
                  </span>
                </div>
              ))}
              {trash.length > 0 && (
                <button
                  className="np-button"
                  disabled={busy}
                  style={{ marginTop: 8 }}
                  onClick={() => {
                    if (!window.confirm('Run the purge for expired trash entries of this account?')) return;
                    void run(
                      () => api('/files/trash/purge', { method: 'POST', body: JSON.stringify({ account_id: accountId }) }),
                      'purge completed — expired entries the agent removed are cleared from the ledger.',
                    );
                  }}
                >
                  Purge expired entries
                </button>
              )}
            </div>

            <div className="np-card">
              <h3 style={{ marginTop: 0 }}>SSH keys</h3>
              <p style={{ fontSize: 12, color: 'var(--np-muted)', marginTop: 0 }}>
                Deploy reconciles only the panel-managed lines of
                <code> authorized_keys</code>; keys added by hand on the node
                are never touched.
                {sshDeployed && sshDeployed.exists && sshDeployed.foreign_count > 0 && (
                  <>
                    {' '}Currently {sshDeployed.foreign_count} foreign key(s) on the node.
                  </>
                )}
              </p>
              {sshKeys.length === 0 && <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>No keys imported.</p>}
              {sshKeys.map((k) => {
                const onNode = sshDeployed?.data.find((d) => d.ssh_key_id === k.id)?.on_node;
                return (
                  <div key={k.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 12, wordBreak: 'break-all' }}>
                      <strong>{k.name}</strong>{' '}
                      {onNode ? <span className="np-badge">on node</span> : <span className="np-badge">not deployed</span>}
                      <br />
                      <code>{k.fingerprint}</code>
                    </span>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() => {
                        if (!window.confirm(`Remove key ${k.name}? It is removed from the node on the next deploy.`)) return;
                        void run(() => api(`/ssh/keys/${k.id}`, { method: 'DELETE' }), 'key removed.');
                      }}
                    >
                      Remove
                    </button>
                  </div>
                );
              })}
              <div style={{ marginTop: 8 }}>
                <button
                  className="np-button"
                  disabled={busy}
                  onClick={() =>
                    void run(
                      () => api('/ssh/keys/deploy', { method: 'POST', body: JSON.stringify({ account_id: accountId }) }),
                      'keys deployed — authorized_keys reconciled on the node.',
                    )
                  }
                >
                  Deploy to node
                </button>
              </div>
              <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
                <input
                  className="np-input"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  placeholder="key name (e.g. laptop)"
                  aria-label="SSH key name"
                />
                <textarea
                  className="np-input"
                  value={keyBody}
                  onChange={(e) => setKeyBody(e.target.value)}
                  placeholder="ssh-ed25519 AAAA… comment"
                  rows={3}
                  aria-label="SSH public key"
                />
                <button
                  className="np-button"
                  disabled={busy || keyName.trim() === '' || keyBody.trim() === ''}
                  onClick={() =>
                    void run(
                      () =>
                        api('/ssh/keys', {
                          method: 'POST',
                          body: JSON.stringify({ account_id: accountId, name: keyName.trim(), public_key: keyBody.trim() }),
                        }),
                      'key imported — use Deploy to node to write it to authorized_keys.',
                    ).then(() => {
                      setKeyName('');
                      setKeyBody('');
                    })
                  }
                >
                  Import key
                </button>
              </div>
            </div>

            <div className="np-card">
              <h3 style={{ marginTop: 0 }}>FTP accounts</h3>
              <p style={{ fontSize: 12, color: 'var(--np-muted)', marginTop: 0 }}>
                vsftpd virtual users (ADR-0011): each login is chrooted to a
                directory inside this account&apos;s home. Passwords are hashed
                on the node (SHA-512-crypt) and never stored in the panel.
              </p>
              {ftpAccounts.length === 0 && <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>No FTP accounts.</p>}
              {ftpAccounts.map((f) => (
                <div key={f.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 12, wordBreak: 'break-all' }}>
                    <strong>{f.username}</strong>{' '}
                    {f.read_only && <span className="np-badge">read-only</span>}
                    <br />
                    <span style={{ color: 'var(--np-muted)' }}>root: {f.root_dir}</span>
                  </span>
                  <span style={{ display: 'flex', gap: 6 }}>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() => {
                        const pw = window.prompt(`New password for ${f.username} (min 8 chars):`);
                        if (!pw || pw.length < 8) return;
                        void run(() => api(`/ftp/${f.id}/password`, { method: 'POST', body: JSON.stringify({ password: pw }) }), 'password rotated.');
                      }}
                    >
                      Reset password
                    </button>
                    <button
                      className="np-button"
                      style={{ padding: '2px 8px', fontSize: 11 }}
                      disabled={busy}
                      onClick={() => {
                        if (!window.confirm(`Remove FTP account ${f.username}?`)) return;
                        void run(() => api(`/ftp/${f.id}`, { method: 'DELETE' }), 'ftp account removed.');
                      }}
                    >
                      Remove
                    </button>
                  </span>
                </div>
              ))}
              <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
                <input
                  className="np-input"
                  value={ftpUser}
                  onChange={(e) => setFtpUser(e.target.value)}
                  placeholder="login (e.g. alice.web)"
                  aria-label="FTP login"
                />
                <input
                  className="np-input"
                  type="password"
                  value={ftpPass}
                  onChange={(e) => setFtpPass(e.target.value)}
                  placeholder="password (min 8 chars)"
                  aria-label="FTP password"
                />
                <input
                  className="np-input"
                  value={ftpRoot}
                  onChange={(e) => setFtpRoot(e.target.value)}
                  placeholder="directory inside home (empty = home itself)"
                  aria-label="FTP root directory"
                />
                <label style={{ fontSize: 12, display: 'flex', gap: 6, alignItems: 'center' }}>
                  <input type="checkbox" checked={ftpRo} onChange={(e) => setFtpRo(e.target.checked)} />
                  read-only (no uploads)
                </label>
                <button
                  className="np-button"
                  disabled={busy || ftpUser.trim() === '' || ftpPass.length < 8}
                  onClick={() =>
                    void run(
                      () =>
                        api('/ftp', {
                          method: 'POST',
                          body: JSON.stringify({
                            account_id: accountId,
                            username: ftpUser.trim(),
                            password: ftpPass,
                            ...(ftpRoot.trim() !== '' ? { root_dir: ftpRoot.trim() } : {}),
                            read_only: ftpRo,
                          }),
                        }),
                      'ftp account created.',
                    ).then(() => {
                      setFtpUser('');
                      setFtpPass('');
                      setFtpRoot('');
                      setFtpRo(false);
                    })
                  }
                >
                  Create FTP account
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </Shell>
  );
}
