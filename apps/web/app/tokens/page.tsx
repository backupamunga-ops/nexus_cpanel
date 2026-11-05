'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import { WEB_KNOWN_PERMISSIONS } from '../../lib/permissions';
import Shell from '../shell';

/**
 * API tokens screen (C4, API spec §4.3 /tokens — session-only by design).
 *
 * The secret is shown exactly ONCE (create/rotate) — after dismissal it is
 * unrecoverable by design (only its SHA-256 is stored). Rotation never
 * extends the original expiry. A token can do nothing beyond its scopes,
 * and never more than its owner could interactively.
 */

interface ApiToken {
  id: string;
  name: string;
  scopes: string[];
  ip_allowlist: string[];
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
  revoked_at: string | null;
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—';
}

function copyText(text: string): void {
  if (navigator.clipboard?.writeText) {
    void navigator.clipboard.writeText(text);
    return;
  }
  const el = document.createElement('textarea');
  el.value = text;
  document.body.appendChild(el);
  el.select();
  document.execCommand('copy');
  document.body.removeChild(el);
}

export default function TokensPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Create form state
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [expiresAt, setExpiresAt] = useState('');
  const [ipAllowlist, setIpAllowlist] = useState('');

  // Show-once secret (create or rotate)
  const [minted, setMinted] = useState<{ token: string; context: string } | null>(null);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const j = await api<{ data: ApiToken[] }>('/tokens');
      setTokens(j.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await api<{ token: string; record: ApiToken }>('/tokens', {
        method: 'POST',
        body: JSON.stringify({
          name,
          scopes: [...scopes],
          ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {}),
          ...(ipAllowlist.trim()
            ? { ip_allowlist: ipAllowlist.split(',').map((s) => s.trim()).filter(Boolean) }
            : {}),
        }),
      });
      setMinted({ token: result.token, context: `“${result.record.name}”` });
      setName('');
      setScopes(new Set());
      setExpiresAt('');
      setIpAllowlist('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'create failed');
    } finally {
      setBusy(false);
    }
  }

  async function rotate(t: ApiToken) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await api<{ token: string; record: ApiToken }>(`/tokens/${t.id}/rotate`, {
        method: 'POST',
      });
      setMinted({ token: result.token, context: `“${t.name}” (rotated — old secret is dead)` });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'rotate failed');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(t: ApiToken) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/tokens/${t.id}`, { method: 'DELETE' });
      setMessage(`token “${t.name}” revoked.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'revoke failed');
    } finally {
      setBusy(false);
    }
  }

  function toggleScope(p: string) {
    setScopes((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });
  }

  return (
    <Shell active="/tokens" user={user}>
      <h1 className="np-title">API tokens</h1>
      <p className="np-subtitle">
        Scoped automation credentials (C4). A token can do <strong>nothing beyond its
        scopes</strong>, never more than you could, and never manage credentials or 2FA
        itself. Secrets are hashed (SHA-256) at rest and shown exactly once.
      </p>

      {message && <p role="status" style={{ color: 'var(--np-muted)', marginTop: 12 }}>{message}</p>}
      {error && <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>{error}</p>}

      {/* ── show-once secret ──────────────────────────────────────── */}
      {minted && (
        <div className="np-card" style={{ marginTop: 20, maxWidth: 560 }}>
          <h2 style={{ marginTop: 0 }}>New token secret {minted.context}</h2>
          <p style={{ color: 'var(--np-danger)', fontSize: 13 }}>
            Copy it now — this is the only time it is ever displayed.
          </p>
          <code style={{ wordBreak: 'break-all', display: 'block', padding: 8, background: 'var(--np-bg, #0b0d12)' }}>
            {minted.token}
          </code>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button className="np-button" onClick={() => copyText(minted.token)} type="button">
              Copy secret
            </button>
            <button className="np-button" onClick={() => setMinted(null)} type="button">
              Done — I&apos;ve stored it
            </button>
          </div>
        </div>
      )}

      {/* ── create form ───────────────────────────────────────────── */}
      <form onSubmit={create} className="np-card" style={{ marginTop: 20, maxWidth: 560 }}>
        <h2 style={{ marginTop: 0 }}>Create token</h2>
        <label htmlFor="tok-name" style={{ display: 'block', marginBottom: 4 }}>Name</label>
        <input
          id="tok-name"
          className="np-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="ci-deploy"
          required
          maxLength={100}
        />
        <fieldset style={{ border: 'none', margin: '12px 0 0', padding: 0 }}>
          <legend style={{ padding: 0, marginBottom: 6 }}>Scopes ({scopes.size} selected)</legend>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
            {WEB_KNOWN_PERMISSIONS.map((p) => (
              <label key={p} style={{ fontSize: 13, display: 'flex', gap: 6, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={scopes.has(p)}
                  onChange={() => toggleScope(p)}
                />
                <code>{p}</code>
              </label>
            ))}
          </div>
        </fieldset>
        <label htmlFor="tok-exp" style={{ display: 'block', margin: '12px 0 4px' }}>
          Expires (optional — rotation never extends it)
        </label>
        <input
          id="tok-exp"
          className="np-input"
          type="datetime-local"
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
        />
        <label htmlFor="tok-ips" style={{ display: 'block', margin: '12px 0 4px' }}>
          IP allowlist (optional, comma-separated)
        </label>
        <input
          id="tok-ips"
          className="np-input"
          value={ipAllowlist}
          onChange={(e) => setIpAllowlist(e.target.value)}
          placeholder="203.0.113.7, 198.51.100.0/24"
        />
        <button className="np-button" type="submit" disabled={busy || scopes.size === 0} style={{ marginTop: 16 }}>
          {busy ? 'Creating…' : 'Create token'}
        </button>
        {scopes.size === 0 && (
          <p style={{ color: 'var(--np-muted)', fontSize: 12, marginTop: 8 }}>
            Scopes are required — a token with no scopes could do nothing, so the
            server would reject it.
          </p>
        )}
      </form>

      {/* ── list ──────────────────────────────────────────────────── */}
      <div style={{ marginTop: 24, display: 'grid', gap: 12 }}>
        {tokens.length === 0 && (
          <p style={{ color: 'var(--np-muted)' }}>No tokens yet.</p>
        )}
        {tokens.map((t) => (
          <div
            key={t.id}
            className="np-card"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}
          >
            <div>
              <strong>{t.name}</strong>{' '}
              {t.revoked_at ? <span className="np-badge">revoked</span> : null}
              <div style={{ color: 'var(--np-muted)', fontSize: 12, marginTop: 2 }}>
                scopes: {t.scopes.map((s) => (
                  <code key={s} style={{ marginRight: 6 }}>{s}</code>
                ))}
              </div>
              <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                created {when(t.created_at)} · expires {when(t.expires_at)} · last used {when(t.last_used_at)}
                {t.ip_allowlist.length > 0 && <> · IPs {t.ip_allowlist.join(', ')}</>}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="np-button" onClick={() => void rotate(t)} disabled={busy || !!t.revoked_at}>
                Rotate
              </button>
              <button className="np-button" onClick={() => void revoke(t)} disabled={busy || !!t.revoked_at}>
                Revoke
              </button>
            </div>
          </div>
        ))}
      </div>
    </Shell>
  );
}
