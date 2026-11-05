'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Resellers admin screen (API spec §4.6). Server-Admin only — the server
 * rejects non-super-admins at the PermissionsGuard and the nav item only
 * renders for super admins; this screen is the third gate, not the first.
 *
 * A reseller IS a hosting account granted reseller capability: the grant
 * form picks a live account and (optionally) a parent reseller. Nesting is
 * capped by policy (Decision 3: default 2 levels, RESELLER_MAX_DEPTH) — the
 * server's 400/409 answers are shown verbatim, never hidden. Custom domains
 * (ADR-0003) are set with status 'pending'; C14 keeps sessions bound to the
 * origin they were minted on, so a branded domain never leaks a session to
 * another reseller's panel.
 */

interface ResellerDto {
  id: string;
  hosting_account: { id: string; username: string; status: string };
  parent_reseller_id: string | null;
  depth: number;
  branding: Record<string, unknown>;
  custom_domain: string | null;
  custom_domain_status: string | null;
  created_at: string;
  updated_at: string;
}

interface ManagedAccount {
  id: string;
  username: string;
  status: string;
  my_role?: string;
}

interface BrandingForm {
  brand_name: string;
  primary_color: string;
  accent_color: string;
  logo_url: string;
  login_message: string;
}

const EMPTY_BRANDING: BrandingForm = {
  brand_name: '',
  primary_color: '',
  accent_color: '',
  logo_url: '',
  login_message: '',
};

function brandingToForm(branding: Record<string, unknown>): BrandingForm {
  const str = (k: string): string => {
    const v = branding[k];
    return typeof v === 'string' ? v : '';
  };
  return {
    brand_name: str('brand_name'),
    primary_color: str('primary_color'),
    accent_color: str('accent_color'),
    logo_url: str('logo_url'),
    login_message: str('login_message'),
  };
}

export default function ResellersPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [resellers, setResellers] = useState<ResellerDto[]>([]);
  const [accounts, setAccounts] = useState<ManagedAccount[]>([]);
  const [grantAccount, setGrantAccount] = useState('');
  const [grantParent, setGrantParent] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [branding, setBranding] = useState<BrandingForm>(EMPTY_BRANDING);
  const [domainInput, setDomainInput] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [r, a] = await Promise.all([
        api<{ data: ResellerDto[] }>('/resellers'),
        api<{ data: ManagedAccount[] }>('/accounts'),
      ]);
      setResellers(r.data ?? []);
      setAccounts(a.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const byId = new Map(resellers.map((r) => [r.id, r]));
  const resellerAccountIds = new Set(resellers.map((r) => r.hosting_account.id));
  const grantable = accounts.filter((a) => !resellerAccountIds.has(a.id));

  function openEditor(r: ResellerDto) {
    setEditingId(r.id);
    setBranding(brandingToForm(r.branding));
    setDomainInput(r.custom_domain ?? '');
    setMessage(null);
    setError(null);
  }

  function closeEditor() {
    setEditingId(null);
    setBranding(EMPTY_BRANDING);
    setDomainInput('');
    setError(null);
  }

  async function grant(e: FormEvent) {
    e.preventDefault();
    if (!grantAccount) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<ResellerDto>('/resellers', {
        method: 'POST',
        body: JSON.stringify({
          hosting_account_id: grantAccount,
          ...(grantParent ? { parent_reseller_id: grantParent } : {}),
        }),
      });
      setMessage(
        `reseller granted on “${created.hosting_account.username}” (depth ${created.depth}) — hash-chained audit entry written.`,
      );
      setGrantAccount('');
      setGrantParent('');
      await refresh();
    } catch (err) {
      // Depth-cap 400s and duplicate 409s are informative — show verbatim.
      setError(err instanceof Error ? err.message : 'grant failed');
    } finally {
      setBusy(false);
    }
  }

  async function saveBranding() {
    if (!editingId) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      // FULL replacement (the server stores exactly this object).
      const brandingOut: Record<string, unknown> = {};
      for (const [k, raw] of Object.entries(branding)) {
        const v = raw.trim();
        if (v !== '') brandingOut[k] = v;
      }
      await api(`/resellers/${editingId}/branding`, {
        method: 'PATCH',
        body: JSON.stringify({ branding: brandingOut }),
      });
      setMessage('branding saved — the branded login page reads it on next visit.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'branding save failed');
    } finally {
      setBusy(false);
    }
  }

  async function setDomain() {
    if (!editingId) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const updated = await api<ResellerDto>(`/resellers/${editingId}/custom-domain`, {
        method: 'POST',
        body: JSON.stringify({ custom_domain: domainInput }),
      });
      setMessage(
        `custom domain “${updated.custom_domain}” registered (${updated.custom_domain_status}) — sessions will be isolated per C14 once it activates.`,
      );
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'custom domain failed');
    } finally {
      setBusy(false);
    }
  }

  async function clearDomain(r: ResellerDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/resellers/${r.id}/custom-domain`, { method: 'DELETE' });
      setMessage('custom domain cleared — sessions fall back to panel-kind hosts.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'clear failed');
    } finally {
      setBusy(false);
    }
  }

  async function remove(r: ResellerDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/resellers/${r.id}`, { method: 'DELETE' });
      setMessage(`reseller on “${r.hosting_account.username}” removed (hosting account untouched).`);
      if (editingId === r.id) closeEditor();
      await refresh();
    } catch (err) {
      // 409 with live children is expected and informative — show verbatim.
      setError(err instanceof Error ? err.message : 'delete failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/resellers" user={user}>
      <h1 className="np-title">Resellers</h1>
      <p className="np-subtitle">
        White-label operators (§4.6). A reseller is a hosting account with reseller
        capability; nesting is capped by policy (default 2 levels — RESELLER_MAX_DEPTH).
        Custom panel domains ship in v1.0 (ADR-0003): registration sets the domain to
        “pending”, certificate activation is out-of-band, and C14 keeps every session
        bound to the origin it was created on.
      </p>

      {message && <p role="status" style={{ color: 'var(--np-muted)', marginTop: 12 }}>{message}</p>}
      {error && <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>{error}</p>}

      {/* ── grant form ────────────────────────────────────────────── */}
      <form onSubmit={grant} className="np-card" style={{ marginTop: 20, maxWidth: 720 }}>
        <h2 style={{ marginTop: 0 }}>Grant reseller capability</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <label style={{ display: 'grid', gap: 4, flex: 1, minWidth: 220 }}>
            Hosting account
            <select
              className="np-input"
              value={grantAccount}
              onChange={(e) => setGrantAccount(e.target.value)}
            >
              <option value="">— pick an account —</option>
              {grantable.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.username} ({a.status})
                </option>
              ))}
            </select>
          </label>
          <label style={{ display: 'grid', gap: 4, flex: 1, minWidth: 220 }}>
            Parent reseller (optional)
            <select
              className="np-input"
              value={grantParent}
              onChange={(e) => setGrantParent(e.target.value)}
            >
              <option value="">— none (top level) —</option>
              {resellers.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.hosting_account.username} (depth {r.depth})
                </option>
              ))}
            </select>
          </label>
        </div>
        <div style={{ marginTop: 16 }}>
          <button className="np-button" type="submit" disabled={busy || !grantAccount}>
            {busy ? 'Working…' : 'Grant reseller'}
          </button>
        </div>
      </form>

      {/* ── editor ────────────────────────────────────────────────── */}
      {editingId && byId.get(editingId) && (
        <form
          className="np-card"
          style={{ marginTop: 20, maxWidth: 720 }}
          onSubmit={(e) => {
            e.preventDefault();
            void saveBranding();
          }}
        >
          <h2 style={{ marginTop: 0 }}>
            Customize “{byId.get(editingId)!.hosting_account.username}”
          </h2>
          <label style={{ display: 'block', marginBottom: 10 }}>
            Brand name
            <input
              className="np-input"
              style={{ width: '100%' }}
              value={branding.brand_name}
              maxLength={100}
              onChange={(e) => setBranding((b) => ({ ...b, brand_name: e.target.value }))}
              placeholder="BrandCo Hosting"
            />
          </label>
          <div style={{ display: 'flex', gap: 12 }}>
            <label style={{ display: 'block', marginBottom: 10, flex: 1 }}>
              Primary color
              <input
                className="np-input"
                style={{ width: '100%' }}
                value={branding.primary_color}
                maxLength={7}
                onChange={(e) => setBranding((b) => ({ ...b, primary_color: e.target.value }))}
                placeholder="#0a84ff"
              />
            </label>
            <label style={{ display: 'block', marginBottom: 10, flex: 1 }}>
              Accent color
              <input
                className="np-input"
                style={{ width: '100%' }}
                value={branding.accent_color}
                maxLength={7}
                onChange={(e) => setBranding((b) => ({ ...b, accent_color: e.target.value }))}
                placeholder="#30d158"
              />
            </label>
          </div>
          <label style={{ display: 'block', marginBottom: 10 }}>
            Logo URL (https only)
            <input
              className="np-input"
              style={{ width: '100%' }}
              value={branding.logo_url}
              maxLength={500}
              onChange={(e) => setBranding((b) => ({ ...b, logo_url: e.target.value }))}
              placeholder="https://cdn.brand.example/logo.svg"
            />
          </label>
          <label style={{ display: 'block', marginBottom: 10 }}>
            Login page message
            <input
              className="np-input"
              style={{ width: '100%' }}
              value={branding.login_message}
              maxLength={300}
              onChange={(e) => setBranding((b) => ({ ...b, login_message: e.target.value }))}
              placeholder="Welcome to BrandCo hosting"
            />
          </label>
          <label style={{ display: 'block', marginBottom: 10 }}>
            Custom panel domain
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                className="np-input"
                style={{ width: '100%' }}
                value={domainInput}
                maxLength={253}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="panel.brandco.example"
              />
              <button className="np-button" type="button" onClick={() => void setDomain()} disabled={busy}>
                Set
              </button>
              {byId.get(editingId)!.custom_domain && (
                <button
                  className="np-button"
                  type="button"
                  onClick={() => void clearDomain(byId.get(editingId)!)}
                  disabled={busy}
                >
                  Clear
                </button>
              )}
            </div>
          </label>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="np-button" type="submit" disabled={busy}>
              {busy ? 'Saving…' : 'Save branding'}
            </button>
            <button className="np-button" type="button" onClick={closeEditor} disabled={busy}>
              Close
            </button>
          </div>
        </form>
      )}

      {/* ── list ──────────────────────────────────────────────────── */}
      <div style={{ marginTop: 24, display: 'grid', gap: 12 }}>
        {resellers.length === 0 && (
          <p style={{ color: 'var(--np-muted)' }}>No resellers yet — grant capability to a hosting account above.</p>
        )}
        {resellers.map((r) => {
          const parent = r.parent_reseller_id ? byId.get(r.parent_reseller_id) : null;
          return (
            <div
              key={r.id}
              className="np-card"
              style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}
            >
              <div>
                <strong>{r.hosting_account.username}</strong>{' '}
                <span className="np-badge">depth {r.depth}</span>
                {r.custom_domain && (
                  <span className="np-badge">
                    {' '}
                    {r.custom_domain} · {r.custom_domain_status}
                  </span>
                )}
                <div style={{ color: 'var(--np-muted)', fontSize: 12, marginTop: 2 }}>
                  {parent
                    ? `under ${parent.hosting_account.username}`
                    : 'top level'}
                  {' · '}
                  account {r.hosting_account.status}
                </div>
                <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                  {typeof r.branding['brand_name'] === 'string'
                    ? `brand “${r.branding['brand_name'] as string}”`
                    : 'no branding set'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="np-button" onClick={() => openEditor(r)} disabled={busy}>
                  Customize
                </button>
                <button className="np-button" onClick={() => void remove(r)} disabled={busy}>
                  Remove
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </Shell>
  );
}
