'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Packages admin screen (API spec §4.5). Server-Admin only — the server
 * rejects non-super-admins at the PermissionsGuard, and the nav item only
 * renders for super admins; this screen is the third gate (defense in
 * depth), not the first.
 *
 * Fail-closed validation is server-owned: unknown quota keys are REJECTED
 * (a typo'd key would silently enforce nothing), cpu has 0.1-core
 * granularity, values are positive and capped. Deletes are SOFT and refused
 * with 409 while live accounts reference the package — that error is shown
 * verbatim, never hidden.
 */

interface QuotaSet {
  cpu?: number;
  mem_mb?: number;
  disk_mb?: number;
  inodes?: number;
  processes?: number;
}

interface PackageDto {
  id: string;
  name: string;
  description: string | null;
  quotas: QuotaSet;
  features: Record<string, boolean>;
  php_versions: string[];
  isolation_profile: string;
  over_quota_policy: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

const QUOTA_FIELDS: Array<{ key: keyof QuotaSet; label: string; hint: string }> = [
  { key: 'cpu', label: 'CPU (cores)', hint: '0.1 granularity, ≤ 64' },
  { key: 'mem_mb', label: 'Memory (MiB)', hint: '≤ 1048576 (1 TiB)' },
  { key: 'disk_mb', label: 'Disk (MiB)', hint: '≤ 10485760 (10 TiB)' },
  { key: 'inodes', label: 'Inodes', hint: 'file count' },
  { key: 'processes', label: 'Processes', hint: '≤ 4096' },
];

// 8.5 = distro PHP on Ubuntu 26.04 (ondrej/php has no resolute dist yet).
const PHP_VERSIONS = ['8.1', '8.2', '8.3', '8.4', '8.5'];
const POLICIES = ['alert', 'throttle', 'suspend'];

interface FeatureRow {
  key: string;
  value: boolean;
}

interface FormState {
  id: string | null; // null = create
  name: string;
  description: string;
  quotas: Partial<Record<keyof QuotaSet, string>>; // raw strings; parse on submit
  features: FeatureRow[];
  php: Set<string>;
  over_quota_policy: string;
  is_active: boolean;
}

const EMPTY_FORM: FormState = {
  id: null,
  name: '',
  description: '',
  quotas: {},
  features: [],
  php: new Set(),
  over_quota_policy: 'alert',
  is_active: true,
};

function quotaSummary(q: QuotaSet): string {
  const parts: string[] = [];
  if (q.cpu !== undefined) parts.push(`${q.cpu} core`);
  if (q.mem_mb !== undefined) parts.push(`${q.mem_mb} MiB mem`);
  if (q.disk_mb !== undefined) parts.push(`${q.disk_mb} MiB disk`);
  if (q.inodes !== undefined) parts.push(`${q.inodes} inodes`);
  if (q.processes !== undefined) parts.push(`${q.processes} procs`);
  return parts.length > 0 ? parts.join(' · ') : 'no quotas set';
}

export default function PackagesPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [packages, setPackages] = useState<PackageDto[]>([]);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
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
      const j = await api<{ data: PackageDto[] }>('/packages');
      setPackages(j.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  function edit(p: PackageDto) {
    setForm({
      id: p.id,
      name: p.name,
      description: p.description ?? '',
      quotas: Object.fromEntries(
        Object.entries(p.quotas).map(([k, v]) => [k, String(v)]),
      ) as FormState['quotas'],
      features: Object.entries(p.features).map(([key, value]) => ({ key, value })),
      php: new Set(p.php_versions),
      over_quota_policy: p.over_quota_policy,
      is_active: p.is_active,
    });
    setMessage(null);
    setError(null);
  }

  function reset() {
    setForm(EMPTY_FORM);
    setError(null);
  }

  function setQuota(key: keyof QuotaSet, raw: string) {
    setForm((f) => ({ ...f, quotas: { ...f.quotas, [key]: raw } }));
  }

  function addFeature() {
    setForm((f) => ({ ...f, features: [...f.features, { key: '', value: true }] }));
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    void doSubmit();
  }

  async function doSubmit() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      // Quotas: send only the keys with a value (partial set — server merges
      // nothing; create treats missing keys as "no quota for that key").
      const quotas: Record<string, number> = {};
      for (const [k, raw] of Object.entries(form.quotas)) {
        if (raw !== undefined && raw.trim() !== '') {
          const n = Number(raw);
          if (!Number.isFinite(n)) {
            throw new Error(`quota '${k}': not a number`);
          }
          quotas[k] = n;
        }
      }
      const features = Object.fromEntries(
        form.features
          .map((r) => ({ ...r, key: r.key.trim() }))
          .filter((r) => r.key.length > 0)
          .map((r) => [r.key, r.value]),
      );
      const body = {
        name: form.name,
        ...(form.description.trim() ? { description: form.description } : { description: null }),
        ...(Object.keys(quotas).length > 0 ? { quotas } : {}),
        features,
        php_versions: [...form.php],
        over_quota_policy: form.over_quota_policy,
        is_active: form.is_active,
      };
      if (form.id === null) {
        const created = await api<PackageDto>('/packages', {
          method: 'POST',
          body: JSON.stringify(body),
        });
        setMessage(`package “${created.name}” created.`);
      } else {
        const updated = await api<PackageDto>(`/packages/${form.id}`, {
          method: 'PATCH',
          body: JSON.stringify(body),
        });
        setMessage(`package “${updated.name}” updated — change hash-chained.`);
      }
      reset();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'save failed');
    } finally {
      setBusy(false);
    }
  }

  async function remove(p: PackageDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/packages/${p.id}`, { method: 'DELETE' });
      setMessage(`package “${p.name}” soft-deleted (history retained).`);
      await refresh();
    } catch (err) {
      // 409 with live references is EXPECTED and informative — show verbatim.
      setError(err instanceof Error ? err.message : 'delete failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/packages" user={user}>
      <h1 className="np-title">Packages</h1>
      <p className="np-subtitle">
        Resource templates for hosting accounts (§4.5). Quotas are enforced by the
        agent as cgroup v2 limits; unknown quota keys are rejected, not ignored.
        Package deletes are soft and refused while accounts still reference them.
      </p>

      {message && <p role="status" style={{ color: 'var(--np-muted)', marginTop: 12 }}>{message}</p>}
      {error && <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>{error}</p>}

      {/* ── editor ────────────────────────────────────────────────── */}
      <form onSubmit={submit} className="np-card" style={{ marginTop: 20, maxWidth: 640 }}>
        <h2 style={{ marginTop: 0 }}>{form.id === null ? 'New package' : `Edit package`}</h2>
        <label htmlFor="pkg-name" style={{ display: 'block', marginBottom: 4 }}>Name</label>
        <input
          id="pkg-name"
          className="np-input"
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          placeholder="Standard"
          required
          maxLength={100}
        />
        <label htmlFor="pkg-desc" style={{ display: 'block', margin: '12px 0 4px' }}>
          Description (optional)
        </label>
        <input
          id="pkg-desc"
          className="np-input"
          value={form.description}
          onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
          maxLength={500}
        />

        <fieldset style={{ border: 'none', padding: 0, margin: '16px 0 0' }}>
          <legend style={{ padding: 0, marginBottom: 6 }}>Quotas (leave blank = unset)</legend>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {QUOTA_FIELDS.map((q) => (
              <label key={q.key} style={{ display: 'block', fontSize: 13 }}>
                {q.label}
                <input
                  className="np-input"
                  style={{ marginTop: 2 }}
                  type="number"
                  step={q.key === 'cpu' ? '0.1' : '1'}
                  min="0"
                  value={form.quotas[q.key] ?? ''}
                  onChange={(e) => setQuota(q.key, e.target.value)}
                  placeholder={q.hint}
                />
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset style={{ border: 'none', padding: 0, margin: '16px 0 0' }}>
          <legend style={{ padding: 0, marginBottom: 6 }}>Features</legend>
          {form.features.map((row, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
              <input
                className="np-input"
                value={row.key}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    features: f.features.map((r, j) => (j === i ? { ...r, key: e.target.value } : r)),
                  }))
                }
                placeholder="feature_key"
                pattern="[a-z0-9_]*"
                maxLength={64}
                style={{ maxWidth: 220 }}
                aria-label={`Feature ${i + 1} key`}
              />
              <label style={{ fontSize: 13, display: 'flex', gap: 4, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={row.value}
                  onChange={(e) =>
                    setForm((f) => ({
                      ...f,
                      features: f.features.map((r, j) => (j === i ? { ...r, value: e.target.checked } : r)),
                    }))
                  }
                />
                enabled
              </label>
              <button
                className="np-button"
                type="button"
                style={{ padding: '2px 8px', fontSize: 11 }}
                onClick={() => setForm((f) => ({ ...f, features: f.features.filter((_, j) => j !== i) }))}
              >
                Remove
              </button>
            </div>
          ))}
          <button className="np-button" type="button" style={{ padding: '2px 10px', fontSize: 12 }} onClick={addFeature}>
            + Add feature
          </button>
        </fieldset>

        <fieldset style={{ border: 'none', padding: 0, margin: '16px 0 0' }}>
          <legend style={{ padding: 0, marginBottom: 6 }}>PHP versions offered</legend>
          <div style={{ display: 'flex', gap: 12 }}>
            {PHP_VERSIONS.map((v) => (
              <label key={v} style={{ fontSize: 13, display: 'flex', gap: 4, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={form.php.has(v)}
                  onChange={() =>
                    setForm((f) => {
                      const next = new Set(f.php);
                      if (next.has(v)) next.delete(v);
                      else next.add(v);
                      return { ...f, php: next };
                    })
                  }
                />
                {v}
              </label>
            ))}
          </div>
        </fieldset>

        <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginTop: 16 }}>
          <label style={{ fontSize: 13, display: 'flex', gap: 6, alignItems: 'center' }}>
            Over-quota policy
            <select
              className="np-input"
              style={{ width: 'auto' }}
              value={form.over_quota_policy}
              onChange={(e) => setForm((f) => ({ ...f, over_quota_policy: e.target.value }))}
            >
              {POLICIES.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </label>
          <label style={{ fontSize: 13, display: 'flex', gap: 6, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(e) => setForm((f) => ({ ...f, is_active: e.target.checked }))}
            />
            active (assignable to new accounts)
          </label>
          <span className="np-badge">isolation: standard</span>
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
          <button className="np-button" type="submit" disabled={busy}>
            {busy ? 'Saving…' : form.id === null ? 'Create package' : 'Save changes'}
          </button>
          {form.id !== null && (
            <button className="np-button" type="button" onClick={reset} disabled={busy}>
              Cancel edit
            </button>
          )}
        </div>
      </form>

      {/* ── list ──────────────────────────────────────────────────── */}
      <div style={{ marginTop: 24, display: 'grid', gap: 12 }}>
        {packages.length === 0 && (
          <p style={{ color: 'var(--np-muted)' }}>No packages yet.</p>
        )}
        {packages.map((p) => (
          <div
            key={p.id}
            className="np-card"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}
          >
            <div>
              <strong>{p.name}</strong>{' '}
              {!p.is_active && <span className="np-badge">inactive</span>}
              <div style={{ color: 'var(--np-muted)', fontSize: 12, marginTop: 2 }}>
                {quotaSummary(p.quotas)} · policy {p.over_quota_policy}
              </div>
              <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>
                php {p.php_versions.length > 0 ? p.php_versions.join(', ') : '—'}
                {Object.keys(p.features).length > 0 && (
                  <> · features {Object.keys(p.features).join(', ')}</>
                )}
              </div>
              {p.description && (
                <div style={{ color: 'var(--np-muted)', fontSize: 12 }}>{p.description}</div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="np-button" onClick={() => edit(p)} disabled={busy}>
                Edit
              </button>
              <button className="np-button" onClick={() => void remove(p)} disabled={busy}>
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </Shell>
  );
}
