'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Server settings screen (P2) — admin-editable platform configuration.
 * Server-Admin only: the server rejects non-super-admins at the
 * PermissionsGuard, the nav item renders only for super admins, and this
 * screen is the third gate (defense in depth), not the first.
 *
 * The form is GENERATED from the server's whitelist (GET /settings returns
 * each definition's type, bounds, default and enforced flag), so the UI can
 * never offer an input the API would reject. Fail-closed 400 details are
 * shown verbatim. `enforced: false` settings carry an explicit
 * "stored — not yet enforced" badge: the value is validated and audited
 * today, and the runtime seam that reads it lands incrementally (D-11).
 * Unknown keys are impossible to enter — there is no free-form key field.
 */

interface SettingDto {
  key: string;
  category: string;
  label: string;
  description: string;
  type: string;
  value: string | number | boolean;
  default: string | number | boolean;
  min: number | null;
  max: number | null;
  min_length: number | null;
  max_length: number | null;
  enforced: boolean;
  updated_at: string | null;
  updated_by: string | null;
}

const CATEGORY_HEADINGS: Record<string, { title: string; blurb: string }> = {
  platform: { title: 'Platform', blurb: 'Naming and surface text for this installation.' },
  security: {
    title: 'Security',
    blurb: 'Lockout, password and session policy. Values are audited on every change; enforcement seams land incrementally (D-11).',
  },
  audit: { title: 'Audit', blurb: 'Retention of the hash-chained audit trail (C11).' },
};

const CATEGORY_ORDER = ['platform', 'security', 'audit'];

/** Local edit state, keyed by setting key. Undefined = untouched (shows server value). */
type Drafts = Record<string, string | number | boolean | undefined>;

export default function ServerSettingsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [settings, setSettings] = useState<SettingDto[]>([]);
  const [drafts, setDrafts] = useState<Drafts>({});
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const j = await api<{ data: SettingDto[] }>('/settings');
      setSettings(j.data ?? []);
      setDrafts({});
      setLoaded(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const grouped = useMemo(() => {
    const byCategory = new Map<string, SettingDto[]>();
    for (const s of settings) {
      const list = byCategory.get(s.category) ?? [];
      list.push(s);
      byCategory.set(s.category, list);
    }
    return CATEGORY_ORDER.filter((c) => byCategory.has(c)).map((c) => ({
      category: c,
      items: byCategory.get(c) ?? [],
    }));
  }, [settings]);

  function draftValue(s: SettingDto): string | number | boolean {
    const d = drafts[s.key];
    return d === undefined ? s.value : d;
  }

  function setDraft(s: SettingDto, raw: string) {
    // Keep integers as strings while typing; parse on submit (mirrors the
    // packages quota editor — never mid-type coercion).
    const next: string | number | boolean =
      s.type === 'integer' ? raw : s.type === 'boolean' ? raw === 'true' : raw;
    setDrafts((prev) => ({ ...prev, [s.key]: next }));
  }

  async function save(s: SettingDto, value: string | number | boolean) {
    setBusyKey(s.key);
    setMessage(null);
    setError(null);
    try {
      const payload = s.type === 'integer' ? Number(value) : value;
      const updated = await api<SettingDto>(`/settings/${encodeURIComponent(s.key)}`, {
        method: 'PUT',
        body: JSON.stringify({ value: payload }),
      });
      setSettings((prev) => prev.map((x) => (x.key === updated.key ? updated : x)));
      setDrafts((prev) => {
        const next = { ...prev };
        delete next[s.key];
        return next;
      });
      setMessage(
        updated.enforced
          ? `“${updated.label}” saved — change hash-chained into the audit log and live immediately.`
          : `“${updated.label}” saved — change hash-chained into the audit log (stored; enforcement wiring pending).`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'save failed');
    } finally {
      setBusyKey(null);
    }
  }

  async function resetToDefault(s: SettingDto) {
    await save(s, s.default);
  }

  const dirty = (s: SettingDto): boolean => {
    const d = drafts[s.key];
    if (d === undefined) return false;
    return String(d) !== String(s.value);
  };

  return (
    <Shell active="/server-settings" user={user}>
      <h1 className="np-title">Server settings</h1>
      <p className="np-subtitle">
        Platform-wide configuration. The editable set is a server-owned
        whitelist — unknown keys cannot exist, values are type- and
        bound-checked fail-closed, and every change is hash-chained into the
        audit log with the acting admin&apos;s identity.
      </p>

      {user && !user.is_super_admin && (
        <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>
          Server-Admin only. The control plane rejects non-super-admin requests
          at the permission guard.
        </p>
      )}

      {message && (
        <p role="status" style={{ color: 'var(--np-muted)', marginTop: 12 }}>
          {message}
        </p>
      )}
      {error && (
        <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>
          {error}
        </p>
      )}

      {loaded && settings.length === 0 && (
        <p style={{ color: 'var(--np-muted)', marginTop: 12 }}>
          No settings returned — the catalog is empty on this build.
        </p>
      )}

      {grouped.map(({ category, items }) => {
        const head = CATEGORY_HEADINGS[category] ?? { title: category, blurb: '' };
        return (
          <section key={category} style={{ marginTop: 28 }}>
            <h2>{head.title}</h2>
            <p style={{ color: 'var(--np-muted)', fontSize: 13, marginTop: -4 }}>{head.blurb}</p>
            {items.map((s) => (
              <div
                key={s.key}
                className="np-card"
                style={{ marginTop: 14, maxWidth: 640, padding: '14px 18px' }}
              >
                <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
                  <label htmlFor={`set-${s.key}`} style={{ fontWeight: 600 }}>
                    {s.label}
                  </label>
                  <span className="np-badge">{s.type}</span>
                  {s.enforced ? (
                    <span className="np-badge" style={{ color: 'var(--np-success)' }}>
                      enforced
                    </span>
                  ) : (
                    <span
                      className="np-badge"
                      style={{ color: 'var(--np-warning)' }}
                      title="Value is stored, validated and audited; the runtime seam that reads it has not landed yet."
                    >
                      stored — not yet enforced
                    </span>
                  )}
                  {s.value !== s.default && (
                    <span className="np-badge" title="A stored override exists for this key.">
                      modified
                    </span>
                  )}
                </div>
                <p style={{ color: 'var(--np-muted)', fontSize: 13, margin: '6px 0 10px' }}>
                  {s.description}
                </p>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  {s.type === 'boolean' ? (
                    <select
                      id={`set-${s.key}`}
                      className="np-input"
                      style={{ maxWidth: 140 }}
                      value={draftValue(s) ? 'true' : 'false'}
                      onChange={(e) => setDraft(s, e.target.value)}
                      disabled={busyKey === s.key}
                    >
                      <option value="false">false</option>
                      <option value="true">true</option>
                    </select>
                  ) : s.type === 'integer' ? (
                    <input
                      id={`set-${s.key}`}
                      className="np-input"
                      type="number"
                      inputMode="numeric"
                      style={{ maxWidth: 140 }}
                      value={String(draftValue(s))}
                      min={s.min ?? undefined}
                      max={s.max ?? undefined}
                      step={1}
                      onChange={(e) => setDraft(s, e.target.value)}
                      disabled={busyKey === s.key}
                    />
                  ) : (
                    <input
                      id={`set-${s.key}`}
                      className="np-input"
                      type="text"
                      style={{ maxWidth: 340 }}
                      value={String(draftValue(s))}
                      maxLength={s.max_length ?? undefined}
                      onChange={(e) => setDraft(s, e.target.value)}
                      disabled={busyKey === s.key}
                    />
                  )}
                  <button
                    className="np-button"
                    type="button"
                    disabled={busyKey === s.key || !dirty(s)}
                    onClick={() => void save(s, draftValue(s))}
                  >
                    {busyKey === s.key ? 'Saving…' : 'Save'}
                  </button>
                  {s.value !== s.default && (
                    <button
                      className="np-button"
                      type="button"
                      disabled={busyKey === s.key}
                      onClick={() => void resetToDefault(s)}
                      title={`Default: ${String(s.default)}`}
                    >
                      Reset to default
                    </button>
                  )}
                </div>
                <p style={{ color: 'var(--np-muted)', fontSize: 11, margin: '8px 0 0' }}>
                  <code>{s.key}</code>
                  {' · '}
                  {s.updated_at
                    ? `last changed ${new Date(s.updated_at).toLocaleString()}`
                    : 'never changed (default)'}
                </p>
              </div>
            ))}
          </section>
        );
      })}
    </Shell>
  );
}
