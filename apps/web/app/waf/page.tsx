'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser } from '../../lib/api';
import Shell from '../shell';
import { Icon } from '../icons';

/**
 * Threat protection (API spec §4.15a, ADR-0017) — B12.
 *
 * One screen for the two per-site defenses: the web application firewall
 * (ModSecurity posture per site) and virus scanning (ClamAV with a
 * quarantine model). Modes are spelled out in plain language; when the
 * agent is unreachable the cards say so (D-11). Quarantine delete asks for
 * confirmation — it destroys the artifact for good.
 */

interface WafPolicy {
  domain_id: string;
  domain: string;
  account_username: string;
  mode: string;
  paranoia_level: number;
  exclusions: string[];
  updated_at: string;
}

interface ScanDto {
  id: string;
  scope: string;
  scope_path: string;
  status: string;
  infected_count: number;
  quarantined_count: number;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
}

interface QuarantineEntry {
  id: string;
  file_path: string;
  signature: string;
  quarantine_path: string | null;
  quarantined_at: string;
}

const MODE_HELP: Record<string, string> = {
  off: 'WAF is not filtering this site.',
  detect: 'Suspicious requests are logged but still go through.',
  block: 'Suspicious requests are stopped before they reach the site.',
};

export default function WafPage() {
  const [policies, setPolicies] = useState<WafPolicy[] | null>(null);
  const [scans, setScans] = useState<ScanDto[] | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanScope, setScanScope] = useState('account');
  const [scanAccount, setScanAccount] = useState('');
  const [accounts, setAccounts] = useState<Array<{ id: string; username: string }>>([]);

  useEffect(() => {
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [p, s, q, a] = await Promise.all([
        api<{ data: WafPolicy[] }>('/security/modsecurity'),
        api<{ data: ScanDto[] }>('/security/malware/scans'),
        api<{ data: QuarantineEntry[] }>('/security/malware/quarantine'),
        api<{ data: Array<{ id: string; username: string }> }>('/accounts'),
      ]);
      setPolicies(p.data ?? []);
      setScans(s.data ?? []);
      setQuarantine(q.data ?? []);
      setAccounts(a.data ?? []);
      setScanAccount((cur) => cur || a.data?.[0]?.id || '');
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function setMode(policy: WafPolicy, mode: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(`/security/modsecurity/${policy.domain_id}`, {
        method: 'PATCH',
        body: JSON.stringify({ mode, paranoia_level: policy.paranoia_level }),
      });
      setNotice(`${policy.domain}: ${MODE_HELP[mode]}`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not change WAF mode');
    } finally {
      setBusy(false);
    }
  }

  async function startScan(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice('Scan running on the node — this can take a while…');
    try {
      await api('/security/malware/scan', {
        method: 'POST',
        body: JSON.stringify({ scope: scanScope, account_id: scanScope === 'account' ? scanAccount : undefined }),
      });
      setNotice('Scan finished.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'scan failed');
    } finally {
      setNotice(null);
      setBusy(false);
    }
  }

  async function deleteQuarantine(entry: QuarantineEntry) {
    if (!window.confirm(`Permanently delete the infected file\n${entry.file_path}\nfrom quarantine? This cannot be undone.`)) {
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(`/security/malware/quarantine/${entry.id}`, { method: 'DELETE' });
      setNotice('Infected file destroyed.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'delete failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/waf">
      <div className="np-stack">
        <div className="np-page-head">
          <div>
            <h1 className="np-title">Threat protection</h1>
            <p className="lede">
              Two shields for every website here: a web application firewall that
              filters suspicious requests, and a virus scanner that locks infected
              files away in quarantine — nothing is ever deleted without you saying so.
            </p>
          </div>
        </div>

        {error && <div className="np-error">{error}</div>}
        {notice && <div className="np-ok">{notice}</div>}

        {/* ---- WAF cards ---- */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="shield" />
              </span>
              Web application firewall
            </h3>
            <span className="np-badge">{policies?.length ?? '…'} sites</span>
          </div>
          {policies === null ? (
            <p className="np-muted">Loading…</p>
          ) : policies.length === 0 ? (
            <div className="np-empty">No websites yet — add one on the Websites page first.</div>
          ) : (
            <div style={{ display: 'grid', gap: 12, gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
              {policies.map((p) => (
                <div key={p.domain_id} className="np-card" style={{ background: 'var(--np-card-2)', marginBottom: 0 }}>
                  <div className="np-card-head" style={{ marginBottom: 8 }}>
                    <h3 style={{ fontSize: 13 }}>{p.domain}</h3>
                    <span className={`np-badge ${p.mode === 'block' ? 'ok' : p.mode === 'detect' ? 'warn' : ''}`}>
                      {p.mode === 'block' ? 'blocking' : p.mode === 'detect' ? 'watching' : 'off'}
                    </span>
                  </div>
                  <p className="np-muted" style={{ fontSize: 11.5, marginBottom: 10 }}>{MODE_HELP[p.mode]}</p>
                  <div className="np-row" style={{ gap: 6 }}>
                    {(['off', 'detect', 'block'] as const).map((m) => (
                      <button
                        key={m}
                        className={`np-button np-button-sm ${p.mode === m ? '' : 'np-button-ghost'}`}
                        disabled={busy || p.mode === m}
                        onClick={() => void setMode(p, m)}
                        title={MODE_HELP[m]}
                      >
                        {m === 'off' ? 'Turn off' : m === 'detect' ? 'Watch' : 'Block'}
                      </button>
                    ))}
                  </div>
                  {p.exclusions.length > 0 && (
                    <p className="np-muted" style={{ fontSize: 10.5, marginTop: 8 }}>
                      {p.exclusions.length} rule exclusion{p.exclusions.length === 1 ? '' : 's'}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ---- Scan center ---- */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="search" />
              </span>
              Virus scans (ClamAV)
            </h3>
          </div>
          <form className="np-form" onSubmit={startScan}>
            <div className="np-row" style={{ alignItems: 'flex-end' }}>
              <div className="np-field" style={{ minWidth: 180 }}>
                <label htmlFor="scan-scope">What to scan</label>
                <select
                  id="scan-scope"
                  className="np-input np-select"
                  value={scanScope}
                  onChange={(e) => setScanScope(e.target.value)}
                >
                  <option value="account">A hosting account’s files</option>
                  <option value="server">The whole server</option>
                </select>
              </div>
              {scanScope === 'account' && (
                <div className="np-field" style={{ minWidth: 180 }}>
                  <label htmlFor="scan-account">Account</label>
                  <select
                    id="scan-account"
                    className="np-input np-select"
                    value={scanAccount}
                    onChange={(e) => setScanAccount(e.target.value)}
                  >
                    {accounts.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.username}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <button className="np-button" disabled={busy}>
                {busy ? 'Scanning…' : 'Start scan'}
              </button>
              <span className="np-hint">
                Infected files are moved to quarantine automatically — never deleted outright.
              </span>
            </div>
          </form>

          {scans !== null && scans.length > 0 && (
            <div className="np-table-wrap" style={{ marginTop: 14 }}>
              <table className="np-table">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Scope</th>
                    <th>Result</th>
                    <th>Infected</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.slice(0, 8).map((s) => (
                    <tr key={s.id}>
                      <td>{new Date(s.started_at).toLocaleString()}</td>
                      <td>{s.scope}</td>
                      <td>
                        <span className={`np-badge ${s.status === 'success' ? (s.infected_count > 0 ? 'warn' : 'ok') : 'err'}`}>
                          {s.status === 'success' ? (s.infected_count > 0 ? `${s.infected_count} infected` : 'clean') : s.status}
                        </span>
                      </td>
                      <td className="np-mono">{s.quarantined_count} quarantined</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ---- Quarantine ---- */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="lock" />
              </span>
              Quarantine
            </h3>
            <span className="np-badge">{quarantine?.length ?? '…'}</span>
          </div>
          {quarantine === null ? (
            <p className="np-muted">Loading…</p>
          ) : quarantine.length === 0 ? (
            <div className="np-empty">Nothing in quarantine — either scans are clean or nothing was flagged yet.</div>
          ) : (
            <div className="np-table-wrap">
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Original file</th>
                    <th>Detected as</th>
                    <th>Since</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {quarantine.map((q) => (
                    <tr key={q.id}>
                      <td className="np-mono" style={{ fontSize: 11.5 }}>{q.file_path}</td>
                      <td><span className="np-badge err">{q.signature}</span></td>
                      <td>{new Date(q.quarantined_at).toLocaleString()}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="np-button np-button-danger np-button-sm"
                          disabled={busy}
                          onClick={() => void deleteQuarantine(q)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="np-muted" style={{ fontSize: 11.5, marginTop: 10 }}>
            Deleted files are gone for good. Restoring a file back into a website is possible on
            request (it is audited like every other action).
          </p>
        </section>
      </div>
    </Shell>
  );
}
