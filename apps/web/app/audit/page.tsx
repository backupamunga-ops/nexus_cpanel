'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, getUser } from '../../lib/api';
import Shell from '../shell';
import { Icon } from '../icons';

/**
 * Audit log & chain verification (B13 UI half of C11). Every sensitive
 * action lands here as a hash-chained entry; the verify card re-walks the
 * whole chain on demand and reports exactly where a break starts (the
 * daily cron does the same in the background and alerts on failure).
 */

interface AuditEntry {
  id: string;
  occurred_at: string;
  actor_user_id: string | null;
  operation: string;
  parameters: unknown;
  outcome: string;
  prior_hash?: string;
  this_hash?: string;
}

interface VerifyResult {
  verified: boolean;
  brokenAt: string | null;
  checked: number;
}

function prettyParams(p: unknown): string {
  try {
    const s = JSON.stringify(p);
    return s && s !== '{}' ? s.slice(0, 120) : '';
  } catch {
    return '';
  }
}

export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const a = await api<{ data: AuditEntry[] }>('/audit/entries?limit=60');
      setEntries(a.data ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function runVerify() {
    setVerifying(true);
    setError(null);
    try {
      const v = await api<VerifyResult>('/audit/verify', { method: 'POST' });
      setVerify(v);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'verification failed');
    } finally {
      setVerifying(false);
    }
  }

  return (
    <Shell active="/audit">
      <div className="np-stack">
        <div className="np-page-head">
          <div>
            <h1 className="np-title">Audit log</h1>
            <p className="lede">
              Every sensitive action is recorded here in a tamper-evident chain:
              each entry is cryptographically linked to the one before it, so
              nothing can be quietly edited or removed later.
            </p>
          </div>
          <button className="np-button np-button-ghost" disabled={verifying} onClick={() => void runVerify()}>
            <Icon name="shield" size={14} />
            {verifying ? 'Checking…' : 'Verify chain now'}
          </button>
        </div>

        {error && <div className="np-error">{error}</div>}

        {verify && (
          <section className="np-card">
            <div className="np-card-head" style={{ marginBottom: 6 }}>
              <h3>
                <span className="ico">
                  <Icon name={verify.verified ? 'check' : 'alert'} />
                </span>
                Chain verification
              </h3>
              <span className={`np-badge ${verify.verified ? 'ok' : 'err'}`}>
                {verify.verified ? 'verified' : 'BROKEN'}
              </span>
            </div>
            <p className="np-muted" style={{ fontSize: 12.5 }}>
              {verify.verified
                ? `All ${verify.checked} entries checked — the chain is intact.`
                : `Verification failed at entry ${verify.brokenAt ?? '?'} after ${verify.checked} good entries. Treat this as a security incident: the log may have been edited directly in the database.`}
            </p>
          </section>
        )}

        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="file" />
              </span>
              Recent entries
            </h3>
            <span className="np-badge">{entries?.length ?? '…'}</span>
          </div>
          {entries === null ? (
            <p className="np-muted">Loading…</p>
          ) : entries.length === 0 ? (
            <div className="np-empty">No entries yet.</div>
          ) : (
            <div className="np-table-wrap">
              <table className="np-table">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Action</th>
                    <th>Details</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => (
                    <tr key={e.id}>
                      <td style={{ whiteSpace: 'nowrap' }}>{new Date(e.occurred_at).toLocaleString()}</td>
                      <td className="np-mono" style={{ fontSize: 11.5, color: 'var(--np-foreground)' }}>{e.operation}</td>
                      <td className="np-mono" style={{ fontSize: 11 }}>{prettyParams(e.parameters)}</td>
                      <td>
                        <span className={`np-badge ${e.outcome === 'success' ? 'ok' : 'err'}`}>{e.outcome}</span>
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
