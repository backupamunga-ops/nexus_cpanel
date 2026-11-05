'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, getUser } from '../../lib/api';
import Shell from '../shell';
import { Icon } from '../icons';

/**
 * Job center (B13): every long-running piece of work the panel does,
 * with its live state. Retrying a failed job asks for confirmation and
 * creates a fresh attempt — the old row stays as history.
 */

interface JobDto {
  id: string;
  queue_name: string;
  job_type: string;
  status: string;
  progress: number;
  attempts: number;
  payload: unknown;
  result: unknown;
  created_at: string;
  completed_at: string | null;
}

const STATUS_LABEL: Record<string, string> = {
  waiting: 'queued',
  active: 'running',
  completed: 'done',
  failed: 'failed',
};

function resultNote(j: JobDto): string {
  const r = j.result as { error?: string; error_message?: string } | null;
  if (j.status === 'failed' && r?.error) return String(r.error).slice(0, 140);
  return '';
}

export default function JobsPage() {
  const [jobs, setJobs] = useState<JobDto[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const j = await api<{ data: JobDto[] }>('/jobs');
      setJobs(j.data ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 8000);
    return () => clearInterval(t);
  }, [refresh]);

  async function retry(j: JobDto) {
    if (!window.confirm(`Retry "${j.job_type}"? A new attempt will start now.`)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(`/jobs/${j.id}/retry`, { method: 'POST' });
      setNotice('Retry started — watch its state below.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'retry failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/jobs">
      <div className="np-stack">
        <div className="np-page-head">
          <div>
            <h1 className="np-title">Jobs</h1>
            <p className="lede">
              The panel’s to-do list: scans, backups and other long-running work,
              with live progress. Failed jobs can be retried — the old attempt is
              kept for the record.
            </p>
          </div>
          <span className="np-badge">auto-refreshing</span>
        </div>

        {error && <div className="np-error">{error}</div>}
        {notice && <div className="np-ok">{notice}</div>}

        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="refresh" />
              </span>
              Recent jobs
            </h3>
            <span className="np-badge">{jobs?.length ?? '…'}</span>
          </div>
          {jobs === null ? (
            <p className="np-muted">Loading…</p>
          ) : jobs.length === 0 ? (
            <div className="np-empty">
              Nothing running yet — jobs appear here when a backup, scan or other
              long task is started.
            </div>
          ) : (
            <div className="np-table-wrap">
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Job</th>
                    <th>State</th>
                    <th>Progress</th>
                    <th>Attempts</th>
                    <th>Started</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((j) => (
                    <tr key={j.id}>
                      <td>
                        <b style={{ color: 'var(--np-foreground)', fontSize: 12.5 }}>{j.job_type}</b>
                        {resultNote(j) && (
                          <small style={{ display: 'block', color: 'var(--np-danger)', fontSize: 11 }}>
                            {resultNote(j)}
                          </small>
                        )}
                      </td>
                      <td>
                        <span className={`np-badge ${j.status === 'completed' ? 'ok' : j.status === 'failed' ? 'err' : 'warn'}`}>
                          {STATUS_LABEL[j.status] ?? j.status}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div className="np-mini-bar" style={{ width: 80, height: 5, background: 'var(--np-card-3)', borderRadius: 10, overflow: 'hidden' }}>
                            <div style={{ width: `${j.progress}%`, height: '100%', background: 'linear-gradient(90deg, var(--np-primary), var(--np-primary-2))' }} />
                          </div>
                          <span className="np-mono" style={{ fontSize: 11 }}>{j.progress}%</span>
                        </div>
                      </td>
                      <td className="np-mono">{j.attempts}</td>
                      <td>{new Date(j.created_at).toLocaleString()}</td>
                      <td style={{ textAlign: 'right' }}>
                        {j.status === 'failed' && (
                          <button
                            className="np-button np-button-ghost np-button-sm"
                            disabled={busy}
                            onClick={() => void retry(j)}
                          >
                            Retry
                          </button>
                        )}
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
