'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Migration Center (B15, §4.21 / M15) — "Move a website from cPanel".
 *
 * Built for non-technical users (DirectAdmin-simple): one artifact, one
 * target account, four plain steps — Look inside → Show the plan → Move it
 * → The report. The honest part stays honest in plain words: every entity
 * wears a verdict (verified byte-for-byte / created fresh / skipped with a
 * reason), a migration with ANY failed check says "failed" — it never
 * dresses up as partially done — and mailbox/database passwords are never
 * carried over: users get fresh ones and reset them in the panel.
 */

interface EntityRow {
  id: string;
  entity_type: string;
  source_id: string;
  target_id: string | null;
  status: string;
  checksum_source: string | null;
  checksum_target: string | null;
  checksum_parity: boolean | null;
  notes: string | null;
}

interface JobDto {
  id: string;
  source_platform: string;
  source_identifier: string;
  source_username: string | null;
  target_account_id: string | null;
  target_account_domain: string | null;
  status: string;
  artifact_sha256: string | null;
  entity_count: number | null;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
}

interface ReportDto {
  migration_job_id: string;
  status: string;
  source: { platform: string; artifact: string; username: string | null };
  target: { account_id: string; username: string };
  totals: Record<string, number>;
  entities: Array<{
    entity_type: string;
    source_id: string;
    target_id: string | null;
    status: string;
    checksum_source: string | null;
    checksum_target: string | null;
    checksum_parity: boolean | null;
    notes: string | null;
  }>;
  cutover: {
    note: string;
    zones: Array<{ zone: string; records: Array<{ name: string; type: string; content: string; ttl: number }>; rollback_note: string }>;
  };
}

interface AccountOption {
  id: string;
  username: string;
}

interface ArtifactOption {
  name: string;
  size_bytes: number;
  sha256: string;
}

/** Plain words for entity types — the report speaks human, not schema. */
const ENTITY_LABELS: Record<string, string> = {
  files: 'Website files',
  dns_zone: 'DNS zone',
  mail_domain: 'Email domain',
  mailbox: 'Mailbox',
  database: 'Database',
  ssl: 'SSL certificate',
  cron: 'Scheduled tasks (cron)',
};

const ENTITY_ORDER = ['files', 'dns_zone', 'mail_domain', 'mailbox', 'database', 'ssl', 'cron'];

function statusBadge(status: string) {
  const map: Record<string, { color: string; label: string; title: string }> = {
    verified: { color: 'var(--np-success)', label: 'verified', title: 'Checked byte-for-byte against the source archive.' },
    imported: { color: 'var(--np-warning)', label: 'imported', title: 'Brought over — the verification pass re-checks it at the end.' },
    imported_plain: { color: 'var(--np-warning)', label: 'created', title: 'Created fresh through the panel (no file checksum exists).' },
    failed: { color: 'var(--np-danger, #ef4444)', label: 'failed', title: 'This item did not make it — the report shows exactly why.' },
    skipped: { color: 'inherit', label: 'skipped', title: 'Deliberately not moved, with a reason — never silently dropped.' },
    pending: { color: 'inherit', label: 'waiting', title: 'Queued for the next move.' },
    importing: { color: 'inherit', label: 'moving…', title: 'Being moved right now.' },
  };
  const meta = map[status] ?? { color: 'inherit', label: status, title: '' };
  return (
    <span className="np-badge" style={{ color: meta.color }} title={meta.title}>
      {meta.label}
    </span>
  );
}

function jobStatusBadge(status: string) {
  const map: Record<string, { color: string; label: string }> = {
    analyzed: { color: 'inherit', label: 'looked inside' },
    planned: { color: 'inherit', label: 'plan ready' },
    importing: { color: 'var(--np-warning)', label: 'moving…' },
    verifying: { color: 'var(--np-warning)', label: 'checking…' },
    completed: { color: 'var(--np-success)', label: 'done — everything verified' },
    failed: { color: 'var(--np-danger, #ef4444)', label: 'failed — see the report' },
    canceled: { color: 'inherit', label: 'canceled' },
  };
  const meta = map[status] ?? { color: 'inherit', label: status };
  return (
    <span className="np-badge" style={{ color: meta.color }}>
      {meta.label}
    </span>
  );
}

function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function sortEntities(rows: EntityRow[]): EntityRow[] {
  return [...rows].sort(
    (a, b) =>
      (ENTITY_ORDER.indexOf(a.entity_type) + 1 || 99) - (ENTITY_ORDER.indexOf(b.entity_type) + 1 || 99) ||
      a.source_id.localeCompare(b.source_id),
  );
}

/** The one obvious next action per job state (DirectAdmin rule: no dead ends). */
function nextAction(job: JobDto): { label: string; phase: 'dry-run' | 'execute' | 'report' } | null {
  if (job.status === 'analyzed') return { label: 'Show the plan', phase: 'dry-run' };
  if (job.status === 'planned') return { label: 'Move everything now', phase: 'execute' };
  if (job.status === 'failed') return { label: 'Resume the move', phase: 'execute' };
  if (['completed', 'importing', 'verifying'].includes(job.status)) return { label: 'Open the report', phase: 'report' };
  return null;
}

export default function MigrationsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [jobs, setJobs] = useState<JobDto[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactOption[]>([]);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [selected, setSelected] = useState<JobDto | null>(null);
  const [detail, setDetail] = useState<{ entities: EntityRow[] } | null>(null);
  const [report, setReport] = useState<ReportDto | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // new-migration form
  const [artifact, setArtifact] = useState('');
  const [accountId, setAccountId] = useState('');

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [j, a] = await Promise.all([api<{ data: JobDto[] }>('/migrations'), api<{ data: AccountOption[] }>('/accounts')]);
      setJobs(j.data ?? []);
      setAccounts(a.data ?? []);
      setAccountId((cur) => cur || a.data?.[0]?.id || '');
      // Artifacts are agent-side; a missing agent just means an empty picker.
      try {
        const list = await api<{ artifacts: ArtifactOption[] }>('/migrations/artifacts').catch(() => ({ artifacts: [] as ArtifactOption[] }));
        setArtifacts(list.artifacts ?? []);
        setArtifact((cur) => cur || list.artifacts?.[0]?.name || '');
      } catch {
        setArtifacts([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function openJob(job: JobDto) {
    setSelected(job);
    setReport(null);
    setError(null);
    try {
      const d = await api<JobDto & { entities: EntityRow[] }>(`/migrations/${job.id}`);
      setDetail({ entities: sortEntities(d.entities ?? []) });
    } catch (err) {
      setDetail(null);
      setError(err instanceof Error ? err.message : 'could not load the migration');
    }
  }

  async function createMigration(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = (await api<JobDto>('/migrations', {
        method: 'POST',
        body: JSON.stringify({ artifact: artifact.trim(), target_account_id: accountId }),
      })) as JobDto;
      setMessage(
        `Looked inside ${created.source_identifier}: ${created.entity_count} item group(s) found. Open it below to see the plan before anything moves.`,
      );
      setArtifact('');
      await refresh();
      await openJob(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not read that archive');
    } finally {
      setBusy(false);
    }
  }

  async function act(job: JobDto, phase: 'analyze' | 'dry-run' | 'execute' | 'report' | 'cancel') {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      if (phase === 'dry-run') {
        await api(`/migrations/${job.id}/dry-run`, { method: 'POST' });
        setMessage('Plan is ready — nothing has moved yet. Review it, then press "Move everything now".');
      } else if (phase === 'execute') {
        const after = await api<JobDto & { entities: EntityRow[] }>(`/migrations/${job.id}/execute`, { method: 'POST' });
        setDetail({ entities: sortEntities(after.entities ?? []) });
        setSelected({ ...job, status: after.status });
        setMessage(
          after.status === 'completed'
            ? 'Move finished — every item verified byte-for-byte. Open the report for the details.'
            : 'Move finished with problems — open the report; failed items show exactly what did not verify.',
        );
      } else if (phase === 'report') {
        const rep = await api<ReportDto>(`/migrations/${job.id}/report`);
        setReport(rep);
      } else if (phase === 'cancel') {
        await api(`/migrations/${job.id}/cancel`, { method: 'POST' });
        setMessage('Migration canceled. Nothing else will move.');
      }
      await refresh();
      if (phase !== 'execute' && phase !== 'report') {
        const updated = await api<{ data: JobDto[] }>(`/migrations`);
        const mine = (updated.data ?? []).find((x) => x.id === job.id);
        if (mine) setSelected(mine);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'that step did not complete');
    } finally {
      setBusy(false);
    }
  }

  async function removeJob(job: JobDto) {
    setBusy(true);
    setError(null);
    try {
      await api(`/migrations/${job.id}`, { method: 'DELETE' });
      setSelected(null);
      setDetail(null);
      setReport(null);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not delete this migration');
    } finally {
      setBusy(false);
    }
  }

  const action = selected ? nextAction(selected) : null;

  return (
    <Shell active="/migrations" user={user}>
      <h1>Migrations</h1>
      <p className="np-muted">
        Move a hosting account from cPanel into this panel, from one archive file. Nothing is
        guessed: every file, database, mailbox and DNS record is checked byte-for-byte, and you see
        the full report before you switch your domain over.
      </p>

      <div className="np-banner">
        <strong>How it works:</strong> put the cPanel backup file (<code>cpmove-user.tar.gz</code>)
        on the server&apos;s migration shelf, pick it below, choose the account it moves into, then
        follow the steps. Passwords are <em>never</em> copied from the old archive — mailboxes and
        databases get fresh ones you reset here. If anything fails verification, the whole
        migration says <strong>failed</strong> — no half-done moves dressed up as success.
      </div>

      {error && <p className="np-error">{error}</p>}
      {message && <p className="np-ok">{message}</p>}

      <section className="np-card">
        <h2>Start a move</h2>
        {artifacts.length === 0 ? (
          <p className="np-empty">
            No cPanel archives on the migration shelf yet. Copy your <code>cpmove-*.tar.gz</code> to
            the server&apos;s migration folder (<code>/var/lib/nexuspanel-agent/migrations</code>)
            and it will appear here.
          </p>
        ) : (
          <form onSubmit={createMigration} className="np-form">
            <label>
              Backup file (from the migration shelf)
              <select value={artifact} onChange={(e) => setArtifact(e.target.value)}>
                {artifacts.map((a) => (
                  <option key={a.name} value={a.name}>
                    {a.name} — {fmtBytes(a.size_bytes)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Move into account
              <select value={accountId} onChange={(e) => setAccountId(e.target.value)}>
                {accounts.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.username}
                  </option>
                ))}
              </select>
            </label>
            <button className="np-button" disabled={busy || !artifact || !accountId}>
              Look inside the archive
            </button>
          </form>
        )}
      </section>

      <section className="np-card">
        <h2>Moves</h2>
        {jobs.length === 0 ? (
          <p className="np-empty">No migrations yet — start one above.</p>
        ) : (
          <table className="np-table">
            <thead>
              <tr>
                <th>Archive</th>
                <th>Source user</th>
                <th>Into account</th>
                <th>Status</th>
                <th>Started</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id} style={{ cursor: 'pointer' }} onClick={() => void openJob(j)}>
                  <td>{j.source_identifier}</td>
                  <td>{j.source_username ?? '—'}</td>
                  <td>{j.target_account_id ?? '—'}</td>
                  <td>{jobStatusBadge(j.status)}</td>
                  <td>{new Date(j.started_at).toLocaleString()}</td>
                  <td>
                    <button
                      className="np-button"
                      disabled={busy}
                      onClick={(e) => {
                        e.stopPropagation();
                        void openJob(j);
                      }}
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {selected && (
        <section className="np-card">
          <h2>
            {selected.source_identifier} → {selected.target_account_id ?? '?'} {jobStatusBadge(selected.status)}
          </h2>
          {selected.error_message && <p className="np-error">{selected.error_message}</p>}
          <div className="np-row" style={{ gap: 8, flexWrap: 'wrap' }}>
            {action && (
              <button className="np-button" disabled={busy} onClick={() => void act(selected, action.phase)}>
                {action.label}
              </button>
            )}
            <button className="np-button" disabled={busy} onClick={() => void act(selected, 'report')}>
              Report
            </button>
            {!['completed', 'failed', 'canceled'].includes(selected.status) && (
              <button className="np-button" disabled={busy} onClick={() => void act(selected, 'cancel')}>
                Cancel
              </button>
            )}
            {['completed', 'failed', 'canceled'].includes(selected.status) && (
              <button className="np-button" disabled={busy} onClick={() => void removeJob(selected)}>
                Delete record
              </button>
            )}
          </div>

          {detail && detail.entities.length > 0 && (
            <table className="np-table">
              <thead>
                <tr>
                  <th>What</th>
                  <th>From the archive</th>
                  <th>Verdict</th>
                  <th>Checked</th>
                </tr>
              </thead>
              <tbody>
                {detail.entities.map((e) => (
                  <tr key={e.id}>
                    <td>{ENTITY_LABELS[e.entity_type] ?? e.entity_type}</td>
                    <td>
                      {e.source_id}
                      {e.notes && <div className="np-muted" style={{ fontSize: 12 }}>{e.notes}</div>}
                    </td>
                    <td>{statusBadge(e.status)}</td>
                    <td>
                      {e.checksum_parity === true && <span className="np-ok">byte-for-byte ✓</span>}
                      {e.checksum_parity === false && <span className="np-error">mismatch ✗</span>}
                      {e.checksum_parity === null && <span className="np-muted">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {report && (
        <section className="np-card">
          <h2>Verification report</h2>
          <p className="np-muted">
            {report.source.artifact} ({report.source.platform}) → account {report.target.username}.
            Verified: {report.totals['verified'] ?? 0} · Failed: {report.totals['failed'] ?? 0} ·
            Skipped: {report.totals['skipped'] ?? 0} · Source size: {fmtBytes(report.totals['source_bytes'])}
          </p>
          <table className="np-table">
            <thead>
              <tr>
                <th>What</th>
                <th>From the archive</th>
                <th>Verdict</th>
                <th>Source checksum</th>
                <th>Arrived as</th>
                <th>Parity</th>
              </tr>
            </thead>
            <tbody>
              {sortEntities(report.entities.map((e, i) => ({ ...e, id: `${e.entity_type}:${e.source_id}:${i}` }))).map((e) => (
                <tr key={e.id}>
                  <td>{ENTITY_LABELS[e.entity_type] ?? e.entity_type}</td>
                  <td>{e.source_id}</td>
                  <td>{statusBadge(e.status)}</td>
                  <td className="np-muted" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                    {e.checksum_source ? `${e.checksum_source.slice(0, 16)}…` : '—'}
                  </td>
                  <td className="np-muted" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                    {e.checksum_target ? `${e.checksum_target.slice(0, 16)}…` : '—'}
                  </td>
                  <td>
                    {e.checksum_parity === true && <span className="np-ok">match</span>}
                    {e.checksum_parity === false && <span className="np-error">MISMATCH</span>}
                    {e.checksum_parity === null && <span className="np-muted">n/a</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {report.cutover.zones.length > 0 && (
            <>
              <h3>Switch your domain over (cutover plan)</h3>
              <p className="np-muted">{report.cutover.note}</p>
              {report.cutover.zones.map((z) => (
                <div key={z.zone}>
                  <h4>{z.zone}</h4>
                  <table className="np-table">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Points to</th>
                        <th>TTL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {z.records.map((r, i) => (
                        <tr key={i}>
                          <td>{r.name}</td>
                          <td>{r.type}</td>
                          <td>{r.content}</td>
                          <td>{r.ttl}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p className="np-muted" style={{ fontSize: 12 }}>
                    {z.rollback_note}
                  </p>
                </div>
              ))}
            </>
          )}
        </section>
      )}
    </Shell>
  );
}
