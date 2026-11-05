'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Backups panel (API spec §4.16, B10).
 *
 * Honest badges (D-11) everywhere:
 *   - a run only wears "verified" when a real proof ran (integrity verify
 *     with checksum + age decrypt, or a dry-run test-restore) — success
 *     alone never earns it;
 *   - schedules are stored cron expressions — the firing engine is the B13
 *     job framework, so "Run now" is the live path today;
 *   - destination configs are encrypted envelopes: the panel creates and
 *     tests them, it never reads them back.
 */

interface DestinationDto {
  id: string;
  name: string;
  type: 'local' | 's3' | 'sftp';
  is_default: boolean;
  age_recipients_note: string;
  created_at: string;
}

interface JobDto {
  id: string;
  name: string;
  scope: 'server' | 'account' | 'site' | 'database';
  scope_id: string | null;
  scope_label: string;
  destination_id: string;
  destination_name: string;
  schedule: string;
  schedule_note: string;
  retention_days: number;
  keep_daily: number;
  keep_weekly: number;
  keep_monthly: number;
  is_enabled: boolean;
  created_at: string;
}

interface RunDto {
  id: string;
  job_id: string;
  job_name: string;
  status: 'running' | 'success' | 'failed' | 'verified';
  started_at: string;
  completed_at: string | null;
  size_bytes: number | null;
  artifact_path: string | null;
  checksum_sha256: string | null;
  verified_at: string | null;
  error_message: string | null;
}

interface AccountOption {
  id: string;
  username: string;
}

interface DatabaseOption {
  id: string;
  name: string;
}

function statusBadge(status: RunDto['status']) {
  if (status === 'verified') {
    return (
      <span className="np-badge" style={{ color: 'var(--np-success)' }} title="A real proof ran: checksum (+ decrypt for encrypted artifacts) or a dry-run test-restore.">
        verified
      </span>
    );
  }
  if (status === 'success') {
    return (
      <span className="np-badge" style={{ color: 'var(--np-warning)' }} title="The backup succeeded — the verified badge appears only after a proof (Verify or a dry-run test-restore).">
        success — not verified yet
      </span>
    );
  }
  if (status === 'failed') {
    return <span className="np-badge" style={{ color: 'var(--np-danger, #ef4444)' }}>failed</span>;
  }
  return <span className="np-badge">running…</span>;
}

function fmtBytes(n: number | null): string {
  if (n === null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function BackupsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [destinations, setDestinations] = useState<DestinationDto[]>([]);
  const [jobs, setJobs] = useState<JobDto[]>([]);
  const [runs, setRuns] = useState<RunDto[]>([]);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [databases, setDatabases] = useState<DatabaseOption[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // destination create form
  const [destName, setDestName] = useState('');
  const [destType, setDestType] = useState<'local' | 's3' | 'sftp'>('local');
  const [localRoot, setLocalRoot] = useState('/var/backups/nexuspanel');
  const [s3Bucket, setS3Bucket] = useState('');
  const [s3Prefix, setS3Prefix] = useState('');
  const [s3Endpoint, setS3Endpoint] = useState('');
  const [s3Region, setS3Region] = useState('');
  const [s3AccessKey, setS3AccessKey] = useState('');
  const [s3SecretKey, setS3SecretKey] = useState('');
  const [sftpHost, setSftpHost] = useState('');
  const [sftpPort, setSftpPort] = useState('22');
  const [sftpUser, setSftpUser] = useState('');
  const [sftpKey, setSftpKey] = useState('');
  const [sftpBaseDir, setSftpBaseDir] = useState('');
  const [sftpHostKey, setSftpHostKey] = useState('');
  const [ageRecipients, setAgeRecipients] = useState('');

  // job create form
  const [jobName, setJobName] = useState('');
  const [jobScope, setJobScope] = useState<'account' | 'database' | 'server'>('account');
  const [jobScopeId, setJobScopeId] = useState('');
  const [jobDestination, setJobDestination] = useState('');
  const [jobSchedule, setJobSchedule] = useState('0 3 * * *');
  const [jobRetention, setJobRetention] = useState('30');
  const [jobKeepDaily, setJobKeepDaily] = useState('7');
  const [jobKeepWeekly, setJobKeepWeekly] = useState('4');
  const [jobKeepMonthly, setJobKeepMonthly] = useState('6');

  // preview / restore panel
  const [preview, setPreview] = useState<{
    run_id: string;
    manifest: Record<string, unknown>;
    entries: Array<{ name: string; size: number }>;
    total_entries: number;
    truncated: boolean;
    checksum_match: boolean;
  } | null>(null);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [d, j, r, a] = await Promise.all([
        api<{ data: DestinationDto[] }>('/backups/destinations'),
        api<{ data: JobDto[] }>('/backups/jobs'),
        api<{ data: RunDto[] }>('/backups/runs'),
        api<{ data: AccountOption[] }>('/accounts'),
      ]);
      setDestinations(d.data ?? []);
      setJobs(j.data ?? []);
      setRuns(r.data ?? []);
      setAccounts(a.data ?? []);
      setJobDestination((cur) => cur || d.data?.[0]?.id || '');
      setJobScopeId((cur) => cur || a.data?.[0]?.id || '');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Load databases for the chosen account when the scope is database.
  useEffect(() => {
    if (jobScope !== 'database' || !jobScopeId) return;
    let alive = true;
    api<{ data: DatabaseOption[] }>(`/databases?account_id=${jobScopeId}`)
      .then((d) => {
        if (!alive) return;
        setDatabases(d.data ?? []);
      })
      .catch(() => {
        if (alive) setDatabases([]);
      });
    return () => {
      alive = false;
    };
  }, [jobScope, jobScopeId]);

  function buildDestinationConfig(): Record<string, unknown> {
    const recipients = ageRecipients
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const config: Record<string, unknown> = {};
    if (destType === 'local') {
      config['root'] = localRoot.trim();
    } else if (destType === 's3') {
      config['bucket'] = s3Bucket.trim();
      if (s3Prefix.trim()) config['prefix'] = s3Prefix.trim();
      if (s3Endpoint.trim()) config['endpoint'] = s3Endpoint.trim();
      if (s3Region.trim()) config['region'] = s3Region.trim();
      config['access_key_id'] = s3AccessKey.trim();
      config['secret_access_key'] = s3SecretKey;
    } else {
      config['host'] = sftpHost.trim();
      config['username'] = sftpUser.trim();
      config['private_key'] = sftpKey;
      if (sftpBaseDir.trim()) config['base_dir'] = sftpBaseDir.trim();
      const port = Number(sftpPort);
      if (Number.isInteger(port) && port > 0) config['port'] = port;
      if (sftpHostKey.trim()) config['host_key'] = sftpHostKey.trim();
    }
    if (recipients.length > 0) config['age_recipients'] = recipients;
    return config;
  }

  async function createDestination(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<DestinationDto>('/backups/destinations', {
        method: 'POST',
        body: JSON.stringify({ name: destName.trim(), type: destType, config: buildDestinationConfig() }),
      });
      setMessage(
        `Destination ${created.name} (${created.type}) stored as an encrypted envelope. Run Test to prove the round trip before pointing jobs at it.`,
      );
      setDestName('');
      setS3SecretKey('');
      setSftpKey('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'destination creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function testDestination(d: DestinationDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ status: string; round_trip_bytes: number; host_key_pinned: boolean; note?: string }>(
        `/backups/destinations/${d.id}/test`,
        { method: 'POST' },
      );
      setMessage(
        `Destination ${d.name}: ${out.status} — ${out.round_trip_bytes} bytes round-tripped.` +
          (out.note ? ` ${out.note}` : ''),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'destination test failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteDestination(d: DestinationDto) {
    if (!window.confirm(`Delete destination ${d.name}? Its stored config envelope is destroyed.`)) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/backups/destinations/${d.id}`, { method: 'DELETE' });
      setMessage(`Destination ${d.name} deleted.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'destination deletion failed');
    } finally {
      setBusy(false);
    }
  }

  async function createJob(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const created = await api<JobDto>('/backups/jobs', {
        method: 'POST',
        body: JSON.stringify({
          name: jobName.trim(),
          scope: jobScope,
          scope_id: jobScope === 'server' ? undefined : jobScopeId,
          destination_id: jobDestination,
          schedule: jobSchedule.trim(),
          retention_days: Number(jobRetention) || undefined,
          keep_daily: Number(jobKeepDaily) || 0,
          keep_weekly: Number(jobKeepWeekly) || 0,
          keep_monthly: Number(jobKeepMonthly) || 0,
        }),
      });
      setMessage(`Job ${created.name} created (${created.scope_label}). ${created.schedule_note}`);
      setJobName('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'job creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function runJob(j: JobDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<RunDto>(`/backups/jobs/${j.id}/run`, { method: 'POST' });
      if (out.status === 'success') {
        setMessage(`Backup ${j.name} finished: ${out.artifact_path} (${fmtBytes(out.size_bytes)}). Verify it to earn the verified badge.`);
      } else if (out.status === 'failed') {
        setMessage(`Backup ${j.name} FAILED and the run journal says so honestly: ${out.error_message}`);
      } else {
        setMessage(`Backup ${j.name}: ${out.status}.`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'run failed');
    } finally {
      setBusy(false);
    }
  }

  async function toggleJob(j: JobDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/backups/jobs/${j.id}`, { method: 'PATCH', body: JSON.stringify({ is_enabled: !j.is_enabled }) });
      setMessage(`Job ${j.name} ${j.is_enabled ? 'disabled' : 'enabled'}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'update failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteJob(j: JobDto) {
    if (!window.confirm(`Delete job ${j.name}? Its run history is removed with it; artifacts at the destination stay.`)) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/backups/jobs/${j.id}`, { method: 'DELETE' });
      setMessage(`Job ${j.name} deleted.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'job deletion failed');
    } finally {
      setBusy(false);
    }
  }

  async function previewRun(r: RunDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    setPreview(null);
    try {
      const out = await api<{
        run_id: string;
        manifest: Record<string, unknown>;
        entries: Array<{ name: string; size: number }>;
        total_entries: number;
        truncated: boolean;
        checksum_match: boolean;
      }>(`/backups/runs/${r.id}/restore-preview`, { method: 'POST' });
      setPreview(out);
      if (!out.checksum_match) {
        setError('Preview warning: the artifact does not match its manifest checksum — run Verify for details.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'preview failed');
    } finally {
      setBusy(false);
    }
  }

  async function verifyRun(r: RunDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ status: string; note: string }>(`/backups/runs/${r.id}/verify`, { method: 'POST' });
      if (out.status === 'verified') {
        setMessage(out.note);
      } else {
        setError(`Verify FAILED for ${r.artifact_path}: ${out.note}`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'verify failed');
    } finally {
      setBusy(false);
    }
  }

  async function restoreRun(r: RunDto, dryRun: boolean) {
    if (!dryRun && !window.confirm(`Real restore of ${r.artifact_path} into the account home? Existing files may be overwritten.`)) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const out = await api<{ status: string; note: string; extracted: string[] }>(`/backups/runs/${r.id}/restore`, {
        method: 'POST',
        body: JSON.stringify({ dry_run: dryRun }),
      });
      setMessage(`${dryRun ? 'Test-restore' : 'Restore'} ${out.status}: ${out.note} (${out.extracted.length} entries)`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'restore failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/backups" user={user}>
      <h1>Backups &amp; restore</h1>
      <p className="np-muted">
        Encrypted artifacts (tar.gz, age C15) to local, S3-compatible or SFTP destinations, with
        manifest + checksum on every run and a restore flow that previews before it touches anything.
      </p>

      <div className="np-banner">
        <strong>Honest notes:</strong> the <em>verified</em> badge appears only after a real proof
        (Verify, or a dry-run test-restore) — a successful backup alone never earns it. Schedules are
        stored cron expressions; the firing engine lands with the job framework (B13), so
        <strong> Run now</strong> is the live path today. Destination configs are encrypted envelopes
        (ADR-0009): created and tested here, never read back. Encrypted restores require the age
        master key on the node — without it they fail loudly (C15), by design.
      </div>

      {error && <p className="np-error">{error}</p>}
      {message && <p className="np-ok">{message}</p>}

      <section className="np-card">
        <h2>Destinations</h2>
        {destinations.length === 0 ? (
          <p className="np-empty">No destinations yet — create one below (local, S3-compatible or SFTP).</p>
        ) : (
          <table className="np-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th></th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {destinations.map((d) => (
                <tr key={d.id}>
                  <td>{d.name}</td>
                  <td>
                    <span className="np-badge">{d.type}</span>{' '}
                    {d.is_default && <span className="np-badge">default</span>}
                  </td>
                  <td>
                    <button className="np-button" disabled={busy} onClick={() => void testDestination(d)}>
                      Test
                    </button>
                  </td>
                  <td>
                    <button className="np-button" disabled={busy} onClick={() => void deleteDestination(d)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <form onSubmit={createDestination} className="np-form">
          <h3>Add a destination</h3>
          <label>
            Name
            <input value={destName} onChange={(e) => setDestName(e.target.value)} placeholder="primary-local" required />
          </label>
          <label>
            Type
            <select value={destType} onChange={(e) => setDestType(e.target.value as typeof destType)}>
              <option value="local">Local (agent backup root)</option>
              <option value="s3">S3-compatible (rclone)</option>
              <option value="sftp">SFTP</option>
            </select>
          </label>
          {destType === 'local' && (
            <label>
              Root (absolute, under the agent backup root)
              <input value={localRoot} onChange={(e) => setLocalRoot(e.target.value)} />
            </label>
          )}
          {destType === 's3' && (
            <>
              <label>
                Bucket
                <input value={s3Bucket} onChange={(e) => setS3Bucket(e.target.value)} placeholder="nexus-backups" required />
              </label>
              <label>
                Prefix (optional)
                <input value={s3Prefix} onChange={(e) => setS3Prefix(e.target.value)} placeholder="alpha" />
              </label>
              <label>
                Endpoint (optional — for non-AWS S3)
                <input value={s3Endpoint} onChange={(e) => setS3Endpoint(e.target.value)} placeholder="https://s3.example.net" />
              </label>
              <label>
                Region (optional)
                <input value={s3Region} onChange={(e) => setS3Region(e.target.value)} />
              </label>
              <label>
                Access key ID
                <input value={s3AccessKey} onChange={(e) => setS3AccessKey(e.target.value)} required />
              </label>
              <label>
                Secret access key
                <input type="password" value={s3SecretKey} onChange={(e) => setS3SecretKey(e.target.value)} required />
              </label>
            </>
          )}
          {destType === 'sftp' && (
            <>
              <label>
                Host
                <input value={sftpHost} onChange={(e) => setSftpHost(e.target.value)} required />
              </label>
              <label>
                Port
                <input value={sftpPort} onChange={(e) => setSftpPort(e.target.value)} />
              </label>
              <label>
                Username
                <input value={sftpUser} onChange={(e) => setSftpUser(e.target.value)} required />
              </label>
              <label>
                Private key (PEM)
                <input type="password" value={sftpKey} onChange={(e) => setSftpKey(e.target.value)} required />
              </label>
              <label>
                Base dir on the remote (optional)
                <input value={sftpBaseDir} onChange={(e) => setSftpBaseDir(e.target.value)} placeholder="/srv/backups" />
              </label>
              <label>
                Host key (base64, optional — pins the server identity)
                <input value={sftpHostKey} onChange={(e) => setSftpHostKey(e.target.value)} />
              </label>
            </>
          )}
          <label>
            Age recipients (comma-separated public keys — strongly recommended; empty = plaintext, flagged on runs)
            <input value={ageRecipients} onChange={(e) => setAgeRecipients(e.target.value)} placeholder="age1..." />
          </label>
          <button className="np-button" disabled={busy || !destName.trim()}>
            Create destination
          </button>
        </form>
      </section>

      <section className="np-card">
        <h2>Backup jobs</h2>
        {jobs.length === 0 ? (
          <p className="np-empty">No jobs yet — a job binds a scope (account, site, database or server) to a destination.</p>
        ) : (
          <table className="np-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Scope</th>
                <th>Destination</th>
                <th>Schedule</th>
                <th>Retention (GFS)</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id}>
                  <td>{j.name}</td>
                  <td>{j.scope_label}</td>
                  <td>{j.destination_name}</td>
                  <td>
                    <code>{j.schedule}</code>{' '}
                    <span className="np-badge" title={j.schedule_note}>
                      stored — not yet firing (B13)
                    </span>
                  </td>
                  <td>
                    {j.retention_days}d · {j.keep_daily}/{j.keep_weekly}/{j.keep_monthly}
                  </td>
                  <td>
                    <button className="np-button" disabled={busy} onClick={() => void runJob(j)}>
                      Run now
                    </button>{' '}
                    <button className="np-button" disabled={busy} onClick={() => void toggleJob(j)}>
                      {j.is_enabled ? 'Disable' : 'Enable'}
                    </button>{' '}
                    <button className="np-button" disabled={busy} onClick={() => void deleteJob(j)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <form onSubmit={createJob} className="np-form">
          <h3>Create a job</h3>
          <label>
            Name
            <input value={jobName} onChange={(e) => setJobName(e.target.value)} placeholder="nightly-account" required />
          </label>
          <label>
            Scope
            <select
              value={jobScope}
              onChange={(e) => {
                setJobScope(e.target.value as typeof jobScope);
                setJobScopeId(accounts[0]?.id || '');
              }}
            >
              <option value="account">Account (whole home)</option>
              <option value="database">Database (mariadb dump)</option>
              <option value="server">Server (agent-managed config)</option>
            </select>
          </label>
          {jobScope !== 'server' && (
            <label>
              {jobScope === 'database' ? 'Account (owner of the database)' : 'Account'}
              <select value={jobScopeId} onChange={(e) => setJobScopeId(e.target.value)}>
                {accounts.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.username}
                  </option>
                ))}
              </select>
            </label>
          )}
          {jobScope === 'database' && databases.length > 0 && (
            <label>
              Database
              <select value={jobScopeId} onChange={(e) => setJobScopeId(e.target.value)}>
                {databases.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label>
            Destination
            <select value={jobDestination} onChange={(e) => setJobDestination(e.target.value)}>
              {destinations.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name} ({d.type})
                </option>
              ))}
            </select>
          </label>
          <label>
            Schedule (cron — fires with the B13 job framework)
            <input value={jobSchedule} onChange={(e) => setJobSchedule(e.target.value)} />
          </label>
          <label>
            Retention days
            <input value={jobRetention} onChange={(e) => setJobRetention(e.target.value)} />
          </label>
          <label>
            GFS keep — daily / weekly / monthly
            <div style={{ display: 'flex', gap: 8 }}>
              <input value={jobKeepDaily} onChange={(e) => setJobKeepDaily(e.target.value)} aria-label="keep daily" />
              <input value={jobKeepWeekly} onChange={(e) => setJobKeepWeekly(e.target.value)} aria-label="keep weekly" />
              <input value={jobKeepMonthly} onChange={(e) => setJobKeepMonthly(e.target.value)} aria-label="keep monthly" />
            </div>
          </label>
          <button className="np-button" disabled={busy || !jobName.trim() || !jobDestination}>
            Create job
          </button>
        </form>
      </section>

      <section className="np-card">
        <h2>Runs</h2>
        {runs.length === 0 ? (
          <p className="np-empty">No runs yet — press Run now on a job.</p>
        ) : (
          <table className="np-table">
            <thead>
              <tr>
                <th>Job</th>
                <th>Status</th>
                <th>Started</th>
                <th>Size</th>
                <th>Artifact</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td>{r.job_name}</td>
                  <td>{statusBadge(r.status)}</td>
                  <td>{new Date(r.started_at).toLocaleString()}</td>
                  <td>{fmtBytes(r.size_bytes)}</td>
                  <td>
                    <code>{r.artifact_path ?? '—'}</code>
                    {r.error_message && <div className="np-muted">{r.error_message}</div>}
                  </td>
                  <td>
                    <button className="np-button" disabled={busy || !r.artifact_path} onClick={() => void previewRun(r)}>
                      Preview
                    </button>{' '}
                    <button className="np-button" disabled={busy || !r.artifact_path} onClick={() => void verifyRun(r)}>
                      Verify
                    </button>{' '}
                    <button className="np-button" disabled={busy || !r.artifact_path} onClick={() => void restoreRun(r, true)}>
                      Test-restore
                    </button>{' '}
                    <button className="np-button" disabled={busy || !r.artifact_path} onClick={() => void restoreRun(r, false)}>
                      Restore
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {preview && (
          <div>
            <h3>Restore preview — {String(preview.manifest['artifact'] ?? preview.run_id)}</h3>
            <p className="np-muted">
              {preview.total_entries} entries
              {preview.truncated ? ' (first page shown)' : ''} · checksum match:{' '}
              {preview.checksum_match ? 'yes' : 'NO — do not restore before verifying'} · scope{' '}
              {String(preview.manifest['scope'] ?? '?')} · encrypted:{' '}
              {preview.manifest['encrypted'] ? 'yes (C15)' : 'no — plaintext destination'}
            </p>
            <pre className="np-pre">
              {preview.entries.map((e) => `${String(e.size).padStart(8)}  ${e.name}`).join('\n')}
            </pre>
          </div>
        )}
      </section>
    </Shell>
  );
}
