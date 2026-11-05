'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * DNS console (API spec §4.9, ADR-0012).
 *
 * PowerDNS on the node is the authority; this screen drives the agent and
 * shows the mirror. Everything shown here is real state: DNSSEC material is
 * read live from the node, propagation results are per-resolver with
 * missing/timeout reported — never flattened into a fake "done" (D-11).
 */

interface ZoneDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  name: string;
  is_active: boolean;
  dnssec_enabled: boolean;
  record_count: number;
  created_at: string;
}

interface RecordDto {
  id: string;
  zone_id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  priority: number | null;
  weight: number | null;
  port: number | null;
  is_active: boolean;
  created_at: string;
}

interface DnssecState {
  zone: string;
  enabled: boolean;
  ds: string[];
  dnskey: string[];
  keys: Array<{ key_type: string; key_id: string; detail: string }>;
}

interface ZoneCheck {
  zone: string;
  ok: boolean;
  issues: string[];
}

interface PropagationResult {
  zone: string;
  resolvers: string[];
  checked: number;
  consistent: boolean;
  results: Array<{ name: string; type: string; resolver: string; state: string; answer?: string }>;
}

interface AccountOption {
  id: string;
  username: string;
}

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'NS'];

export default function DnsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [accounts, setAccounts] = useState<AccountOption[]>([]);
  const [accountId, setAccountId] = useState('');
  const [zones, setZones] = useState<ZoneDto[]>([]);
  const [selected, setSelected] = useState<ZoneDto | null>(null);
  const [records, setRecords] = useState<RecordDto[]>([]);
  const [dnssec, setDnssec] = useState<DnssecState | null>(null);
  const [zoneCheck, setZoneCheck] = useState<ZoneCheck | null>(null);
  const [propagation, setPropagation] = useState<PropagationResult | null>(null);
  const [exported, setExported] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // create form
  const [newZone, setNewZone] = useState('');
  const [seedIp, setSeedIp] = useState('');

  // record form
  const [recName, setRecName] = useState('');
  const [recType, setRecType] = useState('A');
  const [recContent, setRecContent] = useState('');
  const [recTtl, setRecTtl] = useState('3600');
  const [recPriority, setRecPriority] = useState('');
  const [recWeight, setRecWeight] = useState('');
  const [recPort, setRecPort] = useState('');
  const [editing, setEditing] = useState<RecordDto | null>(null);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const a = await api<{ data: AccountOption[] }>('/accounts');
      setAccounts(a.data ?? []);
      setAccountId((cur) => cur || a.data?.[0]?.id || '');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const loadZones = useCallback(async () => {
    if (!accountId) return;
    try {
      const z = await api<{ data: ZoneDto[] }>(`/dns/zones?account_id=${accountId}`);
      setZones(z.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load zones');
    }
  }, [accountId]);

  useEffect(() => {
    void loadZones();
  }, [loadZones]);

  const loadZone = useCallback(async (z: ZoneDto) => {
    setSelected(z);
    setRecords([]);
    setDnssec(null);
    setZoneCheck(null);
    setPropagation(null);
    setExported(null);
    setError(null);
    try {
      const r = await api<{ data: RecordDto[] }>(`/dns/zones/${z.id}/records`);
      setRecords(r.data ?? []);
      const d = await api<DnssecState>(`/dns/zones/${z.id}/dnssec`);
      setDnssec(d);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load zone detail');
    }
  }, []);

  async function createZone(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const records: unknown[] = [];
      if (seedIp.trim()) {
        records.push({ name: '@', type: 'A', content: seedIp.trim(), ttl: 3600 });
        records.push({ name: 'www', type: 'CNAME', content: `${newZone.trim()}`, ttl: 3600 });
      }
      const created = await api<ZoneDto>('/dns/zones', {
        method: 'POST',
        body: JSON.stringify({ account_id: accountId, name: newZone.trim(), records }),
      });
      setMessage(
        created.record_count === 0
          ? `Zone ${created.name} created. The nameserver seeded a default SOA (ns1.${created.name}) — replace it if your NS plan differs.`
          : `Zone ${created.name} created with ${created.record_count} records.`,
      );
      setNewZone('');
      setSeedIp('');
      await loadZones();
      await loadZone(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'zone creation failed');
    } finally {
      setBusy(false);
    }
  }

  async function saveRecord(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    const payload: Record<string, unknown> = {
      name: recName.trim() || '@',
      type: recType,
      content: recContent.trim(),
      ttl: Number(recTtl) || 3600,
    };
    if (recPriority !== '') payload['priority'] = Number(recPriority);
    if (recWeight !== '') payload['weight'] = Number(recWeight);
    if (recPort !== '') payload['port'] = Number(recPort);
    try {
      if (editing) {
        await api(`/dns/zones/${selected.id}/records/${editing.id}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        });
        setMessage(`Record ${String(payload['name'])} ${recType} updated — serial bumped on the nameserver.`);
      } else {
        await api(`/dns/zones/${selected.id}/records`, {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        setMessage(`Record ${String(payload['name'])} ${recType} applied.`);
      }
      setEditing(null);
      setRecName('');
      setRecContent('');
      setRecPriority('');
      setRecWeight('');
      setRecPort('');
      setRecTtl('3600');
      await loadZone(selected);
      await loadZones();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'record apply failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteRecord(r: RecordDto) {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/dns/zones/${selected.id}/records/${r.id}`, { method: 'DELETE' });
      setMessage(`Record ${r.name} ${r.type} removed.`);
      await loadZone(selected);
      await loadZones();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'record removal failed');
    } finally {
      setBusy(false);
    }
  }

  async function toggleDnssec(enable: boolean) {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      if (enable) {
        const res = await api<{ status: string; ds: string[] }>(`/dns/zones/${selected.id}/dnssec/enable`, { method: 'POST' });
        setMessage(`DNSSEC enabled. Add the DS record at your registrar: ${res.ds[0] ?? '(no DS returned)'}`);
      } else {
        await api(`/dns/zones/${selected.id}/dnssec/disable`, { method: 'POST' });
        setMessage('DNSSEC disabled on the node. Remove the DS record at your registrar.');
      }
      await loadZone(selected);
      await loadZones();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'dnssec change failed');
    } finally {
      setBusy(false);
    }
  }

  async function runZoneCheck() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const res = await api<ZoneCheck>(`/dns/zones/${selected.id}/zone-check`, { method: 'POST' });
      setZoneCheck(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'zone check failed');
    } finally {
      setBusy(false);
    }
  }

  async function runPropagation() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const res = await api<PropagationResult>(`/dns/zones/${selected.id}/check-propagation`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setPropagation(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'propagation check failed');
    } finally {
      setBusy(false);
    }
  }

  async function runExport() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ zone: string; content: string }>(`/dns/zones/${selected.id}/export`);
      setExported(res.content);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'export failed');
    } finally {
      setBusy(false);
    }
  }

  async function deleteZone(z: ZoneDto) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await api(`/dns/zones/${z.id}`, { method: 'DELETE' });
      setMessage(`Zone ${z.name} deleted from the nameserver.`);
      setSelected(null);
      setRecords([]);
      setDnssec(null);
      await loadZones();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'zone deletion failed');
    } finally {
      setBusy(false);
    }
  }

  function startEdit(r: RecordDto) {
    setEditing(r);
    const suffix = selected ? `.${selected.name}` : '';
    setRecName(r.name === selected?.name ? '@' : r.name.endsWith(suffix) ? r.name.slice(0, -suffix.length) : r.name);
    setRecType(r.type);
    setRecContent(
      r.type === 'MX'
        ? r.content.split(' ').slice(1).join(' ')
        : r.type === 'SRV'
          ? r.content.split(' ').slice(3).join(' ')
          : r.content,
    );
    setRecTtl(String(r.ttl));
    setRecPriority(r.priority !== null ? String(r.priority) : '');
    setRecWeight(r.weight !== null ? String(r.weight) : '');
    setRecPort(r.port !== null ? String(r.port) : '');
  }

  return (
    <Shell active="/dns" user={user}>
      <h1>DNS zones</h1>
      <p className="lede">
        Authoritative zones on this node&apos;s PowerDNS. Every change goes
        through the privileged agent, bumps the SOA serial, and is audited.
      </p>

      {error && (
        <p role="alert" className="np-error">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="np-ok">
          {message}
        </p>
      )}

      <section className="np-card">
        <h2>Create a zone</h2>
        <form onSubmit={createZone} className="np-form">
          <label>
            Hosting account
            <select value={accountId} onChange={(e) => setAccountId(e.target.value)}>
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.username}
                </option>
              ))}
            </select>
          </label>
          <label>
            Zone name
            <input
              value={newZone}
              onChange={(e) => setNewZone(e.target.value)}
              placeholder="example.com"
              required
            />
          </label>
          <label>
            Seed A record for (optional IPv4)
            <input
              value={seedIp}
              onChange={(e) => setSeedIp(e.target.value)}
              placeholder="192.0.2.10 — creates @ A and www CNAME"
            />
          </label>
          <button className="np-button" disabled={busy || !newZone.trim()}>
            Create zone
          </button>
        </form>
        <p className="np-muted">
          With no seed IP, the nameserver seeds a default SOA only
          (ns1.&lt;zone&gt;) — reported on creation so it can be corrected.
        </p>
      </section>

      <section className="np-card">
        <h2>Zones</h2>
        {zones.length === 0 ? (
          <p className="np-empty">No zones yet for this account — create one above.</p>
        ) : (
          <table className="np-table">
            <thead>
              <tr>
                <th>Zone</th>
                <th>Records</th>
                <th>DNSSEC</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {zones.map((z) => (
                <tr key={z.id} data-selected={selected?.id === z.id}>
                  <td>{z.name}</td>
                  <td>{z.record_count}</td>
                  <td>
                    <span className={`np-badge ${z.dnssec_enabled ? 'ok' : ''}`}>
                      {z.dnssec_enabled ? 'secured' : 'not secured'}
                    </span>
                  </td>
                  <td>
                    <button className="np-button" onClick={() => void loadZone(z)}>
                      Open
                    </button>{' '}
                    <button className="np-button" disabled={busy} onClick={() => void deleteZone(z)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {selected && (
        <>
          <section className="np-card">
            <h2>
              Records — {selected.name}{' '}
              <span className={`np-badge ${selected.dnssec_enabled ? 'ok' : ''}`}>
                {selected.dnssec_enabled ? 'DNSSEC on' : 'DNSSEC off'}
              </span>
            </h2>
            {records.length === 0 ? (
              <p className="np-empty">This zone has no records yet — add the first one below.</p>
            ) : (
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Content</th>
                    <th>TTL</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((r) => (
                    <tr key={r.id}>
                      <td>{r.name}</td>
                      <td>{r.type}</td>
                      <td className="np-mono">{r.content}</td>
                      <td>{r.ttl}</td>
                      <td>
                        <button className="np-button" onClick={() => startEdit(r)}>
                          Edit
                        </button>{' '}
                        <button className="np-button" disabled={busy} onClick={() => void deleteRecord(r)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            <form onSubmit={saveRecord} className="np-form">
              <h3>{editing ? `Edit record (${editing.type})` : 'Add a record'}</h3>
              <label>
                Name
                <input value={recName} onChange={(e) => setRecName(e.target.value)} placeholder="@ or www (relative to the zone)" />
              </label>
              <label>
                Type
                <select value={recType} onChange={(e) => setRecType(e.target.value)}>
                  {RECORD_TYPES.map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </label>
              <label>
                Content
                <input value={recContent} onChange={(e) => setRecContent(e.target.value)} placeholder="192.0.2.1 / host / &quot;text&quot;" required />
              </label>
              <label>
                TTL
                <input value={recTtl} onChange={(e) => setRecTtl(e.target.value)} />
              </label>
              {(recType === 'MX' || recType === 'SRV') && (
                <label>
                  Priority
                  <input value={recPriority} onChange={(e) => setRecPriority(e.target.value)} />
                </label>
              )}
              {recType === 'SRV' && (
                <>
                  <label>
                    Weight
                    <input value={recWeight} onChange={(e) => setRecWeight(e.target.value)} />
                  </label>
                  <label>
                    Port
                    <input value={recPort} onChange={(e) => setRecPort(e.target.value)} />
                  </label>
                </>
              )}
              <button className="np-button" disabled={busy}>
                {editing ? 'Update record' : 'Add record'}
              </button>{' '}
              {editing && (
                <button
                  type="button"
                  className="np-button"
                  onClick={() => {
                    setEditing(null);
                    setRecName('');
                    setRecContent('');
                  }}
                >
                  Cancel
                </button>
              )}
            </form>
          </section>

          <section className="np-card">
            <h2>DNSSEC</h2>
            {dnssec ? (
              <>
                <p>
                  Live state on the node:{' '}
                  <span className={`np-badge ${dnssec.enabled ? 'ok' : ''}`}>
                    {dnssec.enabled ? 'secured' : 'not secured'}
                  </span>
                  {selected.dnssec_enabled !== dnssec.enabled && (
                    <span className="np-badge"> mirror out of sync — refresh to reconcile</span>
                  )}
                </p>
                {dnssec.ds.length > 0 && (
                  <>
                    <h3>DS records for your registrar</h3>
                    <pre className="np-pre">{dnssec.ds.join('\n')}</pre>
                  </>
                )}
                {dnssec.dnskey.length > 0 && (
                  <>
                    <h3>DNSKEYs</h3>
                    <pre className="np-pre">{dnssec.dnskey.join('\n')}</pre>
                  </>
                )}
                <button className="np-button" disabled={busy} onClick={() => void toggleDnssec(!selected.dnssec_enabled)}>
                  {selected.dnssec_enabled ? 'Disable DNSSEC' : 'Enable DNSSEC'}
                </button>
              </>
            ) : (
              <p className="np-muted">DNSSEC state loads with the zone.</p>
            )}
            <p className="np-muted">
              Key material lives in PowerDNS&apos;s own store; the panel shows the
              live DS/DNSKEY material. Private-key archival into the panel vault
              is planned, not built.
            </p>
          </section>

          <section className="np-card">
            <h2>Checks</h2>
            <button className="np-button" disabled={busy} onClick={() => void runZoneCheck()}>
              Run zone check
            </button>{' '}
            <button className="np-button" disabled={busy} onClick={() => void runPropagation()}>
              Check propagation
            </button>{' '}
            <button className="np-button" disabled={busy} onClick={() => void runExport()}>
              Export (AXFR format)
            </button>
            {zoneCheck && (
              <div>
                <h3>Zone check — {zoneCheck.ok ? 'clean' : 'problems found'}</h3>
                <pre className="np-pre">{zoneCheck.issues.join('\n') || '(no output)'}</pre>
              </div>
            )}
            {propagation && (
              <div>
                <h3>
                  Propagation — {propagation.consistent ? 'consistent' : 'inconsistent / not yet visible'}
                </h3>
                <table className="np-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Resolver</th>
                      <th>State</th>
                      <th>Answer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {propagation.results.map((r, i) => (
                      <tr key={i}>
                        <td>{r.name}</td>
                        <td>{r.type}</td>
                        <td>{r.resolver}</td>
                        <td>
                          <span className={`np-badge ${r.state === 'match' ? 'ok' : ''}`}>{r.state}</span>
                        </td>
                        <td className="np-mono">{r.answer ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="np-muted">
                  Checked public resolvers {propagation.resolvers.join(', ')} against the panel mirror.
                  missing = the resolver has no answer yet; timeout = no answer in 2s.
                </p>
              </div>
            )}
            {exported && (
              <div>
                <h3>Zone export</h3>
                <pre className="np-pre">{exported}</pre>
              </div>
            )}
          </section>
        </>
      )}
    </Shell>
  );
}
