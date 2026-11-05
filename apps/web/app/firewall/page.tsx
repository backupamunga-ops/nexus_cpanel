'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, getUser } from '../../lib/api';
import Shell from '../shell';
import { Icon } from '../icons';

/**
 * Firewall & intrusion protection (API spec §4.17, ADR-0016) — B11.
 *
 * Plain-language server security surface: firewall rules (the managed
 * nftables table), live fail2ban jail health and the ban list with an
 * audited unban. Everything shown is live node state; when the agent is
 * unreachable the cards say so instead of pretending (D-11). The
 * self-lockout guard lives in the agent — this screen surfaces its
 * operator-readable refusals verbatim.
 */

interface RuleDto {
  id: string;
  name: string;
  direction: string;
  protocol: string;
  port_from: number | null;
  port_to: number | null;
  source_cidr: string | null;
  action: string;
  is_active: boolean;
  created_at: string;
}

interface FirewallStatus {
  configured: boolean;
  table: string;
  ruleset: string;
}

interface Jail {
  name: string;
  currently_banned: number;
  total_banned: number;
  banned_ips: string[];
  note?: string;
}

interface JailsResponse {
  jails: Jail[];
  note?: string;
}

const EMPTY_FORM = {
  name: '',
  direction: 'inbound',
  protocol: 'tcp',
  port_from: '',
  port_to: '',
  source_cidr: '',
  action: 'accept',
};

function portLabel(r: RuleDto): string {
  if (r.protocol === 'icmp') return '—';
  if (r.port_from === null) return 'any';
  if (r.port_to !== null && r.port_to !== r.port_from) return `${r.port_from}–${r.port_to}`;
  return String(r.port_from);
}

export default function FirewallPage() {
  const [rules, setRules] = useState<RuleDto[] | null>(null);
  const [status, setStatus] = useState<FirewallStatus | null>(null);
  const [jails, setJails] = useState<JailsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ ...EMPTY_FORM });

  useEffect(() => {
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [r, s, j] = await Promise.all([
        api<{ data: RuleDto[] }>('/firewall/rules'),
        api<FirewallStatus>('/firewall/status'),
        api<JailsResponse>('/firewall/fail2ban/jails'),
      ]);
      setRules(r.data ?? []);
      setStatus(s);
      setJails(j);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'control plane unreachable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function addRule(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api('/firewall/rules', {
        method: 'POST',
        body: JSON.stringify({
          name: form.name,
          direction: form.direction,
          protocol: form.protocol,
          port_from: form.port_from === '' ? null : Number(form.port_from),
          port_to: form.port_to === '' ? null : Number(form.port_to),
          source_cidr: form.source_cidr,
          action: form.action,
        }),
      });
      setForm({ ...EMPTY_FORM });
      setNotice('Rule applied to the node firewall.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not add rule');
    } finally {
      setBusy(false);
    }
  }

  async function deleteRule(id: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(`/firewall/rules/${id}`, { method: 'DELETE' });
      setNotice('Rule removed; the firewall was updated on the node.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not remove rule');
    } finally {
      setBusy(false);
    }
  }

  async function unban(jail: string, ip: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api('/firewall/fail2ban/unban', {
        method: 'POST',
        body: JSON.stringify({ jail, ip }),
      });
      setNotice(`${ip} was unbanned from ${jail}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not unban');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/firewall">
      <div className="np-stack">
        <div className="np-page-head">
          <div>
            <h1 className="np-title">Firewall &amp; bans</h1>
            <p className="lede">
              Decide who can reach this server, and see who got locked out for guessing wrong.
              Every change is checked for safety before it goes live — the panel will refuse a
              rule that could lock you out.
            </p>
          </div>
          <span className="np-badge" title="managed nftables table">
            nftables · {status?.configured ? 'active on node' : 'registry saved'}
          </span>
        </div>

        {error && <div className="np-error">{error}</div>}
        {notice && <div className="np-ok">{notice}</div>}

        {/* Live status */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="shield" />
              </span>
              Firewall state on the node
            </h3>
            <span className={`np-badge ${status?.configured ? 'ok' : 'warn'}`}>
              {status === null ? 'checking…' : status.configured ? 'applied' : 'not applied yet'}
            </span>
          </div>
          {status && status.configured ? (
            <pre className="np-pre">{status.ruleset}</pre>
          ) : (
            <p className="np-muted" style={{ fontSize: 12.5 }}>
              {status?.ruleset ?? 'Loading…'} The firewall activates as soon as you add the first
              rule below. Until then no traffic is filtered by the panel.
            </p>
          )}
        </section>

        {/* Rules table */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="layers" />
              </span>
              Rules
            </h3>
            <span className="np-badge">{rules?.length ?? '…'}</span>
          </div>
          {rules === null ? (
            <p className="np-muted">Loading…</p>
          ) : rules.length === 0 ? (
            <div className="np-empty">
              No firewall rules yet — everything is allowed. Add your first rule below.
            </div>
          ) : (
            <div className="np-table-wrap">
              <table className="np-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Direction</th>
                    <th>Protocol</th>
                    <th>Port(s)</th>
                    <th>Source</th>
                    <th>Action</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id}>
                      <td style={{ color: 'var(--np-foreground)' }}>{r.name}</td>
                      <td>{r.direction}</td>
                      <td className="np-mono">{r.protocol}</td>
                      <td className="np-mono">{portLabel(r)}</td>
                      <td className="np-mono">{r.source_cidr || 'anywhere'}</td>
                      <td>
                        <span className={`np-badge ${r.action === 'accept' ? 'ok' : 'err'}`}>
                          {r.action}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="np-button np-button-ghost np-button-sm"
                          disabled={busy}
                          onClick={() => void deleteRule(r.id)}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Add rule */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="plus" />
              </span>
              Add a rule
            </h3>
          </div>
          <form className="np-form" onSubmit={addRule}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
              <div className="np-field">
                <label htmlFor="fw-name">Rule name</label>
                <input
                  id="fw-name"
                  className="np-input"
                  required
                  maxLength={64}
                  placeholder="e.g. web traffic"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="np-field">
                <label htmlFor="fw-dir">Traffic type</label>
                <select
                  id="fw-dir"
                  className="np-input np-select"
                  value={form.direction}
                  onChange={(e) => setForm({ ...form, direction: e.target.value })}
                >
                  <option value="inbound">Incoming</option>
                  <option value="outbound">Outgoing</option>
                </select>
              </div>
              <div className="np-field">
                <label htmlFor="fw-proto">Protocol</label>
                <select
                  id="fw-proto"
                  className="np-input np-select"
                  value={form.protocol}
                  onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP (ping)</option>
                </select>
              </div>
              <div className="np-field">
                <label htmlFor="fw-port">Port(s)</label>
                <input
                  id="fw-port"
                  className="np-input"
                  inputMode="numeric"
                  placeholder={form.protocol === 'icmp' ? 'not needed' : 'e.g. 443'}
                  disabled={form.protocol === 'icmp'}
                  value={form.port_from}
                  onChange={(e) => setForm({ ...form, port_from: e.target.value.replace(/[^0-9]/g, '') })}
                />
                <span className="np-hint">Single port. Leave empty for any port.</span>
              </div>
              <div className="np-field">
                <label htmlFor="fw-cidr">Allowed from</label>
                <input
                  id="fw-cidr"
                  className="np-input"
                  placeholder="anywhere — or 203.0.113.0/24"
                  value={form.source_cidr}
                  onChange={(e) => setForm({ ...form, source_cidr: e.target.value })}
                />
              </div>
              <div className="np-field">
                <label htmlFor="fw-action">Then</label>
                <select
                  id="fw-action"
                  className="np-input np-select"
                  value={form.action}
                  onChange={(e) => setForm({ ...form, action: e.target.value })}
                >
                  <option value="accept">Allow</option>
                  <option value="drop">Block silently</option>
                  <option value="reject">Block &amp; tell the sender</option>
                </select>
              </div>
            </div>
            <div className="np-row">
              <button className="np-button" disabled={busy}>
                {busy ? 'Applying…' : 'Apply rule'}
              </button>
              <span className="np-hint">
                Safety check included: rules that would lock you out of this panel are refused.
              </span>
            </div>
          </form>
        </section>

        {/* fail2ban jails + bans */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="lock" />
              </span>
              Break-in attempts (fail2ban)
            </h3>
            <span className="np-badge">
              {jails === null ? 'checking…' : `${jails.jails.length} jails`}
            </span>
          </div>
          {jails === null ? (
            <p className="np-muted">Loading…</p>
          ) : jails.jails.length === 0 ? (
            <div className="np-empty">
              {jails.note ?? 'fail2ban is not reporting any jails on this node yet.'}
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 14, gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
              {jails.jails.map((j) => (
                <div key={j.name} className="np-card" style={{ background: 'var(--np-card-2)' }}>
                  <div className="np-card-head" style={{ marginBottom: 8 }}>
                    <h3 style={{ fontSize: 13 }}>{j.name}</h3>
                    <span className={`np-badge ${j.currently_banned > 0 ? 'err' : 'ok'}`}>
                      {j.currently_banned} banned now
                    </span>
                  </div>
                  {j.note && <p className="np-muted" style={{ fontSize: 11.5 }}>{j.note}</p>}
                  <p className="np-muted" style={{ fontSize: 11.5, marginBottom: 8 }}>
                    {j.total_banned} bans in total · repeat offenders get locked out automatically.
                  </p>
                  {j.banned_ips.length === 0 ? (
                    <p className="np-muted" style={{ fontSize: 12 }}>Nobody is banned right now.</p>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {j.banned_ips.map((ip) => (
                        <div key={ip} className="np-row" style={{ justifyContent: 'space-between', flexWrap: 'nowrap' }}>
                          <span className="np-mono" style={{ fontSize: 12 }}>{ip}</span>
                          <button
                            className="np-button np-button-ghost np-button-sm"
                            disabled={busy}
                            onClick={() => void unban(j.name, ip)}
                          >
                            Unban
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </Shell>
  );
}
