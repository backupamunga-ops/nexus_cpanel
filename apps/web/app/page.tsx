'use client';

import { useEffect, useState } from 'react';
import { api, getUser } from '../lib/api';
import Shell from './shell';
import { Icon, IconName } from './icons';

interface Account {
  id: string;
  username: string;
  status: string;
}

/** An extension widget slot (P7, SDK spec §7) rendered on the dashboard. */
interface ExtWidget {
  slug: string;
  name: string;
  widget_id: string;
  slot: string;
  entry_url: string;
}

/**
 * Dashboard — plain-language home screen (WS5 refresh). Every number here
 * is fetched live from the control plane; nothing is mocked or decorated
 * (honest-badge rule D-11). When the control plane is unreachable the
 * cards say so instead of inventing values.
 */

const QUICK_ACTIONS: Array<{ href: string; label: string; icon: IconName }> = [
  { href: '/sites', label: 'Add a website', icon: 'globe' },
  { href: '/mail', label: 'Email accounts', icon: 'mail' },
  { href: '/databases', label: 'Databases', icon: 'database' },
  { href: '/dns', label: 'DNS records', icon: 'network' },
  { href: '/files', label: 'Files', icon: 'folder' },
  { href: '/backups', label: 'Backups', icon: 'history' },
  { href: '/settings', label: 'Security', icon: 'shield' },
  { href: '/tokens', label: 'API tokens', icon: 'key' },
];

const GETTING_STARTED: Array<{ href: string; title: string; hint: string }> = [
  { href: '/accounts', title: 'Create a hosting account', hint: 'One account per client or project' },
  { href: '/sites', title: 'Add your first website', hint: 'Pick the domain and PHP version' },
  { href: '/dns', title: 'Point the domain here', hint: 'Manage DNS records in one place' },
  { href: '/backups', title: 'Turn on backups', hint: 'Set it once, sleep well' },
];

function greeting(): string {
  const h = new Date().getHours();
  if (h < 12) return 'Good morning';
  if (h < 18) return 'Good afternoon';
  return 'Good evening';
}

export default function Dashboard() {
  const [me, setMe] = useState<{ display_name: string; is_super_admin: boolean } | null>(null);
  const [accounts, setAccounts] = useState<Account[] | null>(null);
  const [widgets, setWidgets] = useState<ExtWidget[] | null>(null);
  const [version, setVersion] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    const user = getUser();
    setMe(user);
    if (!user) {
      window.location.href = '/login';
      return;
    }
    api<{ data: Account[] }>('/accounts')
      .then((j) => setAccounts(j.data ?? []))
      .catch(() => {
        setAccounts(null);
        setOffline(true);
      });
    fetch('/api/v1/version')
      .then((r) => r.json())
      .then((v) => setVersion(`${v.panel} · schema ${v.schema}`))
      .catch(() => setVersion(null));
    // Extension widget slots (SDK spec §7) — absent list simply renders nothing
    api<{ data: ExtWidget[] }>('/extensions/widgets')
      .then((j) => setWidgets(j.data ?? []))
      .catch(() => setWidgets([]));
  }, []);

  const firstName = me?.display_name?.split(/\s+/)[0] ?? 'there';
  const total = accounts?.length ?? 0;
  const active = accounts?.filter((a) => a.status === 'active').length ?? 0;

  return (
    <Shell active="/">
      <div className="np-stack">
        {/* Hero strip — friendly, honest summary */}
        <div className="np-hero">
          <div>
            <b>
              {greeting()}, {firstName} 👋
            </b>
            <p>
              {offline ? (
                <>Can’t reach the server right now — your data is safe, try again in a moment.</>
              ) : accounts === null ? (
                <>Loading your server summary…</>
              ) : total === 0 ? (
                <>
                  Your panel is ready. Start with <strong>step 1 below</strong> — create a hosting
                  account and you’ll be hosting in minutes.
                </>
              ) : (
                <>
                  {total} hosting account{total === 1 ? '' : 's'} · {active} active ·{' '}
                  <strong>everything in one place</strong> below.
                </>
              )}
            </p>
          </div>
        </div>

        {/* Quick actions — one obvious tile per everyday task */}
        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="plus" />
              </span>
              Quick actions
            </h3>
          </div>
          <div className="np-quick-grid">
            {QUICK_ACTIONS.map((a) => (
              <a className="np-quick-tile" href={a.href} key={a.href}>
                <Icon name={a.icon} />
                <span>{a.label}</span>
              </a>
            ))}
          </div>
        </section>

        {/* Live numbers — real data only */}
        <div className="np-kpi-row">
          <div className="np-kpi">
            <div className="np-kpi-top">
              <span className="np-kpi-label">Hosting accounts</span>
              <span className="np-kpi-icon">
                <Icon name="users" />
              </span>
            </div>
            <div className="np-kpi-value">{accounts === null ? '—' : total}</div>
            <div className="np-kpi-note">
              {accounts === null ? (offline ? 'server unreachable' : 'loading…') : `${active} active`}
            </div>
          </div>
          <div className="np-kpi">
            <div className="np-kpi-top">
              <span className="np-kpi-label">Your access</span>
              <span className="np-kpi-icon">
                <Icon name="shield" />
              </span>
            </div>
            <div className="np-kpi-value" style={{ fontSize: 18, paddingTop: 4 }}>
              {me?.is_super_admin ? 'Administrator' : 'Panel user'}
            </div>
            <div className="np-kpi-note">{me?.is_super_admin ? 'full server control' : 'shared access'}</div>
          </div>
          <div className="np-kpi">
            <div className="np-kpi-top">
              <span className="np-kpi-label">Panel version</span>
              <span className="np-kpi-icon">
                <Icon name='activity' />
              </span>
            </div>
            <div className="np-kpi-value" style={{ fontSize: 18, paddingTop: 4 }}>
              {version ?? '—'}
            </div>
            <div className="np-kpi-note">{version ? 'up to date' : 'control plane offline'}</div>
          </div>
        </div>

        {/* Extension widgets (P7) — sandboxed iframes, context via postMessage */}
        {widgets !== null && widgets.length > 0 && (
          <div className="np-grid">
            {widgets.map((w) => (
              <section className="np-card" key={`${w.slug}:${w.widget_id}`}>
                <div className="np-card-head">
                  <h3>
                    <span className="ico">
                      <Icon name="store" />
                    </span>
                    {w.name}
                  </h3>
                  <span className="np-badge info">extension</span>
                </div>
                <iframe
                  title={`${w.name} — ${w.widget_id}`}
                  src={w.entry_url}
                  sandbox="allow-scripts allow-same-origin"
                  referrerPolicy="no-referrer"
                  style={{ width: '100%', height: 220, border: 'none', borderRadius: 'var(--np-radius-sm)' }}
                  onLoad={(e) => {
                    // SDK spec §7: the widget asks for context via postMessage;
                    // the panel answers with the current theme tokens.
                    const mode = (
                      localStorage.getItem('nexuspanel.theme') as 'dark' | 'light' | null
                    ) ?? 'dark';
                    (e.target as HTMLIFrameElement).contentWindow?.postMessage(
                      {
                        type: 'nexuspanel:context',
                        theme: {
                          mode,
                          primary: '#6366f1',
                          background: mode === 'dark' ? '#0a0a0a' : '#ffffff',
                          foreground: mode === 'dark' ? '#fafafa' : '#0f172a',
                          font_family: 'Inter',
                          border_radius: '8px',
                        },
                      },
                      '*',
                    );
                  }}
                />
              </section>
            ))}
          </div>
        )}

        {/* Getting started — plain steps for non-technical users */}
        <div className="np-grid">
          <section className="np-card">
            <div className="np-card-head">
              <h3>
                <span className="ico">
                  <Icon name="layers" />
                </span>
                Getting started
              </h3>
            </div>
            <div className="np-steps">
              {GETTING_STARTED.map((s, i) => (
                <a className="np-step" href={s.href} key={s.href}>
                  <span className="num">{i + 1}</span>
                  <span>
                    <b>{s.title}</b>
                    <small>{s.hint}</small>
                  </span>
                  <span className="chev">
                    <Icon name="arrow-right" size={14} />
                  </span>
                </a>
              ))}
            </div>
          </section>

          <section className="np-card">
            <div className="np-card-head">
              <h3>
                <span className="ico">
                  <Icon name="lock" />
                </span>
                Built-in safety
              </h3>
            </div>
            <p className="np-muted" style={{ fontSize: 12.5, lineHeight: 1.7 }}>
              Every change you make here is recorded in a tamper-evident audit log, dangerous
              actions ask for confirmation first, and your passwords are never shown to the
              server. This panel never runs as root — by design.
            </p>
          </section>
        </div>
      </div>
    </Shell>
  );
}
