'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { getUser, logout, SessionUser } from '../lib/api';
import { Icon, IconName } from './icons';

/**
 * Sidebar navigation — grouped the way non-technical users think
 * (DirectAdmin-style: plain words, familiar groupings, one obvious place
 * per task). Server-Admin-only entries render only for super admins;
 * the PermissionsGuard remains the enforcement point — this is
 * presentation, not authorization.
 */
const NAV_GROUPS: Array<{
  label: string;
  items: Array<{ href: string; label: string; icon: IconName; adminOnly?: boolean }>;
}> = [
  {
    label: 'Hosting',
    items: [
      { href: '/', label: 'Dashboard', icon: 'gauge' },
      { href: '/sites', label: 'Websites', icon: 'globe' },
      { href: '/apps', label: 'Apps', icon: 'rocket' },
      { href: '/files', label: 'Files', icon: 'folder' },
      { href: '/databases', label: 'Databases', icon: 'database' },
      { href: '/terminal', label: 'Terminal', icon: 'terminal' },
    ],
  },
  {
    label: 'Communication',
    items: [
      { href: '/dns', label: 'DNS', icon: 'network' },
      { href: '/mail', label: 'Email', icon: 'mail' },
    ],
  },
  {
    label: 'Server',
    items: [
      { href: '/backups', label: 'Backups', icon: 'history' },
      { href: '/migrations', label: 'Migrations', icon: 'truck', adminOnly: true },
      { href: '/firewall', label: 'Firewall', icon: 'shield' },
      { href: '/waf', label: 'Threat protection', icon: 'alert' },
      { href: '/settings', label: 'Security', icon: 'lock' },
      { href: '/notifications', label: 'Notifications', icon: 'bell' },
      { href: '/audit', label: 'Audit log', icon: 'file' },
      { href: '/jobs', label: 'Jobs', icon: 'refresh' },
      { href: '/sessions', label: 'Sessions', icon: 'activity' },
      { href: '/tokens', label: 'API tokens', icon: 'key' },
      { href: '/server-settings', label: 'Server settings', icon: 'server', adminOnly: true },
      { href: '/extensions', label: 'Extensions', icon: 'store', adminOnly: true },
    ],
  },
  {
    label: 'Accounts',
    items: [
      { href: '/accounts', label: 'Accounts', icon: 'users' },
      { href: '/packages', label: 'Packages', icon: 'package', adminOnly: true },
      { href: '/resellers', label: 'Resellers', icon: 'store', adminOnly: true },
    ],
  },
];

const THEME_KEY = 'nexuspanel.theme';
const SIDEBAR_KEY = 'nexuspanel.sidebar';

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  return ((parts[0]?.[0] ?? 'U') + (parts[1]?.[0] ?? '')).toUpperCase();
}

export default function Shell({
  children,
  active,
  user,
  onLogout,
}: {
  children: React.ReactNode;
  active: string;
  user?: SessionUser | null;
  onLogout?: () => void;
}) {
  const [version, setVersion] = useState<string>('…');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [collapsed, setCollapsed] = useState(false);
  // Self-sufficient session chip: pages may pass `user`, but the shell also
  // reads the cached session snapshot itself so the chip renders everywhere
  // (client-only read avoids the SSR hydration mismatch).
  const [me, setMe] = useState<SessionUser | null>(user ?? null);

  useEffect(() => {
    const t = (localStorage.getItem(THEME_KEY) as 'dark' | 'light' | null) ?? 'dark';
    setTheme(t);
    document.documentElement.dataset.theme = t;
    setCollapsed(localStorage.getItem(SIDEBAR_KEY) === 'collapsed');
    setMe(user ?? getUser());
    fetch('/api/v1/version')
      .then((r) => r.json())
      .then((v) => setVersion(`v${v.panel}`))
      .catch(() => setVersion('control plane offline'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.dataset.theme = next;
    localStorage.setItem(THEME_KEY, next);
  }

  function toggleCollapsed() {
    const next = !collapsed;
    setCollapsed(next);
    localStorage.setItem(SIDEBAR_KEY, next ? 'collapsed' : 'open');
  }

  const roleLabel = me?.is_super_admin
    ? 'Administrator'
    : me
      ? 'Panel user'
      : null;

  return (
    <div className="np-shell">
      <aside className={`np-sidebar${collapsed ? ' collapsed' : ''}`} style={{ position: 'sticky' }}>
        <button
          className="np-collapse-btn"
          onClick={toggleCollapsed}
          title={collapsed ? 'Expand menu' : 'Collapse menu'}
          aria-label={collapsed ? 'Expand menu' : 'Collapse menu'}
        >
          <Icon name={collapsed ? 'chevron-right' : 'chevron-left'} />
        </button>

        <div className="np-brand">
          <div className="np-brand-mark">N</div>
          <div className="np-brand-name">
            Nexus<span>Panel</span>
          </div>
        </div>

        {NAV_GROUPS.map((group) => {
          const items = group.items.filter((i) => !i.adminOnly || user?.is_super_admin);
          if (items.length === 0) return null;
          return (
            <div className="np-nav-section" key={group.label}>
              <div className="np-nav-label">{group.label}</div>
              {items.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="np-nav-item"
                  data-active={active === item.href}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon name={item.icon} />
                  <span className="label">{item.label}</span>
                </Link>
              ))}
            </div>
          );
        })}

        <div className="np-sidebar-footer">
          <div className="np-row" style={{ gap: 8, padding: '0 4px', flexWrap: 'nowrap' }}>
            <button
              className="np-icon-btn"
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              aria-label="Toggle color theme"
            >
              <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
            </button>
            <div className="np-version-line">{version}</div>
          </div>
          {me && (
            <div className="np-user-chip">
              <div className="np-avatar">{initials(me.display_name || me.email)}</div>
              <div className="np-user-meta">
                <b>{me.display_name}</b>
                <span>{roleLabel}</span>
              </div>
              <button
                className="np-icon-btn"
                onClick={() => void logout()}
                title="Sign out"
                aria-label="Sign out"
              >
                <Icon name="log-out" />
              </button>
            </div>
          )}
        </div>
      </aside>
      <main className="np-main">{children}</main>
    </div>
  );
}
