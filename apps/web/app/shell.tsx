'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { logout, SessionUser } from '../lib/api';

const NAV = [
  { href: '/', label: 'Dashboard' },
  { href: '/accounts', label: 'Accounts' },
  { href: '/sessions', label: 'Sessions' },
];

/**
 * M0 shell: sidebar + dashboard. Milestone P2 introduces the full
 * navigation driven by RBAC permissions (screen specs: WS5).
 */
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

  useEffect(() => {
    fetch('/api/v1/version')
      .then((r) => r.json())
      .then((v) => setVersion(`${v.panel} · schema ${v.schema}`))
      .catch(() => setVersion('control plane offline'));
  }, []);

  return (
    <div className="np-shell">
      <aside className="np-sidebar">
        <strong>NexusPanel</strong>
        <nav aria-label="Primary">
          {NAV.map((item) => (
            <Link key={item.href} href={item.href} data-active={active === item.href}>
              {item.label}
            </Link>
          ))}
        </nav>
        <div style={{ marginTop: 24, color: 'var(--np-muted)', fontSize: 12 }}>
          {version}
          <br />
          <span className="np-badge">M0 preview</span>
        </div>
        {user && (
          <div style={{ marginTop: 16, fontSize: 12, borderTop: '1px solid var(--np-border)', paddingTop: 12 }}>
            <div style={{ color: 'var(--np-fg)' }}>{user.display_name}</div>
            <div style={{ color: 'var(--np-muted)' }}>{user.email}</div>
            <button
              className="np-button"
              style={{ marginTop: 8, width: '100%', padding: '4px 8px', fontSize: 12 }}
              onClick={() => void logout()}
            >
              Sign out
            </button>
          </div>
        )}
      </aside>
      <main className="np-main">{children}</main>
    </div>
  );
}
