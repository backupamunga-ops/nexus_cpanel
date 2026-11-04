'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

const NAV = [
  { href: '/', label: 'Dashboard' },
  { href: '/accounts', label: 'Accounts' },
];

/**
 * M0 shell: sidebar + dashboard. Milestone P2 introduces the full
 * navigation driven by RBAC permissions (screen specs: WS5).
 */
export default function Shell({ children, active }: { children: React.ReactNode; active: string }) {
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
        <p style={{ marginTop: 24, color: 'var(--np-muted)', fontSize: 12 }}>
          {version}
          <br />
          <span className="np-badge">M0 preview</span>
        </p>
      </aside>
      <main className="np-main">{children}</main>
    </div>
  );
}
