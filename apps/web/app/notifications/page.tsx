'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, getUser } from '../../lib/api';
import Shell from '../shell';
import { Icon } from '../icons';

/**
 * Notification center (B13, API spec §4.23) — strictly your own feed:
 * security alerts (audit-chain verification failures), webhook
 * dead-letters, and per-feature results.
 */

interface NotificationDto {
  id: string;
  category: string;
  title: string;
  body: string;
  action_url: string | null;
  severity: string;
  read_at: string | null;
  created_at: string;
}

const SEV_ICON: Record<string, 'alert' | 'bell' | 'check'> = {
  error: 'alert',
  warning: 'bell',
  info: 'check',
};

export default function NotificationsPage() {
  const [items, setItems] = useState<NotificationDto[] | null>(null);
  const [unread, setUnread] = useState(0);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const n = await api<{ data: NotificationDto[]; unread: number }>('/notifications');
      setItems(n.data ?? []);
      setUnread(n.unread ?? 0);
    } catch {
      setItems([]);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function markRead(n: NotificationDto) {
    if (n.read_at) return;
    setBusy(true);
    try {
      await api(`/notifications/${n.id}/read`, { method: 'POST' });
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function markAll() {
    setBusy(true);
    try {
      await api('/notifications/read-all', { method: 'POST' });
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell active="/notifications">
      <div className="np-stack">
        <div className="np-page-head">
          <div>
            <h1 className="np-title">
              Notifications <span>· {unread} unread</span>
            </h1>
            <p className="lede">
              Things you should know about: security alerts, undeliverable
              webhooks, and finished work that needs a look.
            </p>
          </div>
          {unread > 0 && (
            <button className="np-button np-button-ghost" disabled={busy} onClick={() => void markAll()}>
              Mark all as read
            </button>
          )}
        </div>

        <section className="np-card">
          <div className="np-card-head">
            <h3>
              <span className="ico">
                <Icon name="bell" />
              </span>
              Inbox
            </h3>
            <span className={`np-badge ${unread > 0 ? 'warn' : 'ok'}`}>{unread} unread</span>
          </div>
          {items === null ? (
            <p className="np-muted">Loading…</p>
          ) : items.length === 0 ? (
            <div className="np-empty">You’re all caught up — nothing here yet.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {items.map((n) => (
                <button
                  key={n.id}
                  onClick={() => void markRead(n)}
                  style={{
                    display: 'flex', gap: 12, alignItems: 'flex-start', textAlign: 'left',
                    padding: '12px 10px', border: 'none', background: 'transparent',
                    borderRadius: 10, cursor: n.read_at ? 'default' : 'pointer', width: '100%',
                    fontFamily: 'inherit', color: 'inherit',
                    opacity: n.read_at ? 0.62 : 1,
                  }}
                >
                  <span
                    style={{
                      width: 30, height: 30, borderRadius: 8, flexShrink: 0,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background:
                        n.severity === 'error' ? 'var(--np-danger-soft)' : n.severity === 'warning' ? 'var(--np-warning-soft)' : 'var(--np-accent-soft)',
                      color: n.severity === 'error' ? 'var(--np-danger)' : n.severity === 'warning' ? 'var(--np-warning)' : 'var(--np-primary)',
                    }}
                  >
                    <Icon name={SEV_ICON[n.severity] ?? 'bell'} size={14} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <b style={{ display: 'block', fontSize: 13 }}>{n.title}</b>
                    <span className="np-muted" style={{ fontSize: 12, display: 'block', lineHeight: 1.45 }}>{n.body}</span>
                    <span className="np-muted-2" style={{ fontSize: 10.5, color: 'var(--np-muted-2)', display: 'block', marginTop: 3 }}>
                      {n.category} · {new Date(n.created_at).toLocaleString()}
                      {n.action_url ? ` · ${n.action_url}` : ''}
                    </span>
                  </span>
                  {!n.read_at && <span className="np-badge info">new</span>}
                </button>
              ))}
            </div>
          )}
        </section>
      </div>
    </Shell>
  );
}
