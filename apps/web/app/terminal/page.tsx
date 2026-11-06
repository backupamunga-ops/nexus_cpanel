'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { Terminal as XTerm } from '@xterm/xterm';
import type { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { api, getAccessToken, getUser } from '../../lib/api';
import { TerminalClient, toBase64Utf8 } from '../../lib/terminal';
import Shell from '../shell';

/**
 * Terminal screen (ADR-0023): shell access to the node, per hosting account.
 * DirectAdmin-style minimalism — pick the account, connect, type. The session
 * is a real PTY (job control, colors, resize) audited open-to-close in the
 * hash chain; root shells are refused by the agent by design.
 */

interface Account {
  id: string;
  username: string;
  status: string;
  my_role?: string;
}

type Status = 'idle' | 'connecting' | 'connected' | 'ended';

const ROLES_WITH_TERMINAL = new Set(['owner', 'admin']);

export default function TerminalPage() {
  const [user, setUser] = useState<ReturnType<typeof getUser>>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [status, setStatus] = useState<Status>('idle');
  const [message, setMessage] = useState<string | null>(null);

  const termHostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const clientRef = useRef<TerminalClient | null>(null);
  const resizeObsRef = useRef<ResizeObserver | null>(null);
  const statusRef = useRef<Status>('idle');
  statusRef.current = status;

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
      return;
    }
    (async () => {
      try {
        const j = await api<{ data: Account[] }>('/accounts');
        const active = (j.data ?? []).filter((a) => a.status === 'active');
        setAccounts(active);
        if (active.length > 0) setSelected(active[0].username);
      } catch (err) {
        setMessage(err instanceof Error ? err.message : 'could not load accounts');
      }
    })();
    return () => {
      clientRef.current?.close();
      resizeObsRef.current?.disconnect();
      termRef.current?.dispose();
    };
  }, []);

  const cleanupSession = useCallback(() => {
    resizeObsRef.current?.disconnect();
    resizeObsRef.current = null;
    clientRef.current?.close();
    clientRef.current = null;
  }, []);

  const connect = useCallback(async () => {
    if (!selected || status === 'connecting' || status === 'connected') return;
    const token = getAccessToken();
    if (!token) {
      window.location.href = '/login';
      return;
    }
    const host = termHostRef.current;
    if (!host) return;

    setMessage(null);
    setStatus('connecting');
    cleanupSession();

    // Fresh terminal per session (a stale scrollback is a stale session).
    termRef.current?.dispose();
    const { Terminal } = await import('@xterm/xterm');
    const { FitAddon } = await import('@xterm/addon-fit');
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: "'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace",
      theme: {
        background: '#101418',
        foreground: '#d7dde3',
        cursor: '#4cc38a',
        selectionBackground: '#2c3e50',
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const client = new TerminalClient();
    clientRef.current = client;

    client.connect(token, selected, term.cols, term.rows, {
      onReady: (username) => {
        setStatus('connected');
        term.focus();
        term.writeln(`\x1b[36m— connected as ${username} —\x1b[0m`);
      },
      onOut: (b64) => {
        term.write(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
      },
      onExit: (info) => {
        const why = info.reason ? ` — ${info.reason}` : '';
        term.writeln(`\r\n\x1b[33m[session ended${why}]\x1b[0m`);
        setStatus('ended');
        cleanupSession();
      },
      onError: (msg) => {
        term.writeln(`\r\n\x1b[31m[error] ${msg}\x1b[0m`);
      },
      onClosed: (reason) => {
        if (statusRef.current === 'connected' || statusRef.current === 'connecting') {
          const why = reason ? ` — ${reason}` : '';
          term.writeln(`\r\n\x1b[33m[connection closed${why}]\x1b[0m`);
          setStatus('ended');
          cleanupSession();
        }
      },
    });

    // Keystrokes → base64 → relay. The panel never inspects the bytes.
    term.onData((d) => client.input(toBase64Utf8(d)));

    // Container resize → pty resize (TIOCSWINSZ end-to-end).
    const obs = new ResizeObserver(() => {
      try {
        fit.fit();
        client.resize(term.cols, term.rows);
      } catch {
        // fit throws on zero-size containers (collapsed panel) — harmless
      }
    });
    obs.observe(host);
    resizeObsRef.current = obs;
  }, [selected, status, cleanupSession]);

  const disconnect = useCallback(() => {
    clientRef.current?.close();
    clientRef.current = null;
    setStatus('ended');
    termRef.current?.writeln('\x1b[33m[disconnected]\x1b[0m');
  }, []);

  const canOpen = (a: Account): boolean =>
    user?.is_super_admin === true ||
    (a.my_role ? ROLES_WITH_TERMINAL.has(a.my_role) : false);

  const selectedAccount = accounts.find((a) => a.username === selected);
  const busy = status === 'connecting' || status === 'connected';

  return (
    <Shell active="/terminal" user={user}>
      <h1 className="np-title">Terminal</h1>
      <p className="np-subtitle">
        Shell access on the node as the selected hosting account. Every session is
        audited open-to-close; idle sessions are closed after 15 minutes, and root
        shells are refused by the agent by design.
      </p>

      <div
        className="np-card"
        style={{ marginTop: 24, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}
      >
        <label htmlFor="terminal-account" style={{ fontWeight: 600 }}>
          Account
        </label>
        <select
          id="terminal-account"
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          disabled={busy}
          style={{ padding: '6px 10px', borderRadius: 6 }}
        >
          {accounts.length === 0 && <option value="">no hosting accounts yet</option>}
          {accounts.map((a) => (
            <option key={a.id} value={a.username} disabled={!canOpen(a)}>
              {a.username}
              {!canOpen(a) ? ' — needs owner/admin role' : ''}
            </option>
          ))}
        </select>
        {status === 'connected' ? (
          <button className="np-button" onClick={disconnect}>
            Disconnect
          </button>
        ) : (
          <button
            className="np-button"
            onClick={() => void connect()}
            disabled={!selected || !selectedAccount || !canOpen(selectedAccount) || busy}
          >
            {status === 'connecting' ? 'Connecting…' : status === 'ended' ? 'Reconnect' : 'Connect'}
          </button>
        )}
        <span style={{ color: 'var(--np-muted)', fontSize: 12 }}>
          {status === 'connected'
            ? `live — ${selected}`
            : status === 'connecting'
              ? 'opening pty…'
              : status === 'ended'
                ? 'session ended'
                : 'not connected'}
        </span>
      </div>

      <div
        ref={termHostRef}
        style={{
          marginTop: 16,
          height: 480,
          background: '#101418',
          borderRadius: 8,
          padding: 8,
        }}
      />
      {message && (
        <p role="status" style={{ marginTop: 12, color: 'var(--np-muted)' }}>
          {message}
        </p>
      )}
    </Shell>
  );
}
