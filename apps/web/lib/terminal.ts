'use client';

/**
 * Web-terminal client (ADR-0023): one WebSocket per shell session, same
 * handshake as the /events stream (JWT via ?token=). Frames toward the
 * control plane are the `{event, data}` JSON envelopes; shell bytes travel
 * base64 inside them. The relay and the agent never see anything beyond
 * what the user types — there is no command channel.
 */

const BASE_WS = typeof window !== 'undefined'
  ? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/v1/terminal`
  : 'ws://localhost:3000/api/v1/terminal';

export interface TerminalExitInfo {
  status: number | null;
  reason: string | null;
}

export interface TerminalHandlers {
  onReady: (username: string) => void;
  onOut: (base64: string) => void;
  onExit: (info: TerminalExitInfo) => void;
  onError: (message: string) => void;
  onClosed: (reason: string | null) => void;
}

export class TerminalClient {
  private ws: WebSocket | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private handlers: TerminalHandlers | null = null;
  private exited = false;

  connect(token: string, username: string, cols: number, rows: number, handlers: TerminalHandlers): void {
    this.handlers = handlers;
    this.exited = false;
    const ws = new WebSocket(`${BASE_WS}?token=${encodeURIComponent(token)}`);
    this.ws = ws;

    ws.onopen = () => {
      this.send('terminal:open', { username, cols, rows });
      // Keepalive: refreshes the agent idle timer and survives proxies.
      this.pingTimer = setInterval(() => this.send('terminal:ping', {}), 30_000);
    };
    ws.onmessage = (ev) => {
      try {
        const { event, data } = JSON.parse(String(ev.data)) as {
          event: string;
          data: Record<string, unknown>;
        };
        const h = this.handlers;
        if (!h) return;
        if (event === 'terminal:ready') {
          h.onReady(String(data.username ?? username));
        } else if (event === 'terminal:out') {
          h.onOut(String(data.data ?? ''));
        } else if (event === 'terminal:exit') {
          this.exited = true;
          h.onExit({
            status: (data.status as number | null) ?? null,
            reason: (data.reason as string | null) ?? null,
          });
        } else if (event === 'terminal:error') {
          h.onError(String(data.message ?? 'unknown error'));
        } else if (event === 'terminal:closed') {
          h.onClosed((data.reason as string | null) ?? null);
        }
      } catch {
        // Ignore malformed frames.
      }
    };
    ws.onclose = () => {
      this.stopPing();
      if (!this.exited) this.handlers?.onClosed(null);
    };
  }

  /** Sends keystrokes (base64 of the UTF-8 bytes). */
  input(base64: string): void {
    this.send('terminal:in', { data: base64 });
  }

  resize(cols: number, rows: number): void {
    this.send('terminal:resize', { cols, rows });
  }

  close(): void {
    this.stopPing();
    this.send('terminal:close', {});
    this.ws?.close();
    this.ws = null;
  }

  private stopPing(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private send(event: string, data: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ event, data }));
    }
  }
}

/** UTF-8 safe base64 for xterm's onData strings (paste, IME, accents). */
export function toBase64Utf8(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}
