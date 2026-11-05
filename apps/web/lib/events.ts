'use client';

/**
 * Live event stream client (M0): WebSocket /events with JWT auth, auto
 * resubscribe, and a typed event surface. Reconnects with the (possibly
 * refreshed) token; usage sampling itself is server-pushed.
 */

const BASE_WS = typeof window !== 'undefined'
  ? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/v1/events`
  : 'ws://localhost:3000/api/v1/events';

export interface UsageSample {
  username?: string;
  cpu_usec?: number;
  mem_bytes?: number;
  disk_bytes?: number;
  procs?: number;
  [k: string]: unknown;
}

type Handlers = {
  onUsage: (accountId: string, usage: UsageSample, at: string) => void;
  onError?: (accountId: string, error: string) => void;
  onReady?: (pollMs: number) => void;
};

export class EventsStream {
  private ws: WebSocket | null = null;
  private subscriptions = new Set<string>();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private closed = false;

  constructor(
    private readonly getToken: () => string | null,
    private readonly handlers: Handlers,
  ) {}

  start(): void {
    this.closed = false;
    this.connect();
  }

  stop(): void {
    this.closed = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close();
    this.ws = null;
  }

  /** Subscribes (or re-subscribes after reconnect) to an account's usage. */
  subscribe(accountId: string): void {
    this.subscriptions.add(accountId);
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.send('accounts:subscribe', { account_id: accountId });
    }
  }

  unsubscribe(accountId: string): void {
    this.subscriptions.delete(accountId);
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.send('accounts:unsubscribe', { account_id: accountId });
    }
  }

  private connect(): void {
    const token = this.getToken();
    if (!token || this.closed) return;
    const ws = new WebSocket(`${BASE_WS}?token=${encodeURIComponent(token)}`);
    this.ws = ws;

    ws.onopen = () => {
      for (const id of this.subscriptions) {
        this.send('accounts:subscribe', { account_id: id });
      }
    };
    ws.onmessage = (ev) => {
      try {
        const { event, data } = JSON.parse(String(ev.data)) as { event: string; data: Record<string, unknown> };
        if (event === 'ready') {
          this.handlers.onReady?.(Number(data.poll_ms ?? 5000));
        } else if (event === 'accounts:usage') {
          this.handlers.onUsage(String(data.account_id), (data.usage ?? {}) as UsageSample, String(data.at ?? ''));
        } else if (event === 'accounts:usage_error') {
          this.handlers.onError?.(String(data.account_id), String(data.error ?? 'unknown'));
        }
      } catch {
        // Ignore malformed frames.
      }
    };
    ws.onclose = (ev) => {
      if (ev.code === 4401) {
        // Access token expired/invalid — retry with a fresh one shortly.
      }
      if (!this.closed) {
        this.reconnectTimer = setTimeout(() => this.connect(), 3000);
      }
    };
    ws.onerror = () => ws.close();
  }

  private send(event: string, data: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ event, data }));
    }
  }
}
