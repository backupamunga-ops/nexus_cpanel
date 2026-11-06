import { Inject, Logger } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import * as net from 'node:net';
import type { WebSocket } from 'ws';
import type { Server } from 'ws';
import { JwtService } from '../auth/jwt.service';
import { AgentClientService } from '../agent/agent-client.service';
import { PrismaService } from '../prisma/prisma.service';
import { AUDIT_APPENDER, AuditAppender } from '../audit/audit.service';
import { ACCOUNT_ROLE_PERMISSIONS } from '../common/permissions';

/**
 * Web-terminal gateway (ADR-0023): one browser WebSocket per shell session
 * (path /api/v1/terminal, JWT via ?token= — same handshake as /events).
 *
 * Trust path, end to end:
 *
 *   browser ws ── JWT ─▶ this gateway ── signed terminal.open ─▶ agent pty
 *                            │  C7 ownership check (access row role grants
 *                            │  terminal:use; super admin passes)
 *                            │  audit: terminal.open success/failure,
 *                            │  terminal.close with duration
 *                            ▼
 *              agent-side limits (max 3 sessions, 15m idle, 8h lifetime)
 *
 * The gateway is a pure relay: it never inspects or logs terminal content.
 * Wire protocol toward the agent is the length-prefixed framing of
 * apps/agent/internal/term/frame.go; toward the browser it is the same
 * `{event, data}` JSON the /events gateway uses, with base64 payloads.
 */

// Frame types — mirror FrameInput/…/FrameError in term/frame.go.
const FRAME_INPUT = 0x01;
const FRAME_RESIZE = 0x02;
const FRAME_PING = 0x03;
const FRAME_OUTPUT = 0x10;
const FRAME_EXIT = 0x11;
const FRAME_ERROR = 0x12;

// Frame payload cap — mirror maxFrameSize (64 KiB) in term/frame.go.
const MAX_FRAME = 64 * 1024;

interface TerminalState {
  userId: string;
  openedAt: number;
  username?: string;
  accountId?: string;
  opening: boolean;
  socket?: net.Socket;
  closed: boolean;
}

interface AgentFrame {
  type: number;
  payload: Buffer;
}

function encodeFrame(type: number, payload: Buffer = Buffer.alloc(0)): Buffer {
  const hdr = Buffer.alloc(5);
  hdr.writeUInt8(type, 0);
  hdr.writeUInt32BE(payload.length, 1);
  return Buffer.concat([hdr, payload]);
}

/** Reassembles length-prefixed agent frames from arbitrary socket chunks. */
class FrameReader {
  private buf = Buffer.alloc(0);

  push(chunk: Buffer): AgentFrame[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    const frames: AgentFrame[] = [];
    for (;;) {
      if (this.buf.length < 5) break;
      const len = this.buf.readUInt32BE(1);
      if (len > MAX_FRAME) {
        // Protocol violation from the agent side is impossible in practice;
        // drop the stream rather than buffer without bound.
        this.buf = Buffer.alloc(0);
        throw new Error(`agent frame exceeds ${MAX_FRAME} bytes`);
      }
      if (this.buf.length < 5 + len) break;
      const type = this.buf.readUInt8(0);
      const payload = this.buf.subarray(5, 5 + len);
      frames.push({ type, payload: Buffer.from(payload) });
      this.buf = this.buf.subarray(5 + len);
    }
    return frames;
  }
}

function clampDim(v: unknown, min: number, max: number, def: number): number {
  const n = Math.round(Number(v));
  if (!Number.isFinite(n) || n <= 0) return def;
  return Math.min(max, Math.max(min, n));
}

@WebSocketGateway({ path: '/api/v1/terminal' })
export class TerminalGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(TerminalGateway.name);
  private readonly states = new WeakMap<WebSocket, TerminalState>();

  constructor(
    private readonly jwt: JwtService,
    private readonly agent: AgentClientService,
    private readonly prisma: PrismaService,
    @Inject(AUDIT_APPENDER) private readonly audit: AuditAppender,
  ) {}

  handleConnection(client: WebSocket, ...args: unknown[]): void {
    const req = args[0] as { url?: string } | undefined;
    const token = new URL(req?.url ?? '', 'http://localhost').searchParams.get('token');
    const claims = token ? this.jwt.verify(token) : null;
    if (!claims) {
      client.close(4401, 'invalid or expired token');
      return;
    }
    this.states.set(client, { userId: claims.sub, openedAt: Date.now(), opening: false, closed: false });
    this.send(client, 'terminal:hello', { user_id: claims.sub });
  }

  handleDisconnect(client: WebSocket): void {
    const st = this.states.get(client);
    if (st) {
      st.closed = true;
      st.socket?.destroy(); // agent-side cleanup + terminal.close audit
      this.states.delete(client);
    }
  }

  @SubscribeMessage('terminal:open')
  async open(client: WebSocket, data: { username?: string; cols?: number; rows?: number }): Promise<void> {
    const st = this.states.get(client);
    if (!st || st.socket || st.opening || st.closed) return;
    st.opening = true;

    const username = String(data?.username ?? '');
    const cols = clampDim(data?.cols, 2, 500, 80);
    const rows = clampDim(data?.rows, 2, 300, 24);

    try {
      // Visibility first (C7, anti-enumeration): an unknown/invisible
      // account and an invisible-caller account both answer not_found.
      const account = await this.prisma.hostingAccount.findFirst({
        where: { username, deleted_at: null },
        select: { id: true, username: true, status: true },
      });
      if (!account) {
        this.send(client, 'terminal:closed', { reason: 'not_found' });
        return;
      }

      const user = await this.prisma.user.findUnique({
        where: { id: st.userId },
        select: { is_super_admin: true },
      });
      let allowed = user?.is_super_admin === true;
      if (!allowed) {
        const access = await this.prisma.userHostingAccountAccess.findFirst({
          where: { user_id: st.userId, hosting_account_id: account.id, revoked_at: null },
          select: { role: true },
        });
        allowed =
          !!access &&
          (ACCOUNT_ROLE_PERMISSIONS[access.role] ?? []).includes('terminal:use');
      }
      if (!allowed) {
        await this.audit.append({
          operation: 'terminal.open',
          parameters: { username, outcome_reason: 'permission_denied' },
          outcome: 'failure',
          actorUserId: st.userId,
          hostingAccountId: account.id,
        });
        this.send(client, 'terminal:closed', { reason: 'permission_denied' });
        return;
      }
      if (account.status !== 'active') {
        this.send(client, 'terminal:closed', {
          reason: `account is ${account.status} — terminal refused (resume the account first)`,
        });
        return;
      }

      let socket: net.Socket;
      try {
        socket = await this.agent.openTerminalStream({ username, cols, rows });
      } catch (e) {
        await this.audit.append({
          operation: 'terminal.open',
          parameters: { username, outcome_reason: (e as Error).message },
          outcome: 'failure',
          actorUserId: st.userId,
          hostingAccountId: account.id,
        });
        this.send(client, 'terminal:closed', { reason: (e as Error).message });
        return;
      }

      st.socket = socket;
      st.username = username;
      st.accountId = account.id;
      await this.audit.append({
        operation: 'terminal.open',
        parameters: { username, cols, rows },
        outcome: 'success',
        actorUserId: st.userId,
        hostingAccountId: account.id,
      });
      this.send(client, 'terminal:ready', { username });
      this.logger.log(`terminal session opened (${username} by ${st.userId})`);

      const reader = new FrameReader();
      socket.on('data', (chunk: Buffer) => {
        let frames: AgentFrame[];
        try {
          frames = reader.push(chunk);
        } catch (e) {
          this.send(client, 'terminal:error', { message: (e as Error).message });
          socket.destroy();
          return;
        }
        for (const f of frames) {
          if (f.type === FRAME_OUTPUT) {
            this.send(client, 'terminal:out', { data: f.payload.toString('base64') });
          } else if (f.type === FRAME_EXIT) {
            this.finish(client, f.payload.toString('utf8'));
            return;
          } else if (f.type === FRAME_ERROR) {
            try {
              const msg = JSON.parse(f.payload.toString('utf8')) as { message?: string };
              this.send(client, 'terminal:error', { message: msg.message ?? 'agent error' });
            } catch {
              this.send(client, 'terminal:error', { message: 'agent error' });
            }
          }
          // Unknown agent frames are ignored — the session stays usable.
        }
      });
      socket.on('close', () => this.finish(client, JSON.stringify({ status: null, reason: 'stream_closed' })));
      socket.on('error', (e: Error) => {
        this.send(client, 'terminal:error', { message: e.message });
      });
    } finally {
      st.opening = false;
    }
  }

  @SubscribeMessage('terminal:in')
  input(client: WebSocket, data: { data?: string }): void {
    const st = this.states.get(client);
    if (!st?.socket) return;
    const buf = Buffer.from(String(data?.data ?? ''), 'base64');
    if (buf.length === 0 || buf.length > MAX_FRAME) return;
    st.socket.write(encodeFrame(FRAME_INPUT, buf));
  }

  @SubscribeMessage('terminal:resize')
  resize(client: WebSocket, data: { cols?: number; rows?: number }): void {
    const st = this.states.get(client);
    if (!st?.socket) return;
    const payload = Buffer.alloc(4);
    payload.writeUInt16BE(clampDim(data?.cols, 2, 500, 80), 0);
    payload.writeUInt16BE(clampDim(data?.rows, 2, 300, 24), 2);
    st.socket.write(encodeFrame(FRAME_RESIZE, payload));
  }

  /** Browser keepalive — also refreshes the agent's idle timer. */
  @SubscribeMessage('terminal:ping')
  ping(client: WebSocket): void {
    const st = this.states.get(client);
    st?.socket?.write(encodeFrame(FRAME_PING));
  }

  /** Browser-initiated close: destroy the stream; the agent does the rest. */
  @SubscribeMessage('terminal:close')
  close(client: WebSocket): void {
    const st = this.states.get(client);
    if (st?.socket) {
      st.socket.destroy();
    }
  }

  /** Single end-of-session path: audit + notify, idempotent. */
  private finish(client: WebSocket, exitPayload: string): void {
    const st = this.states.get(client);
    if (!st || st.closed) return;
    st.closed = true;
    const durationSec = Math.round((Date.now() - st.openedAt) / 1000);
    let exit: { status?: number | null; reason?: string } = {};
    try {
      exit = JSON.parse(exitPayload) as { status?: number | null; reason?: string };
    } catch {
      // tolerate a malformed exit frame — the session is over either way
    }
    void this.audit
      .append({
        operation: 'terminal.close',
        parameters: {
          username: st.username ?? null,
          session_id: null,
          duration_sec: durationSec,
          exit_status: exit.status ?? null,
          reason: exit.reason ?? null,
        },
        outcome: 'success',
        actorUserId: st.userId,
        hostingAccountId: st.accountId ?? null,
      })
      .catch(() => undefined);
    if (st.socket) {
      st.socket.destroy();
      st.socket = undefined;
    }
    this.send(client, 'terminal:exit', { status: exit.status ?? null, reason: exit.reason ?? null });
    this.send(client, 'terminal:closed', { reason: exit.reason ?? 'session_ended' });
    if (st.username) {
      this.logger.log(`terminal session ended (${st.username}, ${durationSec}s, reason=${exit.reason ?? 'exit'})`);
    }
    this.states.delete(client);
  }

  private send(client: WebSocket, event: string, data: unknown): void {
    if (client.readyState === 1) {
      client.send(JSON.stringify({ event, data }));
    }
  }
}
