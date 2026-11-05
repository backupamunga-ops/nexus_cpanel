import { Logger } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { JwtService } from '../auth/jwt.service';
import { AgentClientService } from '../agent/agent-client.service';
import { PrismaService } from '../prisma/prisma.service';
import type { WebSocket } from 'ws';
import type { Server } from 'ws';

/**
 * Real-time event stream (M0 slice of API spec §2.6 — WebSocket /events).
 *
 * Auth: `?token=<access JWT>` on the connect URL; invalid/missing tokens are
 * rejected with 4401 before the socket opens. The claims' `sid` also lets the
 * client keep one stream alive across access-token rotations.
 *
 * Contract (M0):
 *   client → { event: 'accounts:subscribe',   data: { account_id } }
 *   client → { event: 'accounts:unsubscribe', data: { account_id } }
 *   server → { event: 'accounts:usage',       data: { account_id, usage } }  (every POLL_MS)
 *
 * Usage sampling is server-pushed from the agent's `account.usage` — no
 * client polling loop. P2 adds the full event taxonomy (jobs, notifications).
 */

const POLL_MS = Number(process.env.WS_USAGE_POLL_MS ?? 5000);

interface ClientState {
  userId: string;
  // account_id -> poll timer
  subscriptions: Map<string, ReturnType<typeof setInterval>>;
}

@WebSocketGateway({
  path: '/api/v1/events',
})
export class EventsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(EventsGateway.name);
  private readonly states = new WeakMap<WebSocket, ClientState>();

  constructor(
    private readonly jwt: JwtService,
    private readonly agent: AgentClientService,
    private readonly prisma: PrismaService,
  ) {}

  handleConnection(client: WebSocket, ...args: unknown[]): void {
    const req = args[0] as { url?: string } | undefined;
    const token = new URL(req?.url ?? '', 'http://localhost').searchParams.get('token');
    const claims = token ? this.jwt.verify(token) : null;
    if (!claims) {
      client.close(4401, 'invalid or expired token');
      return;
    }
    this.states.set(client, { userId: claims.sub, subscriptions: new Map() });
    this.send(client, 'ready', { user_id: claims.sub, poll_ms: POLL_MS });
    this.logger.debug(`events client connected (${claims.sub})`);
  }

  handleDisconnect(client: WebSocket): void {
    const state = this.states.get(client);
    if (state) {
      for (const t of state.subscriptions.values()) {
        clearInterval(t);
      }
      this.states.delete(client);
    }
  }

  @SubscribeMessage('accounts:subscribe')
  async subscribe(client: WebSocket, data: { account_id?: string }): Promise<void> {
    const state = this.states.get(client);
    const accountId = data?.account_id;
    if (!state || !accountId || state.subscriptions.has(accountId)) {
      return;
    }
    // Visibility check: the account must exist and be live.
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true },
    });
    if (!account) {
      this.send(client, 'error', { code: 'not_found', account_id: accountId });
      return;
    }

    const push = async (): Promise<void> => {
      try {
        const usage = await this.agent.accountUsage(account.username);
        this.send(client, 'accounts:usage', {
          account_id: accountId,
          usage,
          at: new Date().toISOString(),
        });
      } catch (e) {
        this.send(client, 'accounts:usage_error', {
          account_id: accountId,
          error: (e as Error).message,
        });
      }
    };
    await push();
    state.subscriptions.set(accountId, setInterval(() => void push(), POLL_MS));
  }

  @SubscribeMessage('accounts:unsubscribe')
  unsubscribe(client: WebSocket, data: { account_id?: string }): void {
    const state = this.states.get(client);
    const accountId = data?.account_id;
    if (state && accountId) {
      const t = state.subscriptions.get(accountId);
      if (t) {
        clearInterval(t);
        state.subscriptions.delete(accountId);
      }
    }
  }

  private send(client: WebSocket, event: string, data: unknown): void {
    if (client.readyState === 1) {
      client.send(JSON.stringify({ event, data }));
    }
  }
}
