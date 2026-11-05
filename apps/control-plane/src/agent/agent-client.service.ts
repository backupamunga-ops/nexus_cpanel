import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import * as crypto from 'node:crypto';
import * as http from 'node:http';

/**
 * Client for the NexusPanel Go agent (specs/nexuspanel-agent-spec-v1.0.md §3).
 *
 * Every command is JSON-RPC 2.0 with an Ed25519 signature over
 *   method || raw_params || issued_at || expires_at
 * exactly as the agent's auth package verifies it. There is no other way to
 * talk to the agent — the allowlist on the agent side is the security boundary.
 */
export interface RpcResult<T = unknown> {
  jsonrpc: '2.0';
  id: string;
  result: T;
  error: null | { code: number; message: string; data?: unknown };
  audit?: { entry_id?: string; prior_hash?: string; this_hash?: string };
}

export interface AccountCreateResult {
  uid: number;
  gid: number;
  homedir: string;
}

const RPC_ERRORS: Record<number, number> = {
  [-32000]: 403, // permission denied
  [-32001]: 503, // precondition failed (agent/service state)
  [-32002]: 409, // conflict
  [-32003]: 504, // timeout / expired command
  [-32004]: 429, // quota exceeded
  [-32005]: 503, // control plane unreachable (write rejected)
  [-32601]: 500, // method not found = deployment bug
  [-32602]: 422, // invalid params
};

@Injectable()
export class AgentClientService {
  private readonly logger = new Logger(AgentClientService.name);
  private readonly socketPath: string;
  private signingKey: crypto.KeyObject | null = null;

  constructor() {
    this.socketPath = process.env.AGENT_SOCKET_PATH || '/tmp/nexuspanel-agent.sock';
    const keyPath = process.env.CP_SIGNING_KEY_PATH;
    if (keyPath) {
      try {
        this.signingKey = crypto.createPrivateKey({
          key: readFileSync(keyPath),
          format: 'pem',
        });
        if (this.signingKey.asymmetricKeyType !== 'ed25519') {
          throw new Error(`key is ${this.signingKey.asymmetricKeyType}, want ed25519`);
        }
      } catch (e) {
        this.logger.error(`failed to load signing key at ${keyPath}: ${(e as Error).message}`);
        this.signingKey = null;
      }
    }
    if (!this.signingKey) {
      this.logger.warn(
        'NO SIGNING KEY LOADED — commands will only work against an agent in dev mode. ' +
          'Run `npm run keys:generate` and set CP_SIGNING_KEY_PATH.',
      );
    }
  }

  /** Issues a signed command and returns the parsed response. */
  async call<T>(method: string, params: Record<string, unknown>): Promise<RpcResult<T>> {
    const rawParams = Buffer.from(JSON.stringify(params), 'utf8');
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + 30_000);
    const issued = issuedAt.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const expires = expiresAt.toISOString().replace(/\.\d{3}Z$/, 'Z');

    const id = `req_${crypto.randomUUID()}`;
    const signature = this.sign(method, rawParams, issued, expires);

    const body: Record<string, unknown> = {
      jsonrpc: '2.0',
      id,
      method,
      params: JSON.parse(rawParams.toString('utf8')),
      issued_at: issued,
      expires_at: expires,
    };
    if (signature) {
      body.signature = signature;
    }

    return this.transport<T>(method, body);
  }

  /** Ed25519 signature over method || raw_params || issued_at || expires_at. */
  private sign(
    method: string,
    rawParams: Buffer,
    issuedAt: string,
    expiresAt: string,
  ): string | null {
    if (!this.signingKey) {
      return null;
    }
    const input = Buffer.concat([
      Buffer.from(method, 'utf8'),
      rawParams,
      Buffer.from(issuedAt, 'utf8'),
      Buffer.from(expiresAt, 'utf8'),
    ]);
    const sig = crypto.sign(null, input, this.signingKey);
    return sig.toString('base64');
  }

  /** HTTP-over-unix-socket transport to the agent. */
  private transport<T>(method: string, body: Record<string, unknown>): Promise<RpcResult<T>> {
    const payload = JSON.stringify(body);
    return new Promise<RpcResult<T>>((resolve, reject) => {
      const req = http.request(
        {
          socketPath: this.socketPath,
          path: '/',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
          timeout: 10_000,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcResult<T>;
              if (parsed.error) {
                reject(
                  new ServiceUnavailableException(
                    `agent rejected ${method}: ${parsed.error.message} (${parsed.error.code})`,
                  ),
                );
                return;
              }
              resolve(parsed);
            } catch (e) {
              reject(new Error(`agent returned unparseable response: ${(e as Error).message}`));
            }
          });
        },
      );
      req.on('timeout', () => {
        req.destroy(new Error(`agent timeout on ${method}`));
      });
      req.on('error', (e: NodeJS.ErrnoException) => {
        if (e.code === 'ECONNREFUSED' || e.code === 'ENOENT') {
          reject(
            new ServiceUnavailableException(
              `agent unreachable at ${this.socketPath} (${e.code}) while calling ${method}`,
            ),
          );
          return;
        }
        reject(e);
      });
      req.write(payload);
      req.end();
    });
  }

  // ---- typed convenience wrappers (M0 allowlist slice) ----------------------

  async systemHealth(): Promise<Record<string, string>> {
    const r = await this.call<Record<string, string>>('system.health', {});
    return r.result;
  }

  async accountCreate(username: string, packageId: string): Promise<AccountCreateResult> {
    const r = await this.call<AccountCreateResult>('account.create', {
      username,
      package_id: packageId,
      isolation_profile: 'standard',
    });
    return r.result;
  }

  async accountSuspend(username: string): Promise<void> {
    await this.call('account.suspend', { username });
  }

  async accountResume(username: string): Promise<void> {
    await this.call('account.resume', { username });
  }

  /** Provisions the account's cgroup v2 slice (M0 spec §2.4). */
  async isolationProvision(username: string, profile = 'standard'): Promise<void> {
    await this.call('isolation.provision', { username, profile });
  }

  async accountDelete(username: string): Promise<void> {
    await this.call('account.delete', { username, preserve_files: true });
  }

  async accountUsage(username: string): Promise<Record<string, number | string>> {
    const r = await this.call<Record<string, number | string>>('account.usage', { username });
    return r.result;
  }

  /** Exposed for tests: the exact bytes that were signed. */
  static signatureInput(
    method: string,
    rawParams: Buffer,
    issuedAt: string,
    expiresAt: string,
  ): Buffer {
    return Buffer.concat([
      Buffer.from(method, 'utf8'),
      rawParams,
      Buffer.from(issuedAt, 'utf8'),
      Buffer.from(expiresAt, 'utf8'),
    ]);
  }
}

function readFileSync(p: string): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('node:fs').readFileSync(p, 'utf8');
}

export const RPC_ERROR_MAP = RPC_ERRORS;
