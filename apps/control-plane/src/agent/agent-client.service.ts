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

  /** Applies cgroup v2 limits for an account (spec §4.1; agent returns applied/skipped). */
  async accountQuota(
    username: string,
    quotas: Record<string, number>,
  ): Promise<{ applied: string[]; skipped: Array<{ key: string; reason: string }> }> {
    const r = await this.call<{ applied: string[]; skipped: Array<{ key: string; reason: string }> }>(
      'account.quota',
      { username, quotas },
    );
    return r.result;
  }

  /** Modifies an existing account: quotas and/or isolation profile (spec §4.1). */
  async accountModify(
    username: string,
    opts: { quotas?: Record<string, number>; isolation_profile?: string } = {},
  ): Promise<{ status: string; applied: string[]; skipped?: Array<{ key: string; reason: string }> }> {
    const params: Record<string, unknown> = { username };
    if (opts.quotas !== undefined) {
      params['quotas'] = opts.quotas;
    }
    if (opts.isolation_profile !== undefined) {
      params['isolation_profile'] = opts.isolation_profile;
    }
    const r = await this.call<{
      status: string;
      applied: string[];
      skipped?: Array<{ key: string; reason: string }>;
    }>('account.modify', params);
    return r.result;
  }

  async accountUsage(username: string): Promise<Record<string, number | string>> {
    const r = await this.call<Record<string, number | string>>('account.usage', { username });
    return r.result;
  }

  // ---- P3: sites & domains (filesystem.mkdir + nginx.* §4.3/§4.7) ----------

  /** Creates a directory (and parents) inside the account home (C13-confined). */
  async filesystemMkdir(
    username: string,
    path: string,
    mode?: number,
  ): Promise<{ path: string; created: boolean }> {
    const params: Record<string, unknown> = { username, path, owner: username };
    if (mode !== undefined) {
      params['mode'] = mode;
    }
    const r = await this.call<{ path: string; created: boolean }>('filesystem.mkdir', params);
    return r.result;
  }

  /** Applies a domain vhost: staging → atomic swap → health gate → rollback. */
  async nginxApplyVhost(
    domain: string,
    content: string,
  ): Promise<{ status: string; health_check: string; health_detail?: string; previous_existed: boolean }> {
    const r = await this.call<{
      status: string;
      health_check: string;
      health_detail?: string;
      previous_existed: boolean;
    }>('nginx.apply_vhost', { domain, content });
    return r.result;
  }

  /** Removes a domain vhost (idempotent: absent is a valid answer). */
  async nginxRemoveVhost(
    domain: string,
  ): Promise<{ status: string; health_check?: string; health_detail?: string }> {
    const r = await this.call<{
      status: string;
      health_check?: string;
      health_detail?: string;
    }>('nginx.remove_vhost', { domain });
    return r.result;
  }

  /** On-demand nginx config test (skipped with a reason when no binary). */
  async nginxTest(): Promise<{ status: string; detail?: string }> {
    const r = await this.call<{ status: string; detail?: string }>('nginx.test', {});
    return r.result;
  }

  /** Graceful nginx reload (skipped with a reason when no binary). */
  async nginxReload(): Promise<{ status: string; detail?: string }> {
    const r = await this.call<{ status: string; detail?: string }>('nginx.reload', {});
    return r.result;
  }

  // ---- P3: files (ADR-0008 filesystem content ops §4.3) --------------------

  async filesystemList(username: string, path: string): Promise<{
    path: string;
    entries: Array<{ name: string; type: string; size_bytes: number; mode: string; modified_at: string }>;
    total: number;
  }> {
    const r = await this.call<{
      path: string;
      entries: Array<{ name: string; type: string; size_bytes: number; mode: string; modified_at: string }>;
      total: number;
    }>('filesystem.list', { username, path });
    return r.result;
  }

  async filesystemRead(
    username: string,
    path: string,
  ): Promise<{ path: string; size_bytes: number; content_b64: string; truncated: boolean }> {
    const r = await this.call<{
      path: string;
      size_bytes: number;
      content_b64: string;
      truncated: boolean;
    }>('filesystem.read', { username, path });
    return r.result;
  }

  async filesystemWrite(
    username: string,
    path: string,
    content_b64: string,
    opts: { mode?: number; overwrite?: boolean } = {},
  ): Promise<{ path: string; written_bytes: number; overwritten: boolean; ownership: string }> {
    const params: Record<string, unknown> = { username, path, content_b64 };
    if (opts.mode !== undefined) params['mode'] = opts.mode;
    if (opts.overwrite !== undefined) params['overwrite'] = opts.overwrite;
    const r = await this.call<{
      path: string;
      written_bytes: number;
      overwritten: boolean;
      ownership: string;
    }>('filesystem.write', params);
    return r.result;
  }

  async filesystemMove(
    username: string,
    from: string,
    to: string,
    overwrite = false,
  ): Promise<{ from: string; to: string }> {
    const r = await this.call<{ from: string; to: string }>('filesystem.move', {
      username,
      from,
      to,
      overwrite,
    });
    return r.result;
  }

  async filesystemDelete(
    username: string,
    path: string,
    toTrash = true,
  ): Promise<{ path: string; trash_path: string; size_bytes: number; purged: boolean }> {
    const r = await this.call<{
      path: string;
      trash_path: string;
      size_bytes: number;
      purged: boolean;
    }>('filesystem.delete', { username, path, to_trash: toTrash });
    return r.result;
  }

  async filesystemChmod(
    username: string,
    path: string,
    mode: number,
  ): Promise<{ path: string; mode: string }> {
    const r = await this.call<{ path: string; mode: string }>('filesystem.chmod', {
      username,
      path,
      mode,
    });
    return r.result;
  }

  async filesystemUsage(username: string): Promise<{ bytes: number; inodes: number; partial: boolean }> {
    const r = await this.call<{ bytes: number; inodes: number; partial: boolean }>(
      'filesystem.usage',
      { username },
    );
    return r.result;
  }

  async trashPurge(username: string, beforeDate: string): Promise<{ removed: string[] }> {
    const r = await this.call<{ removed: string[] }>('filesystem.trash_purge', {
      username,
      before_date: beforeDate,
    });
    return r.result;
  }

  // ---- P3: ssl (§4.11) ------------------------------------------------------

  async sslIssueAcme(
    domain: string,
    email: string,
    webroot: string,
  ): Promise<{
    domain: string;
    issuer: string;
    san_names: string[];
    expires_at: string;
    cert_pem: string;
    key_pem: string;
  }> {
    const r = await this.call<{
      domain: string;
      issuer: string;
      san_names: string[];
      expires_at: string;
      cert_pem: string;
      key_pem: string;
    }>('ssl.issue_acme', { domain, email, webroot, challenge_type: 'http01', san: [] });
    return r.result;
  }

  async sslInstallCert(
    domain: string,
    cert_pem: string,
    key_pem: string,
  ): Promise<{ domain: string; issuer: string; san_names: string[]; expires_at: string; common_name?: string; health_check: string }> {
    const r = await this.call<{
      domain: string;
      issuer: string;
      san_names: string[];
      expires_at: string;
      common_name?: string;
      health_check: string;
    }>('ssl.install_cert', { domain, cert_pem, key_pem });
    return r.result;
  }

  async sslRevoke(domain: string): Promise<{ status: string; existed: boolean }> {
    const r = await this.call<{ status: string; existed: boolean }>('ssl.revoke', { domain });
    return r.result;
  }

  // ---- P3: php (§4.6) -------------------------------------------------------

  async phpCreatePool(
    username: string,
    domain: string,
    version: string,
    config: Record<string, unknown>,
  ): Promise<{ status: string; version: string; pool_file: string; conf_content: string }> {
    const r = await this.call<{
      status: string;
      version: string;
      pool_file: string;
      conf_content: string;
    }>('php.create_pool', { username, domain, version, config });
    return r.result;
  }

  async phpModifyPool(
    username: string,
    domain: string,
    version: string,
    config: Record<string, unknown>,
  ): Promise<{ status: string; version: string; pool_file: string; conf_content: string }> {
    const r = await this.call<{
      status: string;
      version: string;
      pool_file: string;
      conf_content: string;
    }>('php.modify_pool', { username, domain, version, config });
    return r.result;
  }

  async phpDeletePool(username: string, domain: string, version: string): Promise<{ status: string; version: string }> {
    const r = await this.call<{ status: string; version: string }>('php.delete_pool', {
      username,
      domain,
      version,
    });
    return r.result;
  }

  async phpListVersions(): Promise<{ installed: string[] }> {
    const r = await this.call<{ installed: string[] }>('php.list_versions', {});
    return r.result;
  }

  // ---- P3: config engine (§4.5) --------------------------------------------

  async configDriftCheck(
    targetName: string,
    expectedContent: string,
  ): Promise<{
    matches: boolean;
    exists: boolean;
    expected_hash: string;
    actual_hash: string;
    file_path: string;
  }> {
    const r = await this.call<{
      matches: boolean;
      exists: boolean;
      expected_hash: string;
      actual_hash: string;
      file_path: string;
    }>('config.drift_check', {
      target_type: 'nginx_vhost',
      target_name: targetName,
      expected_content: expectedContent,
    });
    return r.result;
  }

  async configListActive(targetName: string): Promise<{ exists: boolean; content: string; file_path: string }> {
    const r = await this.call<{ exists: boolean; content: string; file_path: string }>(
      'config.list_active',
      { target_type: 'nginx_vhost', target_name: targetName },
    );
    return r.result;
  }

  // ---- P4 amendment ADR-0010: ssh.* authorized_keys -------------------------

  async sshDeployKeys(
    username: string,
    keys: Array<{ fingerprint: string; public_key: string }>,
  ): Promise<{ file: string; managed_count: number; foreign_count: number; ownership: string }> {
    const r = await this.call<{
      file: string;
      managed_count: number;
      foreign_count: number;
      ownership: string;
    }>('ssh.deploy_keys', { username, keys });
    return r.result;
  }

  async sshListDeployed(username: string): Promise<{
    file: string;
    exists: boolean;
    managed: Array<{ fingerprint: string; public_key: string }>;
    foreign_count: number;
    ownership: string;
  }> {
    const r = await this.call<{
      file: string;
      exists: boolean;
      managed: Array<{ fingerprint: string; public_key: string }>;
      foreign_count: number;
      ownership: string;
    }>('ssh.list_deployed', { username });
    return r.result;
  }

  // ---- P4 amendment ADR-0011: ftp.* vsftpd virtual users --------------------

  async ftpCreateAccount(input: {
    owner_username: string;
    ftp_username: string;
    password: string;
    root_dir: string;
    read_only: boolean;
  }): Promise<{ status: string; root_dir: string; read_only: boolean; userdb: { rebuilt: boolean; skipped?: string } }> {
    const r = await this.call<{
      status: string;
      root_dir: string;
      read_only: boolean;
      userdb: { rebuilt: boolean; skipped?: string };
    }>('ftp.create_account', input);
    return r.result;
  }

  async ftpDeleteAccount(ftpUsername: string): Promise<{ status: string; userdb: { rebuilt: boolean; skipped?: string } }> {
    const r = await this.call<{ status: string; userdb: { rebuilt: boolean; skipped?: string } }>(
      'ftp.delete_account',
      { ftp_username: ftpUsername },
    );
    return r.result;
  }

  async ftpSetPassword(ftpUsername: string, password: string): Promise<{ status: string; userdb: { rebuilt: boolean; skipped?: string } }> {
    const r = await this.call<{ status: string; userdb: { rebuilt: boolean; skipped?: string } }>(
      'ftp.set_password',
      { ftp_username: ftpUsername, password },
    );
    return r.result;
  }

  async ftpListAccounts(): Promise<{ accounts: Array<{ username: string; root_dir: string; read_only: boolean }> }> {
    const r = await this.call<{
      accounts: Array<{ username: string; root_dir: string; read_only: boolean }>;
    }>('ftp.list_accounts', {});
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
