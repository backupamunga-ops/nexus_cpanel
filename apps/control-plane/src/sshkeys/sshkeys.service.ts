import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { Actor } from '../sites/sites.service';

/**
 * SSH keys (API spec §4.13). Panel-side records for per-account public
 * keys: strict key-type allowlist, OpenSSH SHA-256 fingerprint computed at
 * import (a mismatched fingerprint means the stored key is not the key the
 * user pasted — that class of bug dies here).
 *
 * Deployment (ADR-0010): keys are deployed to the account's
 * ~/.ssh/authorized_keys through the agent's ssh.deploy_keys — a
 * managed-line reconcile that preserves hand-added (foreign) keys. The
 * "on node" state is NEVER cached: it is derived live from
 * ssh.list_deployed matched against imported fingerprints, so the UI
 * badge cannot rot (D-11).
 */

const KEY_TYPES = [
  'ssh-ed25519',
  'ssh-rsa',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
];

const KEY_RE =
  /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) ([A-Za-z0-9+/]+={0,2})(?: ([^\n]+))?$/;

export interface SshKeyDto {
  id: string;
  hosting_account_id: string;
  name: string;
  public_key: string;
  fingerprint: string;
  created_at: string;
}

@Injectable()
export class SshKeysService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  private async requireAccount(actor: Actor | undefined, accountId: unknown) {
    if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
      throw new BadRequestException('account_id is required');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true },
    });
    if (!account) {
      throw new NotFoundException('hosting account not found');
    }
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) {
        throw new NotFoundException('hosting account not found');
      }
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: account.id, revoked_at: null },
        select: { id: true },
      });
      if (!access) {
        throw new NotFoundException('hosting account not found');
      }
    }
    return account;
  }

  async list(actor: Actor | undefined, accountId: unknown): Promise<{ data: SshKeyDto[] }> {
    const account = await this.requireAccount(actor, accountId);
    const rows = await this.prisma.sshKey.findMany({
      where: { hosting_account_id: account.id, deleted_at: null },
      orderBy: { created_at: 'desc' },
    });
    return { data: rows.map(toDto) };
  }

  async create(
    actor: Actor | undefined,
    input: { account_id?: unknown; name?: unknown; public_key?: unknown },
  ): Promise<SshKeyDto> {
    const account = await this.requireAccount(actor, input.account_id);

    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (name.length < 1 || name.length > 100) {
      throw new BadRequestException('name is required (1–100 characters)');
    }
    const key = typeof input.public_key === 'string' ? input.public_key.trim() : '';
    const match = KEY_RE.exec(key);
    if (!match) {
      throw new BadRequestException(
        `public_key must be an OpenSSH single-line key (${KEY_TYPES.join(', ')})`,
      );
    }
    let fingerprint: string;
    try {
      const blob = Buffer.from(match[2], 'base64');
      if (blob.length < 8) {
        throw new Error('key blob too short');
      }
      fingerprint = `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
    } catch {
      throw new BadRequestException('public_key body is not valid base64');
    }

    const dup = await this.prisma.sshKey.findFirst({
      where: { fingerprint, deleted_at: null },
      select: { id: true },
    });
    if (dup) {
      throw new ConflictException('this key is already imported');
    }

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.sshKey.create({
        data: {
          hosting_account_id: account.id,
          name,
          public_key: key,
          fingerprint,
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'sshkey.create',
        parameters: { account_id: account.id, name, fingerprint },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return created;
    });
    return toDto(row);
  }

  async remove(actor: Actor | undefined, id: string): Promise<void> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('ssh key not found');
    }
    const row = await this.prisma.sshKey.findFirst({ where: { id, deleted_at: null } });
    if (!row) {
      throw new NotFoundException('ssh key not found');
    }
    // Visibility mirrors the guard's sshKey resolution; super admins pass.
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) {
        throw new NotFoundException('ssh key not found');
      }
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: row.hosting_account_id, revoked_at: null },
        select: { id: true },
      });
      if (!access) {
        throw new NotFoundException('ssh key not found');
      }
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.sshKey.update({ where: { id: row.id }, data: { deleted_at: new Date() } });
      await this.audit.appendWithClient(tx, {
        operation: 'sshkey.delete',
        parameters: { ssh_key_id: row.id, fingerprint: row.fingerprint },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
    });
  }

  // ------------------------------------------------- deployment (ADR-0010)

  /**
   * Deploys every stored key of the account to the node's
   * authorized_keys (managed-line reconcile). Deploying the empty set is
   * legitimate: it removes only panel-managed lines.
   */
  async deploy(
    actor: Actor | undefined,
    accountId: unknown,
  ): Promise<{ deployed: number; foreign_preserved: number; ownership: string }> {
    const account = await this.requireAccount(actor, accountId);
    const keys = await this.prisma.sshKey.findMany({
      where: { hosting_account_id: account.id, deleted_at: null },
      select: { fingerprint: true, public_key: true },
      orderBy: { created_at: 'asc' },
    });
    try {
      const res = await this.agent.sshDeployKeys(
        account.username,
        keys.map((k) => ({ fingerprint: k.fingerprint, public_key: k.public_key })),
      );
      await this.audit.append({
        operation: 'sshkey.deploy',
        parameters: {
          account_id: account.id,
          deployed: res.managed_count,
          foreign_preserved: res.foreign_count,
          ownership: res.ownership,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return { deployed: res.managed_count, foreign_preserved: res.foreign_count, ownership: res.ownership };
    } catch (e) {
      await this.audit.append({
        operation: 'sshkey.deploy',
        parameters: { account_id: account.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
  }

  /**
   * Live on-node state: the deployed authorized_keys reconciled against
   * the panel's stored keys. Nothing here is cached — the agent reads the
   * actual file on every call.
   */
  async deployed(
    actor: Actor | undefined,
    accountId: unknown,
  ): Promise<{
    file: string;
    exists: boolean;
    foreign_count: number;
    data: Array<{ ssh_key_id: string; name: string; fingerprint: string; on_node: boolean }>;
  }> {
    const account = await this.requireAccount(actor, accountId);
    const [rows, live] = await Promise.all([
      this.prisma.sshKey.findMany({
        where: { hosting_account_id: account.id, deleted_at: null },
        select: { id: true, name: true, fingerprint: true },
        orderBy: { created_at: 'asc' },
      }),
      this.agent.sshListDeployed(account.username),
    ]);
    const onNode = new Set(live.managed.map((m) => m.fingerprint));
    return {
      file: live.file,
      exists: live.exists,
      foreign_count: live.foreign_count,
      data: rows.map((r) => ({
        ssh_key_id: r.id,
        name: r.name,
        fingerprint: r.fingerprint,
        on_node: onNode.has(r.fingerprint),
      })),
    };
  }
}

type SshKeyRow = {
  id: string;
  hosting_account_id: string;
  name: string;
  public_key: string;
  fingerprint: string;
  created_at: Date;
};

function toDto(row: SshKeyRow): SshKeyDto {
  return {
    id: row.id,
    hosting_account_id: row.hosting_account_id,
    name: row.name,
    public_key: row.public_key,
    fingerprint: row.fingerprint,
    created_at: row.created_at.toISOString(),
  };
}
