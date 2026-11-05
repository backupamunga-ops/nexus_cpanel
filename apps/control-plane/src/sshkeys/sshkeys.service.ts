import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { Actor } from '../sites/sites.service';

/**
 * SSH keys (API spec §4.13). Panel-side records for per-account public
 * keys: strict key-type allowlist, OpenSSH SHA-256 fingerprint computed at
 * import (a mismatched fingerprint means the stored key is not the key the
 * user pasted — that class of bug dies here).
 *
 * D-11 honesty: keys are STORED in this milestone. Deployment to the
 * account's authorized_keys is an agent-side write (P4 amendment) — until
 * then the UI labels these "stored — not yet deployed to the node", and
 * nothing pretends otherwise.
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
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  private async requireAccount(actor: Actor | undefined, accountId: unknown) {
    if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
      throw new BadRequestException('account_id is required');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true },
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
