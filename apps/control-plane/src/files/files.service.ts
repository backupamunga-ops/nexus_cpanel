import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { Actor } from '../sites/sites.service';

/**
 * File manager service (API spec §4.11) — the orchestration half of the
 * ADR-0008 split: the control plane owns permissions (the guard), ownership
 * (C7 access rows), the trash ledger and the audit chain; the agent owns
 * the bytes (C13-confined).
 *
 * Every operation resolves the account FIRST and verifies visibility — a
 * path on an account the caller cannot see is 404, same as sites. Paths
 * are forwarded verbatim to the agent, which re-validates confinement:
 * the control-plane check is convenience (fail fast, clearer errors), the
 * agent check is the boundary.
 *
 * Trash (30-day purge): deletes move the node file into
 * /home/<user>/.nexus-trash/<timestamp>-<name> and record a trash_entries
 * row with purge_after = now + 30 days. Purge is pull-based: POST
 * /files/trash/purge runs agent trash_purge for the account, then
 * reconciles the ledger against what the agent actually removed.
 */

const TRASH_RETENTION_DAYS = 30;

export interface FileEntryDto {
  name: string;
  type: string;
  size_bytes: number;
  mode: string;
  modified_at: string;
}

export interface TrashEntryDto {
  id: string;
  original_path: string;
  trash_path: string;
  size_bytes: number;
  deleted_at: string;
  purge_after: string;
}

interface AccountInfo {
  id: string;
  username: string;
  homedir: string;
}

@Injectable()
export class FilesService {
  private readonly logger = new Logger(FilesService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  /** Resolves + authorizes the account, returning what the agent needs. */
  private async requireAccount(actor: Actor | undefined, accountId: unknown): Promise<AccountInfo> {
    if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
      throw new BadRequestException('account_id is required');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true, homedir: true },
    });
    if (!account) {
      throw new NotFoundException('hosting account not found');
    }
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) {
        throw new NotFoundException('hosting account not found');
      }
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: {
          user_id: actor.userId,
          hosting_account_id: account.id,
          revoked_at: null,
        },
        select: { id: true },
      });
      if (!access) {
        // §3.2: an account you cannot see does not exist for you.
        throw new NotFoundException('hosting account not found');
      }
    }
    return account;
  }

  /** Normalizes a user path: absolute-under-home or home-relative, no tricks. */
  private resolvePath(account: AccountInfo, raw: unknown): string {
    if (typeof raw !== 'string' || raw.trim() === '') {
      throw new BadRequestException('path is required');
    }
    const p = raw.trim();
    if (p.includes('\0') || p.includes('..')) {
      throw new BadRequestException('path contains forbidden sequences');
    }
    if (p.startsWith(account.homedir + '/') || p === account.homedir) {
      return p; // absolute form
    }
    if (p.startsWith('/')) {
      throw new BadRequestException('absolute paths must be inside the account home');
    }
    return `${account.homedir}/${p}`; // relative form → anchored at home
  }

  async list(
    actor: Actor | undefined,
    accountId: unknown,
    rawPath: unknown,
  ): Promise<{ path: string; entries: FileEntryDto[]; total: number }> {
    const account = await this.requireAccount(actor, accountId);
    const path = this.resolvePath(account, rawPath);
    const res = await this.agent.filesystemList(account.username, path);
    return { path: res.path, entries: res.entries, total: res.total };
  }

  async usage(actor: Actor | undefined, accountId: unknown): Promise<{ bytes: number; inodes: number; partial: boolean }> {
    const account = await this.requireAccount(actor, accountId);
    return this.agent.filesystemUsage(account.username);
  }

  async mkdir(
    actor: Actor | undefined,
    input: { account_id?: unknown; path?: unknown; mode?: unknown },
  ): Promise<{ path: string; created: boolean }> {
    const account = await this.requireAccount(actor, input.account_id);
    const path = this.resolvePath(account, input.path);
    const mode = typeof input.mode === 'number' ? input.mode : undefined;
    try {
      const res = await this.agent.filesystemMkdir(account.username, path, mode);
      await this.audit.append({
        operation: 'file.mkdir',
        parameters: { account_id: account.id, path },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return res;
    } catch (e) {
      await this.audit.append({
        operation: 'file.mkdir',
        parameters: { account_id: account.id, path, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
  }

  async read(
    actor: Actor | undefined,
    accountId: unknown,
    rawPath: unknown,
  ): Promise<{ path: string; size_bytes: number; content_b64: string; truncated: boolean }> {
    const account = await this.requireAccount(actor, accountId);
    const path = this.resolvePath(account, rawPath);
    return this.agent.filesystemRead(account.username, path);
  }

  async write(
    actor: Actor | undefined,
    input: { account_id?: unknown; path?: unknown; content_b64?: unknown; overwrite?: unknown; mode?: unknown },
  ): Promise<{ path: string; written_bytes: number; overwritten: boolean; ownership: string }> {
    const account = await this.requireAccount(actor, input.account_id);
    const path = this.resolvePath(account, input.path);
    if (typeof input.content_b64 !== 'string' || input.content_b64 === '') {
      throw new BadRequestException('content_b64 is required');
    }
    const res = await this.agent.filesystemWrite(account.username, path, input.content_b64, {
      overwrite: input.overwrite === true,
      ...(typeof input.mode === 'number' ? { mode: input.mode } : {}),
    });
    await this.audit.append({
      operation: 'file.write',
      parameters: { account_id: account.id, path, bytes: res.written_bytes, overwritten: res.overwritten },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: account.id,
    });
    return res;
  }

  async chmod(
    actor: Actor | undefined,
    input: { account_id?: unknown; path?: unknown; mode?: unknown },
  ): Promise<{ path: string; mode: string }> {
    const account = await this.requireAccount(actor, input.account_id);
    const path = this.resolvePath(account, input.path);
    if (typeof input.mode !== 'number' || !Number.isInteger(input.mode) || input.mode <= 0 || input.mode > 0o777) {
      throw new BadRequestException('mode must be an integer between 1 and 0777');
    }
    const res = await this.agent.filesystemChmod(account.username, path, input.mode);
    await this.audit.append({
      operation: 'file.chmod',
      parameters: { account_id: account.id, path, mode: res.mode },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: account.id,
    });
    return res;
  }

  /** Soft delete → trash. The node file moves; a ledger row records it. */
  async deleteToTrash(
    actor: Actor | undefined,
    input: { account_id?: unknown; path?: unknown },
  ): Promise<TrashEntryDto> {
    const account = await this.requireAccount(actor, input.account_id);
    const path = this.resolvePath(account, input.path);
    if (path === account.homedir) {
      throw new BadRequestException('the account home cannot be deleted');
    }
    try {
      const res = await this.agent.filesystemDelete(account.username, path, true);
      const purgeAfter = new Date(Date.now() + TRASH_RETENTION_DAYS * 24 * 3600 * 1000);
      const row = await this.prisma.$transaction(async (tx) => {
        const created = await tx.trashEntry.create({
          data: {
            hosting_account_id: account.id,
            original_path: path,
            trash_path: res.trash_path,
            size_bytes: res.size_bytes,
            purge_after: purgeAfter,
          },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'file.delete',
          parameters: { account_id: account.id, path, trash_path: res.trash_path, size_bytes: res.size_bytes },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: account.id,
        });
        return created;
      });
      return toTrashDto(row);
    } catch (e) {
      await this.audit.append({
        operation: 'file.delete',
        parameters: { account_id: account.id, path, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
  }

  async listTrash(actor: Actor | undefined, accountId: unknown): Promise<{ data: TrashEntryDto[] }> {
    const account = await this.requireAccount(actor, accountId);
    const rows = await this.prisma.trashEntry.findMany({
      where: { hosting_account_id: account.id },
      orderBy: { deleted_at: 'desc' },
      take: 500,
    });
    return { data: rows.map(toTrashDto) };
  }

  /** Restores a trash entry: agent moves the file back, ledger row is removed. */
  async restoreTrash(actor: Actor | undefined, entryId: string): Promise<{ restored: true }> {
    const row = await this.prisma.trashEntry.findFirst({ where: { id: entryId } });
    if (!row) {
      throw new NotFoundException('trash entry not found');
    }
    // Visibility: restoring requires the same account visibility as deleting.
    const account = await this.requireAccount(actor, row.hosting_account_id);

    await this.agent.filesystemMove(account.username, row.trash_path, row.original_path);
    await this.prisma.trashEntry.delete({ where: { id: row.id } });
    await this.audit.append({
      operation: 'file.trash.restore',
      parameters: { account_id: row.hosting_account_id, original_path: row.original_path },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: row.hosting_account_id,
    });
    return { restored: true };
  }

  /** Hard-deletes one trash entry now (node file + ledger row). */
  async deleteTrashEntry(actor: Actor | undefined, entryId: string): Promise<void> {
    const row = await this.prisma.trashEntry.findFirst({ where: { id: entryId } });
    if (!row) {
      throw new NotFoundException('trash entry not found');
    }
    const account = await this.requireAccount(actor, row.hosting_account_id);
    await this.agent.filesystemDelete(account.username, row.trash_path, false);
    await this.prisma.trashEntry.delete({ where: { id: row.id } });
    await this.audit.append({
      operation: 'file.trash.delete',
      parameters: { account_id: row.hosting_account_id, trash_path: row.trash_path },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: row.hosting_account_id,
    });
  }

  /**
   * Runs the 30-day purge for an account: the agent removes expired trash
   * files; the ledger reconciles against what the agent ACTUALLY removed —
   * a file the agent could not remove stays in the ledger and in the trash.
   */
  async purgeTrash(actor: Actor | undefined, accountId: unknown): Promise<{ removed: number }> {
    const account = await this.requireAccount(actor, accountId);
    const cutoff = new Date().toISOString();
    const res = await this.agent.trashPurge(account.username, cutoff);
    const removedSet = new Set(res.removed.map((name) => name));

    const expired = await this.prisma.trashEntry.findMany({
      where: { hosting_account_id: account.id, purge_after: { lte: new Date() } },
      select: { id: true, trash_path: true },
    });
    let removed = 0;
    for (const row of expired) {
      if (removedSet.has(basename(row.trash_path))) {
        await this.prisma.trashEntry.delete({ where: { id: row.id } });
        removed++;
      }
    }
    await this.audit.append({
      operation: 'file.trash.purge',
      parameters: { account_id: account.id, removed },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: account.id,
    });
    return { removed };
  }
}

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i >= 0 ? p.slice(i + 1) : p;
}

type TrashRow = {
  id: string;
  hosting_account_id: string;
  original_path: string;
  trash_path: string;
  size_bytes: bigint | number;
  deleted_at: Date;
  purge_after: Date;
};

function toTrashDto(row: TrashRow): TrashEntryDto {
  return {
    id: row.id,
    original_path: row.original_path,
    trash_path: row.trash_path,
    size_bytes: Number(row.size_bytes),
    deleted_at: row.deleted_at.toISOString(),
    purge_after: row.purge_after.toISOString(),
  };
}
