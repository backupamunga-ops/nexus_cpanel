import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { Actor } from '../sites/sites.service';

/**
 * FTP accounts (API spec §4.12) — vsftpd virtual users, ADR-0011.
 *
 * The machine state lives in the agent (per-user vsftpd config + the
 * pam_userdb); the panel owns the registry (file_accounts, DDL-first) and
 * the rules:
 *   - the login is globally unique and strictly shaped (it becomes a
 *     filename in the agent's user-config dir and a userdb key);
 *   - root_dir is confined to the owning account's home (C13) and must
 *     exist — the agent re-validates with the full confinement anyway;
 *   - provisioning is agent-first: a failed agent call leaves NO row;
 *   - the userdb rebuild can be honestly skipped on dev rigs (no db_load):
 *     the response carries the skip reason and the panel logs it loudly —
 *     a login that cannot authenticate is never reported as ready (D-11).
 *
 * Ownership boundary (C7): every route resolves the owning account and
 * 404s for invisible resources (§3.2 anti-enumeration).
 */

const FTP_USER_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

export interface FtpAccountDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  username: string;
  root_dir: string;
  read_only: boolean;
  status: string;
  created_at: string;
  updated_at: string;
}

interface AccountRow {
  id: string;
  username: string;
  homedir: string;
}

@Injectable()
export class FtpService {
  private readonly logger = new Logger(FtpService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  private async requireAccount(actor: Actor | undefined, accountId: unknown): Promise<AccountRow> {
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
        where: { user_id: actor.userId, hosting_account_id: account.id, revoked_at: null },
        select: { id: true },
      });
      if (!access) {
        throw new NotFoundException('hosting account not found');
      }
    }
    return account;
  }

  private async requireVisibleAccountOf(row: { hosting_account_id: string }, actor?: Actor): Promise<AccountRow> {
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: row.hosting_account_id, deleted_at: null },
      select: { id: true, username: true, homedir: true },
    });
    if (!account) {
      throw new NotFoundException('ftp account not found');
    }
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) {
        throw new NotFoundException('ftp account not found');
      }
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: account.id, revoked_at: null },
        select: { id: true },
      });
      if (!access) {
        throw new NotFoundException('ftp account not found');
      }
    }
    return account;
  }

  async list(actor: Actor | undefined, accountId: unknown): Promise<{ data: FtpAccountDto[] }> {
    const account = await this.requireAccount(actor, accountId);
    const rows = await this.prisma.fileAccount.findMany({
      where: { hosting_account_id: account.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
      include: { hosting_account: { select: { username: true } } },
    });
    return { data: rows.map((r) => toDto(r, r.hosting_account?.username ?? account.username)) };
  }

  async create(
    actor: Actor | undefined,
    input: { account_id?: unknown; username?: unknown; password?: unknown; root_dir?: unknown; read_only?: unknown },
  ): Promise<FtpAccountDto> {
    const account = await this.requireAccount(actor, input.account_id);

    const username = typeof input.username === 'string' ? input.username.trim().toLowerCase() : '';
    if (!FTP_USER_RE.test(username)) {
      throw new BadRequestException(
        'username must be 1-63 chars: lowercase letters, digits, dot, dash, underscore (it becomes a node-side login)',
      );
    }
    const dup = await this.prisma.fileAccount.findFirst({
      where: { username, deleted_at: null },
      select: { id: true },
    });
    if (dup) {
      throw new ConflictException('this ftp login already exists');
    }
    const password = typeof input.password === 'string' ? input.password : '';
    if (password.length < 8 || password.length > 1024) {
      throw new BadRequestException('password must be 8-1024 characters');
    }
    const readOnly = input.read_only === true;

    const rawRoot = typeof input.root_dir === 'string' && input.root_dir.trim() !== '' ? input.root_dir.trim() : '.';
    if (rawRoot.includes('..') || rawRoot.includes('\0')) {
      throw new BadRequestException('root_dir must stay inside the account home');
    }
    const rootDir = rawRoot === '.'
      ? account.homedir
      : rawRoot.startsWith('/')
        ? rawRoot
        : `${account.homedir}/${rawRoot}`;
    if (!rootDir.startsWith(`${account.homedir}/`) && rootDir !== account.homedir) {
      throw new BadRequestException('root_dir must stay inside the account home');
    }

    try {
      const res = await this.agent.ftpCreateAccount({
        owner_username: account.username,
        ftp_username: username,
        password,
        root_dir: rootDir,
        read_only: readOnly,
      });
      if (res.userdb.rebuilt === false && res.userdb.skipped) {
        this.logger.warn(
          `ftp account ${username} created but userdb rebuild skipped: ${res.userdb.skipped}`,
        );
      }
      const row = await this.prisma.$transaction(async (tx) => {
        const created = await tx.fileAccount.create({
          data: {
            hosting_account_id: account.id,
            username,
            root_dir: rootDir,
            read_only: readOnly,
            status: 'active',
          },
          include: { hosting_account: { select: { username: true } } },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'ftp.create',
          parameters: {
            account_id: account.id,
            username,
            root_dir: rootDir,
            read_only: readOnly,
            userdb_rebuilt: res.userdb.rebuilt,
          },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: account.id,
        });
        return created;
      });
      return toDto(row, account.username);
    } catch (e) {
      await this.audit.append({
        operation: 'ftp.create',
        parameters: { account_id: account.id, username, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
  }

  /** Rotates the login's password (agent hashes; nothing stored here). */
  async setPassword(actor: Actor | undefined, id: string, input: { password?: unknown }): Promise<void> {
    const row = await this.requireRow(id);
    await this.requireVisibleAccountOf(row, actor);
    const password = typeof input.password === 'string' ? input.password : '';
    if (password.length < 8 || password.length > 1024) {
      throw new BadRequestException('password must be 8-1024 characters');
    }
    try {
      await this.agent.ftpSetPassword(row.username, password);
      await this.audit.append({
        operation: 'ftp.password',
        parameters: { ftp_account_id: row.id, username: row.username },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
    } catch (e) {
      await this.audit.append({
        operation: 'ftp.password',
        parameters: { ftp_account_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
  }

  async remove(actor: Actor | undefined, id: string): Promise<void> {
    const row = await this.requireRow(id);
    const account = await this.requireVisibleAccountOf(row, actor);
    try {
      await this.agent.ftpDeleteAccount(row.username);
    } catch (e) {
      await this.audit.append({
        operation: 'ftp.delete',
        parameters: { ftp_account_id: row.id, username: row.username, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.fileAccount.update({ where: { id: row.id }, data: { deleted_at: new Date(), status: 'deleted' } });
      await this.audit.appendWithClient(tx, {
        operation: 'ftp.delete',
        parameters: { ftp_account_id: row.id, username: row.username },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
    });
    this.logger.log(`removed ftp account ${row.username} of ${account.username}`);
  }

  private async requireRow(id: string) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('ftp account not found');
    }
    const row = await this.prisma.fileAccount.findFirst({
      where: { id, deleted_at: null },
      include: { hosting_account: { select: { username: true } } },
    });
    if (!row) {
      throw new NotFoundException('ftp account not found');
    }
    return row;
  }
}

type FileAccountRow = {
  id: string;
  hosting_account_id: string;
  username: string;
  root_dir: string;
  read_only: boolean;
  status: string;
  created_at: Date;
  updated_at: Date;
};

function toDto(row: FileAccountRow, accountUsername: string): FtpAccountDto {
  return {
    id: row.id,
    hosting_account_id: row.hosting_account_id,
    account_username: accountUsername,
    username: row.username,
    root_dir: row.root_dir,
    read_only: row.read_only,
    status: row.status,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
  };
}
