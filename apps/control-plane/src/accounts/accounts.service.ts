import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { AgentClientService } from '../agent/agent-client.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Hosting account lifecycle — M0 slice of API spec §4.4.
 *
 * Privileged actions flow: validate → agent command → persist + audit in ONE
 * transaction (the hosting_accounts row and its hash-chained audit entry are
 * written atomically, C11). The OS user itself is created by the agent; the
 * panel never touches the system directly.
 */
export interface ManagedAccount {
  id: string;
  username: string;
  package_id: string;
  status: 'active' | 'suspended' | 'terminated';
  uid?: number;
  gid?: number;
  homedir?: string;
  created_at: string;
}

const USERNAME_RE = /^[a-z][a-z0-9-]{0,31}$/;
const RESERVED = new Set([
  'root', 'daemon', 'bin', 'sys', 'adm', 'nobody', 'sshd', 'www-data',
  'postgres', 'nexusagent', 'nexuspanel', 'ubuntu', 'debian',
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

@Injectable()
export class AccountsService {
  private readonly logger = new Logger(AccountsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  async list(): Promise<{ data: ManagedAccount[] }> {
    const rows = await this.prisma.hostingAccount.findMany({
      where: { deleted_at: null },
      orderBy: { created_at: 'desc' },
      take: 200,
    });
    return { data: rows.map(rowToManaged) };
  }

  async get(id: string): Promise<ManagedAccount> {
    const row = await this.prisma.hostingAccount.findFirst({
      where: { id, deleted_at: null },
    });
    if (!row) {
      throw new NotFoundException('account not found');
    }
    return rowToManaged(row);
  }

  async create(username: string, packageId: string, actorUserId?: string): Promise<ManagedAccount> {
    if (!USERNAME_RE.test(username) || RESERVED.has(username)) {
      throw new BadRequestException('username violates policy');
    }
    const exists = await this.prisma.hostingAccount.findFirst({
      where: { username, deleted_at: null },
      select: { id: true },
    });
    if (exists) {
      throw new BadRequestException('account exists');
    }
    const resolvedPackageId = await this.resolvePackageId(packageId);

    const result = await this.agent.accountCreate(username, resolvedPackageId);

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.hostingAccount.create({
        data: {
          username,
          package_id: resolvedPackageId,
          linux_uid: result.uid,
          homedir: result.homedir,
          status: 'active',
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'account.create',
        parameters: { username, package_id: resolvedPackageId, uid: result.uid },
        outcome: 'success',
        actorUserId: actorUserId ?? null,
        hostingAccountId: created.id,
      });
      return created;
    });

    this.logger.log(`created hosting account ${username} (uid ${result.uid}, pkg ${resolvedPackageId})`);
    return rowToManaged(row, result.gid);
  }

  async suspend(id: string, actorUserId?: string): Promise<ManagedAccount> {
    const row = await this.requireAccount(id);
    await this.agent.accountSuspend(row.username);
    const updated = await this.prisma.$transaction(async (tx) => {
      const u = await tx.hostingAccount.update({
        where: { id: row.id },
        data: { status: 'suspended', suspended_at: new Date() },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'account.suspend',
        parameters: { username: row.username, account_id: row.id },
        outcome: 'success',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
      return u;
    });
    return rowToManaged(updated);
  }

  async resume(id: string, actorUserId?: string): Promise<ManagedAccount> {
    const row = await this.requireAccount(id);
    const updated = await this.prisma.$transaction(async (tx) => {
      const u = await tx.hostingAccount.update({
        where: { id: row.id },
        data: { status: 'active', suspended_at: null, suspension_reason: null },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'account.resume',
        parameters: { username: row.username, account_id: row.id },
        outcome: 'success',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
      return u;
    });
    return rowToManaged(updated);
  }

  /** Terminates the account: agent deletes the OS user; the row is soft-deleted. */
  async remove(id: string, actorUserId?: string): Promise<void> {
    const row = await this.requireAccount(id);
    await this.agent.accountDelete(row.username);
    await this.prisma.$transaction(async (tx) => {
      await tx.hostingAccount.update({
        where: { id: row.id },
        data: { status: 'terminated', terminated_at: new Date(), deleted_at: new Date() },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'account.delete',
        parameters: { username: row.username, account_id: row.id },
        outcome: 'success',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
    });
    this.logger.log(`deleted hosting account ${row.username}`);
  }

  async usage(id: string): Promise<Record<string, number | string>> {
    const row = await this.requireAccount(id);
    return this.agent.accountUsage(row.username);
  }

  private async requireAccount(id: string) {
    const row = await this.prisma.hostingAccount.findFirst({ where: { id, deleted_at: null } });
    if (!row) {
      throw new NotFoundException('account not found');
    }
    return row;
  }

  /**
   * M0 package seam: accepts a real package UUID, or resolves/creates the
   * bootstrap "Default" package (packages CRUD lands in P2).
   */
  private async resolvePackageId(packageId: string): Promise<string> {
    if (UUID_RE.test(packageId)) {
      const found = await this.prisma.package.findFirst({
        where: { id: packageId, is_active: true },
        select: { id: true },
      });
      if (found) {
        return found.id;
      }
    }
    const devPkg = await this.prisma.package.upsert({
      where: { id: '00000000-0000-0000-0000-000000000000' },
      create: {
        id: '00000000-0000-0000-0000-000000000000',
        name: 'Default',
        description: 'Bootstrap package (M0 seam)',
        quotas: {},
        features: {},
        php_versions: [],
      },
      update: {},
    });
    return devPkg.id;
  }
}

type HostingAccountRow = {
  id: string;
  username: string;
  package_id: string;
  status: string;
  linux_uid: number;
  homedir: string;
  created_at: Date;
};

function rowToManaged(row: HostingAccountRow, gid?: number): ManagedAccount {
  return {
    id: row.id,
    username: row.username,
    package_id: row.package_id,
    status: row.status as ManagedAccount['status'],
    uid: row.linux_uid,
    gid: gid ?? row.linux_uid,
    homedir: row.homedir,
    created_at: row.created_at.toISOString(),
  };
}
