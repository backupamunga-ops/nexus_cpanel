import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { AgentClientService } from '../agent/agent-client.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';
import { mergeQuotas, validateQuotaSet, QuotaSet } from '../packages/packages.service';

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

  /**
   * Server Admins see every account; everyone else only the accounts they
   * hold an active access row for (C7 — isolation starts at the listing).
   */
  async list(actor?: { userId?: string; isSuperAdmin?: boolean }): Promise<{ data: ManagedAccount[] }> {
    const base = { deleted_at: null };
    const where =
      actor?.userId && !actor.isSuperAdmin
        ? {
            ...base,
            user_hosting_account_access__hosting_account_id: {
              some: { user_id: actor.userId, revoked_at: null },
            },
          }
        : base;
    const rows = await this.prisma.hostingAccount.findMany({
      where,
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

    let result;
    try {
      result = await this.agent.accountCreate(username, resolvedPackageId);
    } catch (e) {
      // Privileged operations audit their failures too (C11/A5).
      await this.audit.append({
        operation: 'account.create',
        parameters: { username, package_id: resolvedPackageId, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actorUserId ?? null,
      });
      throw e;
    }

    // M0 spec §2.3–4: account.create is immediately followed by
    // isolation.provision (the cgroup v2 slice). A provision failure is
    // audited and logged but does NOT roll back the created user — usage
    // reads return zeros until the slice exists; the M0 runbook covers
    // re-provisioning on the node. Rollback compensation is P1 work.
    try {
      await this.agent.isolationProvision(username, 'standard');
    } catch (e) {
      await this.audit.append({
        operation: 'isolation.provision',
        parameters: { username, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actorUserId ?? null,
      });
      this.logger.warn(
        `isolation.provision failed for ${username}: ${(e as Error).message}`,
      );
    }

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
    try {
      await this.agent.accountSuspend(row.username);
    } catch (e) {
      await this.audit.append({
        operation: 'account.suspend',
        parameters: { username: row.username, account_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
      throw e;
    }
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
    try {
      await this.agent.accountResume(row.username);
    } catch (e) {
      await this.audit.append({
        operation: 'account.resume',
        parameters: { username: row.username, account_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
      throw e;
    }
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
    try {
      await this.agent.accountDelete(row.username);
    } catch (e) {
      await this.audit.append({
        operation: 'account.delete',
        parameters: { username: row.username, account_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
      throw e;
    }
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

  /**
   * Applies per-account quota overrides (API spec PATCH /accounts/{id},
   * permission account:update — owner/admin per §11.3). The merge order is
   * package quotas ← override (override wins); the MERGED set is validated
   * and sent to the agent (cgroup v2 enforcement: cpu/mem/processes; disk
   * and inodes come back as `skipped` until filesystem.quota lands — the
   * audit entry records that gap explicitly). The DB stores the OVERRIDE
   * partial (the column's documented semantics); enforcement always
   * recomputes the merge, so a later package change re-bases cleanly.
   */
  async updateQuotas(
    id: string,
    overrideInput: unknown,
    actorUserId?: string,
  ): Promise<ManagedAccount & { quotas_override: QuotaSet; applied: string[]; skipped: Array<{ key: string; reason: string }> }> {
    const row = await this.requireAccount(id);
    if (!overrideInput || typeof overrideInput !== 'object' || Array.isArray(overrideInput)) {
      throw new BadRequestException('quotas override must be an object');
    }
    if (Object.keys(overrideInput as Record<string, unknown>).length === 0) {
      throw new BadRequestException('quotas override must set at least one key');
    }
    const override = validateQuotaSet(overrideInput, 'quotas_override');

    const pkg = await this.prisma.package.findFirst({ where: { id: row.package_id } });
    if (!pkg) {
      throw new NotFoundException('package not found for this account');
    }
    const merged = mergeQuotas((pkg.quotas ?? {}) as QuotaSet, override);

    try {
      const applied = await this.agent.accountQuota(row.username, merged as Record<string, number>);
      const updated = await this.prisma.$transaction(async (tx) => {
        const u = await tx.hostingAccount.update({
          where: { id: row.id },
          data: { quotas_override: override as object },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'account.quota',
          parameters: {
            username: row.username,
            account_id: row.id,
            override,
            applied: applied.applied,
            skipped: applied.skipped,
          },
          outcome: 'success',
          actorUserId: actorUserId ?? null,
          hostingAccountId: row.id,
        });
        return u;
      });
      return {
        ...rowToManaged(updated),
        quotas_override: override,
        applied: applied.applied,
        skipped: applied.skipped,
      };
    } catch (e) {
      await this.audit.append({
        operation: 'account.quota',
        parameters: {
          username: row.username,
          account_id: row.id,
          override,
          error: (e as Error).message,
        },
        outcome: 'failure',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
      throw e;
    }
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
   * Resolves the account's package: a valid UUID must point at a live,
   * active package (BadRequest otherwise — silent fallbacks would hide
   * operator typos); the legacy non-UUID 'default' alias keeps resolving to
   * the bootstrap Default package (M0 compat, seeded on demand).
   */
  private async resolvePackageId(packageId: string): Promise<string> {
    if (UUID_RE.test(packageId)) {
      const found = await this.prisma.package.findFirst({
        where: { id: packageId, is_active: true, deleted_at: null },
        select: { id: true },
      });
      if (found) {
        return found.id;
      }
      throw new BadRequestException('package not found or inactive');
    }
    const devPkg = await this.prisma.package.upsert({
      where: { id: '00000000-0000-0000-0000-000000000000' },
      create: {
        id: '00000000-0000-0000-0000-000000000000',
        name: 'Default',
        description: 'Bootstrap package (legacy alias)',
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
