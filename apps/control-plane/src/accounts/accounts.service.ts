import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { AgentClientService } from '../agent/agent-client.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';
import { SHAREABLE_ROLES } from '../common/permissions';
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
  /**
   * The CALLER's role on this account ('owner'/'admin'/'member'/'readonly',
   * or the 'super-admin' sentinel) — lets the UI gate capabilities without
   * guessing. Absent only if the access-row lookup was skipped.
   */
  my_role?: string;
}

/** One active row of user_hosting_account_access, as returned by the shares API. */
export interface ShareView {
  id: string;
  user: { id: string; email: string; display_name: string };
  role: string;
  granted_by: { id: string; email: string } | null;
  created_at: string;
}

const USERNAME_RE = /^[a-z][a-z0-9-]{0,31}$/;
const RESERVED = new Set([
  'root', 'daemon', 'bin', 'sys', 'adm', 'nobody', 'sshd', 'www-data',
  'postgres', 'nexusagent', 'nexuspanel', 'ubuntu', 'debian',
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Display order for share listings: owner first, then trust descending. */
const ROLE_ORDER: Record<string, number> = { owner: 0, admin: 1, member: 2, readonly: 3 };

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
   * Each row carries the caller's own role (`my_role`) so the UI can gate
   * capabilities without a second round-trip; super-admins get the
   * 'super-admin' sentinel.
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

    let roleByAccount = new Map<string, string>();
    if (actor?.isSuperAdmin) {
      roleByAccount = new Map(rows.map((r) => [r.id, 'super-admin']));
    } else if (actor?.userId && rows.length > 0) {
      const accessRows = await this.prisma.userHostingAccountAccess.findMany({
        where: {
          user_id: actor.userId,
          hosting_account_id: { in: rows.map((r) => r.id) },
          revoked_at: null,
        },
        select: { hosting_account_id: true, role: true },
      });
      roleByAccount = new Map(accessRows.map((r) => [r.hosting_account_id, r.role]));
    }
    return { data: rows.map((row) => ({ ...rowToManaged(row), my_role: roleByAccount.get(row.id) })) };
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

  // ------------------------------------------------------------------------
  // Access sharing (spec §11.3 delegation) — the management surface for the
  // user_hosting_account_access rows the PermissionsGuard (C6) already
  // enforces on every account-scoped route. Every write commits in ONE
  // transaction with its hash-chained audit entry (C11).
  // ------------------------------------------------------------------------

  /** Active shares of one account, owner first, then trust descending. */
  async listShares(id: string): Promise<{ data: ShareView[] }> {
    await this.requireAccount(id);
    const rows = await this.prisma.userHostingAccountAccess.findMany({
      where: { hosting_account_id: id, revoked_at: null },
      include: {
        user: { select: { id: true, email: true, display_name: true } },
        granted_by_user: { select: { id: true, email: true } },
      },
    });
    rows.sort(
      (a, b) =>
        (ROLE_ORDER[a.role] ?? 99) - (ROLE_ORDER[b.role] ?? 99) ||
        a.created_at.getTime() - b.created_at.getTime() ||
        a.id.localeCompare(b.id),
    );
    return { data: rows.map(toShareView) };
  }

  /**
   * Grants another active user a role on this account (permission
   * `account:share` — owner/admin/super-admin per §11.3). Fail-closed
   * validation order: account → role whitelist → user → duplicate. `owner`
   * is NOT grantable (exactly one owner per account; transfer is a separate
   * flow). The caller's id is recorded as granted_by for the audit trail.
   */
  async grantShare(
    id: string,
    email: string,
    role: string,
    actorUserId?: string,
  ): Promise<ShareView> {
    const row = await this.requireAccount(id);
    const normalized = String(email ?? '').trim().toLowerCase();
    if (!normalized || !EMAIL_RE.test(normalized)) {
      throw new BadRequestException('a valid email address is required');
    }
    if (!SHAREABLE_ROLES.includes(role)) {
      throw new BadRequestException(
        role === 'owner'
          ? "role 'owner' cannot be granted — ownership transfer is a separate flow"
          : `role must be one of: ${SHAREABLE_ROLES.join(', ')}`,
      );
    }
    // Uniform 404 for unknown, deactivated and soft-deleted users — no
    // oracle distinguishing them (the grantor is inside the trust boundary,
    // but the panel still avoids confirming which emails ever existed).
    const target = await this.prisma.user.findFirst({
      where: { email: normalized, deleted_at: null, is_active: true },
      select: { id: true, email: true, display_name: true },
    });
    if (!target) {
      throw new NotFoundException('no active user with that email');
    }
    const active = await this.prisma.userHostingAccountAccess.findFirst({
      where: { hosting_account_id: row.id, user_id: target.id, revoked_at: null },
      select: { id: true },
    });
    if (active) {
      throw new ConflictException(
        'user already has active access to this account — revoke the share first to change its role',
      );
    }
    const created = await this.prisma.$transaction(async (tx) => {
      const share = await tx.userHostingAccountAccess.create({
        data: {
          user_id: target.id,
          hosting_account_id: row.id,
          role,
          granted_by_user_id: actorUserId ?? null,
        },
        include: {
          user: { select: { id: true, email: true, display_name: true } },
          granted_by_user: { select: { id: true, email: true } },
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'account.share.grant',
        parameters: {
          account_id: row.id,
          username: row.username,
          user_id: target.id,
          email: target.email,
          role,
        },
        outcome: 'success',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
      return share;
    });
    this.logger.log(`granted '${role}' on ${row.username} to ${target.email}`);
    return toShareView(created);
  }

  /**
   * Soft-revokes one share row (row keeps its history; a fresh grant creates
   * a NEW row). The lookup is scoped to the route's account and to ACTIVE
   * rows, and every miss returns the same 404 — a share id from another
   * account is indistinguishable from an unknown one. The owner row is
   * irrevocable here (it is the account's root of trust).
   */
  async revokeShare(id: string, shareId: string, actorUserId?: string): Promise<void> {
    const row = await this.requireAccount(id);
    const share = await this.prisma.userHostingAccountAccess.findFirst({
      where: { id: shareId, hosting_account_id: row.id, revoked_at: null },
      include: { user: { select: { id: true, email: true } } },
    });
    if (!share) {
      throw new NotFoundException('share not found');
    }
    if (share.role === 'owner') {
      throw new ConflictException(
        'the owner access cannot be revoked — ownership transfer is a separate flow',
      );
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.userHostingAccountAccess.update({
        where: { id: share.id },
        data: { revoked_at: new Date() },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'account.share.revoke',
        parameters: {
          account_id: row.id,
          username: row.username,
          user_id: share.user_id,
          email: share.user.email,
          role: share.role,
        },
        outcome: 'success',
        actorUserId: actorUserId ?? null,
        hostingAccountId: row.id,
      });
    });
    this.logger.log(`revoked '${share.role}' on ${row.username} from ${share.user.email}`);
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

type ShareRow = {
  id: string;
  role: string;
  created_at: Date;
  user_id: string;
  user: { id: string; email: string; display_name: string } | null;
  granted_by_user: { id: string; email: string } | null;
};

function toShareView(row: ShareRow): ShareView {
  return {
    id: row.id,
    user: row.user ?? { id: row.user_id, email: '', display_name: '' },
    role: row.role,
    granted_by: row.granted_by_user ? { id: row.granted_by_user.id, email: row.granted_by_user.email } : null,
    created_at: row.created_at.toISOString(),
  };
}
