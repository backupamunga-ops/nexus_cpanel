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
import { hashMailboxPassword, assertPasswordShape } from './mailbox-hash';

/**
 * Email core (API spec §4.8) — Postfix + Dovecot, ADR-0013.
 *
 * Division of labor (ADR-0013):
 *   - the agent owns node files: postfix maps, maildirs, sieve scripts;
 *   - the panel owns the registry (mail_domains / mailboxes / mail_aliases /
 *     autoresponders, DDL-first) AND all credentials: mailbox passwords are
 *     hashed here with Dovecot's {SSHA512} scheme and verified by Dovecot's
 *     read-only SQL userdb — the agent never sees a password;
 *   - provisioning is agent-first: a failed agent call leaves NO row;
 *   - delivery default is relay-only (ADR-0002): the honest per-domain badge
 *     says so until the self-hosted MTA is explicitly enabled (B08).
 *
 * Package limits (fail-closed): a package may declare `features.mail_enabled`
 * (default on for backwards compatibility) plus `quotas.mailbox_count` and
 * `quotas.mailbox_quota_mb`; both are enforced here before any node call.
 *
 * Ownership boundary (C7): every route resolves the owning account and
 * 404s for invisible resources (§3.2 anti-enumeration).
 */

const MAIL_DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const LOCAL_PART_RE = /^[a-z0-9]([a-z0-9._+-]{0,62}[a-z0-9])?$/;
const MAX_MAILBOX_QUOTA_MB = 1 << 20; // agent cap mirrored here

export interface MailDomainDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  name: string;
  is_active: boolean;
  mailbox_count: number;
  created_at: string;
}

export interface MailboxDto {
  id: string;
  mail_domain_id: string;
  address: string;
  quota_mb: number;
  used_mb: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface MailAliasDto {
  id: string;
  mail_domain_id: string;
  source_address: string;
  destination_address: string;
  is_catchall: boolean;
  created_at: string;
}

export interface AutoresponderDto {
  id: string;
  mailbox_id: string;
  address: string;
  subject: string;
  starts_at: string | null;
  ends_at: string | null;
  /** Honest schedule state: active | scheduled | expired (panel-side truth). */
  schedule_state: 'active' | 'scheduled' | 'expired';
  created_at: string;
}

interface AccountRow {
  id: string;
  username: string;
  package_id: string | null;
}

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  // ---- ownership (C7) ---------------------------------------------------------

  private async requireAccount(actor: Actor | undefined, accountId: unknown): Promise<AccountRow> {
    if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
      throw new BadRequestException('account_id is required');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true, package_id: true },
    });
    if (!account) throw new NotFoundException('hosting account not found');
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) throw new NotFoundException('hosting account not found');
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: account.id, revoked_at: null },
        select: { id: true },
      });
      if (!access) throw new NotFoundException('hosting account not found');
    }
    return account;
  }

  private async requireVisibleDomain(id: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('mail domain not found');
    }
    const domain = await this.prisma.mailDomain.findFirst({
      where: { id, deleted_at: null },
      include: { hosting_account: { select: { id: true, username: true, package_id: true } } },
    });
    if (!domain) throw new NotFoundException('mail domain not found');
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) throw new NotFoundException('mail domain not found');
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: domain.hosting_account_id, revoked_at: null },
        select: { id: true },
      });
      if (!access) throw new NotFoundException('mail domain not found');
    }
    return domain;
  }

  private async requireVisibleMailbox(domainId: string, mailboxId: string, actor?: Actor) {
    await this.requireVisibleDomain(domainId, actor);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(mailboxId)) {
      throw new NotFoundException('mailbox not found');
    }
    const box = await this.prisma.mailboxe.findFirst({
      where: { id: mailboxId, mail_domain_id: domainId, deleted_at: null },
    });
    if (!box) throw new NotFoundException('mailbox not found');
    return box;
  }

  // ---- package limits ---------------------------------------------------------

  private async mailPolicyOf(account: AccountRow): Promise<{ enabled: boolean; maxBoxes: number | null; maxQuotaMb: number | null }> {
    if (!account.package_id) {
      return { enabled: true, maxBoxes: null, maxQuotaMb: null };
    }
    const pkg = await this.prisma.package.findFirst({
      where: { id: account.package_id, deleted_at: null },
      select: { features: true, quotas: true },
    });
    const features = (pkg?.features ?? {}) as Record<string, unknown>;
    const quotas = (pkg?.quotas ?? {}) as Record<string, unknown>;
    const enabled = features['mail_enabled'] !== false; // key-open features; absent = on
    const maxBoxes = typeof quotas['mailbox_count'] === 'number' ? quotas['mailbox_count'] : null;
    const maxQuotaMb = typeof quotas['mailbox_quota_mb'] === 'number' ? quotas['mailbox_quota_mb'] : null;
    return { enabled, maxBoxes, maxQuotaMb };
  }

  private async assertMailAllowed(account: AccountRow): Promise<void> {
    const policy = await this.mailPolicyOf(account);
    if (!policy.enabled) {
      throw new ConflictException("mail is disabled on this account's package");
    }
  }

  private async assertMailboxQuota(account: AccountRow, quotaMb: number, maxQuotaMb: number | null): Promise<void> {
    if (quotaMb < 1 || quotaMb > MAX_MAILBOX_QUOTA_MB || !Number.isInteger(quotaMb)) {
      throw new BadRequestException(`quota_mb must be an integer 1-${MAX_MAILBOX_QUOTA_MB} MB`);
    }
    if (maxQuotaMb !== null && quotaMb > maxQuotaMb) {
      throw new ConflictException(`this package caps mailbox quota at ${maxQuotaMb} MB`);
    }
  }

  private async assertMailboxCount(account: AccountRow, maxBoxes: number | null): Promise<void> {
    if (maxBoxes === null) return;
    const count = await this.prisma.mailboxe.count({
      where: { mail_domain: { hosting_account_id: account.id }, deleted_at: null },
    });
    if (count >= maxBoxes) {
      throw new ConflictException(`this package caps the account at ${maxBoxes} mailboxes`);
    }
  }

  // ---- domains ------------------------------------------------------------------

  async listDomains(actor: Actor | undefined, accountId: unknown): Promise<{ data: MailDomainDto[] }> {
    const account = await this.requireAccount(actor, accountId);
    const domains = await this.prisma.mailDomain.findMany({
      where: { hosting_account_id: account.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
      include: {
        hosting_account: { select: { username: true } },
        mailboxes__mail_domain_id: { where: { deleted_at: null }, select: { id: true } },
      },
    });
    return {
      data: domains.map((d) => ({
        id: d.id,
        hosting_account_id: d.hosting_account_id,
        account_username: d.hosting_account?.username ?? account.username,
        name: d.name,
        is_active: d.is_active,
        mailbox_count: d.mailboxes__mail_domain_id.length,
        created_at: d.created_at.toISOString(),
      })),
    };
  }

  async createDomain(
    actor: Actor | undefined,
    input: { account_id?: unknown; name?: unknown },
  ): Promise<MailDomainDto> {
    const account = await this.requireAccount(actor, input.account_id);
    await this.assertMailAllowed(account);

    const name = typeof input.name === 'string' ? input.name.trim().toLowerCase().replace(/\.$/, '') : '';
    if (!MAIL_DOMAIN_RE.test(name)) {
      throw new BadRequestException('mail domain must be a lowercase FQDN with at least two labels (e.g. example.com)');
    }
    const dup = await this.prisma.mailDomain.findFirst({ where: { name, deleted_at: null }, select: { id: true } });
    if (dup) throw new ConflictException('this mail domain is already managed by the panel');

    let agentResult: { status: string; maps: { built: boolean; skipped?: string } };
    try {
      agentResult = await this.agent.mailCreateDomain(name);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.domain.create',
        parameters: { account_id: account.id, domain: name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
    if (agentResult.maps.built === false && agentResult.maps.skipped) {
      this.logger.warn(`mail domain ${name} registered but postfix maps not rebuilt: ${agentResult.maps.skipped}`);
    }

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.mailDomain.create({
        data: { hosting_account_id: account.id, name, is_active: true },
        include: {
          hosting_account: { select: { username: true } },
          mailboxes__mail_domain_id: { where: { deleted_at: null }, select: { id: true } },
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.domain.create',
        parameters: {
          account_id: account.id,
          domain: name,
          maps_built: agentResult.maps.built,
          maps_skipped: agentResult.maps.skipped ?? null,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return created;
    });
    return {
      id: row.id,
      hosting_account_id: row.hosting_account_id,
      account_username: row.hosting_account?.username ?? account.username,
      name: row.name,
      is_active: row.is_active,
      mailbox_count: 0,
      created_at: row.created_at.toISOString(),
    };
  }

  async deleteDomain(actor: Actor | undefined, id: string): Promise<void> {
    const domain = await this.requireVisibleDomain(id, actor);
    const boxes = await this.prisma.mailboxe.count({ where: { mail_domain_id: domain.id, deleted_at: null } });
    const aliases = await this.prisma.mailAliase.count({ where: { mail_domain_id: domain.id, deleted_at: null } });
    if (boxes > 0 || aliases > 0) {
      throw new ConflictException(
        `delete the ${boxes} mailbox(es) and ${aliases} alias(es) on ${domain.name} first — the panel never orphans node-side state`,
      );
    }
    try {
      await this.agent.mailDeleteDomain(domain.name);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.domain.delete',
        parameters: { mail_domain_id: domain.id, domain: domain.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.mailDomain.update({ where: { id: domain.id }, data: { deleted_at: new Date(), is_active: false } });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.domain.delete',
        parameters: { mail_domain_id: domain.id, domain: domain.name },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
  }

  // ---- mailboxes ------------------------------------------------------------------

  async listMailboxes(actor: Actor | undefined, domainId: string): Promise<{ data: MailboxDto[] }> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const rows = await this.prisma.mailboxe.findMany({
      where: { mail_domain_id: domain.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
    });
    return { data: rows.map((r) => toMailboxDto(r, domain.name)) };
  }

  async createMailbox(
    actor: Actor | undefined,
    domainId: string,
    input: { local_part?: unknown; password?: unknown; quota_mb?: unknown },
  ): Promise<MailboxDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const account = {
      id: domain.hosting_account_id,
      username: domain.hosting_account.username,
      package_id: domain.hosting_account.package_id,
    };
    await this.assertMailAllowed(account);

    const localPart = typeof input.local_part === 'string' ? input.local_part.trim().toLowerCase() : '';
    if (!LOCAL_PART_RE.test(localPart)) {
      throw new BadRequestException(
        'local_part must be 1-64 chars: lowercase letters, digits, dot, dash, underscore, plus (no leading/trailing dot)',
      );
    }
    const dup = await this.prisma.mailboxe.findFirst({
      where: { mail_domain_id: domain.id, local_part: localPart, deleted_at: null },
      select: { id: true },
    });
    if (dup) throw new ConflictException('this mailbox already exists on the domain');

    const password = typeof input.password === 'string' ? input.password : '';
    try {
      assertPasswordShape(password);
    } catch (e) {
      throw new BadRequestException((e as Error).message);
    }
    const policy = await this.mailPolicyOf(account);
    const quotaMb = input.quota_mb === undefined || input.quota_mb === null || input.quota_mb === '' ? 1024 : Number(input.quota_mb);
    await this.assertMailboxQuota(account, quotaMb, policy.maxQuotaMb);
    await this.assertMailboxCount(account, policy.maxBoxes);

    // Agent first: no panel row unless the maildir + map entry exist.
    let agentResult: Awaited<ReturnType<AgentClientService['mailCreateMailbox']>>;
    try {
      agentResult = await this.agent.mailCreateMailbox(`${localPart}@${domain.name}`, quotaMb);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.mailbox.create',
        parameters: { mail_domain_id: domain.id, address: `${localPart}@${domain.name}`, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
    if (agentResult.ownership?.applied === false && agentResult.ownership.skipped) {
      this.logger.warn(`mailbox ${localPart}@${domain.name}: ${agentResult.ownership.skipped}`);
    }

    const passwordHash = Buffer.from(hashMailboxPassword(password), 'utf8');
    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.mailboxe.create({
        data: {
          mail_domain_id: domain.id,
          local_part: localPart,
          password_hash: passwordHash,
          quota_mb: quotaMb,
          is_active: true,
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.mailbox.create',
        parameters: {
          mailbox_id: created.id,
          address: `${localPart}@${domain.name}`,
          quota_mb: quotaMb,
          maildir: agentResult.maildir,
          ownership_applied: agentResult.ownership?.applied ?? false,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return created;
    });
    return toMailboxDto(row, domain.name);
  }

  async updateMailbox(
    actor: Actor | undefined,
    domainId: string,
    mailboxId: string,
    input: { quota_mb?: unknown },
  ): Promise<MailboxDto> {
    const box = await this.requireVisibleMailbox(domainId, mailboxId, actor);
    const domain = await this.prisma.mailDomain.findFirstOrThrow({
      where: { id: box.mail_domain_id },
      include: { hosting_account: { select: { username: true, package_id: true } } },
    });
    const account = {
      id: domain.hosting_account_id,
      username: domain.hosting_account.username,
      package_id: domain.hosting_account.package_id,
    };
    const policy = await this.mailPolicyOf(account);
    const quotaMb = Number(input.quota_mb);
    await this.assertMailboxQuota(account, quotaMb, policy.maxQuotaMb);
    try {
      await this.agent.mailModifyMailbox(`${box.local_part}@${domain.name}`, quotaMb);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.mailbox.update',
        parameters: { mailbox_id: box.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
    const updated = await this.prisma.$transaction(async (tx) => {
      const row = await tx.mailboxe.update({ where: { id: box.id }, data: { quota_mb: quotaMb, updated_at: new Date() } });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.mailbox.update',
        parameters: { mailbox_id: box.id, quota_mb: quotaMb },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return row;
    });
    return toMailboxDto(updated, domain.name);
  }

  /** Rotates the mailbox password. Panel-DB only — the agent is not in the password path (ADR-0013). */
  async setMailboxPassword(
    actor: Actor | undefined,
    domainId: string,
    mailboxId: string,
    input: { password?: unknown },
  ): Promise<void> {
    const box = await this.requireVisibleMailbox(domainId, mailboxId, actor);
    const password = typeof input.password === 'string' ? input.password : '';
    let hash: string;
    try {
      hash = hashMailboxPassword(password);
    } catch (e) {
      throw new BadRequestException((e as Error).message);
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.mailboxe.update({
        where: { id: box.id },
        data: { password_hash: Buffer.from(hash, 'utf8'), updated_at: new Date() },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.mailbox.password',
        parameters: { mailbox_id: box.id },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: (
          await this.prisma.mailDomain.findFirstOrThrow({ where: { id: box.mail_domain_id }, select: { hosting_account_id: true } })
        ).hosting_account_id,
      });
    });
  }

  async deleteMailbox(
    actor: Actor | undefined,
    domainId: string,
    mailboxId: string,
    input: { preserve_mail?: unknown },
  ): Promise<{ preserved_as?: string }> {
    const box = await this.requireVisibleMailbox(domainId, mailboxId, actor);
    const domain = await this.prisma.mailDomain.findFirstOrThrow({
      where: { id: box.mail_domain_id },
      include: { hosting_account: { select: { id: true, username: true } } },
    });
    const address = `${box.local_part}@${domain.name}`;
    const preserve = input.preserve_mail === true;

    // Registry first for aliases pointed at the mailbox: the agent's mop-up
    // drops matching map lines; the rows must not outlive them.
    const pointingAliases = await this.prisma.mailAliase.findMany({
      where: { mail_domain_id: domain.id, deleted_at: null, destination_address: address },
      select: { id: true, source_address: true },
    });

    let preservedAs: string | undefined;
    try {
      const res = await this.agent.mailDeleteMailbox(address, preserve);
      preservedAs = res.preserved_as;
      for (const a of pointingAliases) {
        await this.agent.mailDeleteAlias(a.source_address);
      }
    } catch (e) {
      await this.audit.append({
        operation: 'mail.mailbox.delete',
        parameters: { mailbox_id: box.id, address, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.mailboxe.update({
        where: { id: box.id },
        data: { deleted_at: new Date(), is_active: false },
      });
      const now = new Date();
      for (const a of pointingAliases) {
        await tx.mailAliase.update({ where: { id: a.id }, data: { deleted_at: now } });
      }
      await this.audit.appendWithClient(tx, {
        operation: 'mail.mailbox.delete',
        parameters: {
          mailbox_id: box.id,
          address,
          preserve_mail: preserve,
          preserved: preservedAs ? true : false,
          aliases_removed: pointingAliases.length,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
    return { preserved_as: preservedAs };
  }

  // ---- aliases -------------------------------------------------------------------

  async listAliases(actor: Actor | undefined, domainId: string): Promise<{ data: MailAliasDto[] }> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const rows = await this.prisma.mailAliase.findMany({
      where: { mail_domain_id: domain.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
    });
    return {
      data: rows.map((r) => ({
        id: r.id,
        mail_domain_id: r.mail_domain_id,
        source_address: r.source_address,
        destination_address: r.destination_address,
        is_catchall: r.is_catchall,
        created_at: r.created_at.toISOString(),
      })),
    };
  }

  async createAlias(
    actor: Actor | undefined,
    domainId: string,
    input: { source?: unknown; destination?: unknown },
  ): Promise<MailAliasDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const source = typeof input.source === 'string' ? input.source.trim().toLowerCase() : '';
    const destination = typeof input.destination === 'string' ? input.destination.trim().toLowerCase() : '';

    let sourceAddress: string;
    let isCatchall = false;
    if (source.startsWith('@')) {
      if (!MAIL_DOMAIN_RE.test(source.slice(1))) {
        throw new BadRequestException('catch-all source must be "@domain"');
      }
      if (source !== `@${domain.name}`) {
        throw new BadRequestException(`catch-all must target this domain (@${domain.name})`);
      }
      sourceAddress = source;
      isCatchall = true;
    } else {
      // Accept a bare local part ("help") or a full address on this domain.
      const at = source.indexOf('@');
      const local = at === -1 ? source : source.slice(0, at);
      const dom = at === -1 ? domain.name : source.slice(at + 1);
      if (!LOCAL_PART_RE.test(local) || dom !== domain.name) {
        throw new BadRequestException(`source must be a local part on ${domain.name} (or "@${domain.name}" for a catch-all)`);
      }
      sourceAddress = `${local}@${domain.name}`;
    }

    const destAt = destination.indexOf('@');
    if (
      destAt <= 0 ||
      !LOCAL_PART_RE.test(destination.slice(0, destAt)) ||
      !MAIL_DOMAIN_RE.test(destination.slice(destAt + 1))
    ) {
      throw new BadRequestException('destination must be a full email address (local@domain)');
    }
    if (sourceAddress === destination) {
      throw new BadRequestException('alias source and destination must differ (that would loop)');
    }

    const dup = await this.prisma.mailAliase.findFirst({
      where: { mail_domain_id: domain.id, source_address: sourceAddress, deleted_at: null },
      select: { id: true },
    });
    if (dup) throw new ConflictException('this alias source already exists on the domain');

    try {
      await this.agent.mailCreateAlias(sourceAddress, destination);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.alias.create',
        parameters: { mail_domain_id: domain.id, source: sourceAddress, destination, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.mailAliase.create({
        data: {
          mail_domain_id: domain.id,
          source_address: sourceAddress,
          destination_address: destination,
          is_catchall: isCatchall,
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.alias.create',
        parameters: { alias_id: created.id, source: sourceAddress, destination, catchall: isCatchall },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      return created;
    });
    return {
      id: row.id,
      mail_domain_id: row.mail_domain_id,
      source_address: row.source_address,
      destination_address: row.destination_address,
      is_catchall: row.is_catchall,
      created_at: row.created_at.toISOString(),
    };
  }

  async deleteAlias(actor: Actor | undefined, domainId: string, aliasId: string): Promise<void> {
    await this.requireVisibleDomain(domainId, actor);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(aliasId)) {
      throw new NotFoundException('mail alias not found');
    }
    const row = await this.prisma.mailAliase.findFirst({
      where: { id: aliasId, mail_domain_id: domainId, deleted_at: null },
    });
    if (!row) throw new NotFoundException('mail alias not found');
    const domain = await this.prisma.mailDomain.findFirstOrThrow({
      where: { id: domainId },
      select: { hosting_account_id: true },
    });
    try {
      await this.agent.mailDeleteAlias(row.source_address);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.alias.delete',
        parameters: { alias_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.mailAliase.update({ where: { id: row.id }, data: { deleted_at: new Date() } });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.alias.delete',
        parameters: { alias_id: row.id, source: row.source_address },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
  }

  // ---- autoresponders -------------------------------------------------------------

  async listAutoresponders(actor: Actor | undefined, domainId: string): Promise<{ data: AutoresponderDto[] }> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const rows = await this.prisma.autoresponder.findMany({
      where: { mailbox: { mail_domain_id: domain.id, deleted_at: null } },
      orderBy: { created_at: 'asc' },
      include: { mailbox: { select: { local_part: true } } },
    });
    return { data: rows.map((r) => toAutoresponderDto(r, r.mailbox.local_part, domain.name)) };
  }

  async createAutoresponder(
    actor: Actor | undefined,
    domainId: string,
    input: { mailbox_id?: unknown; subject?: unknown; body?: unknown; starts_at?: unknown; ends_at?: unknown },
  ): Promise<AutoresponderDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const mailboxId = typeof input.mailbox_id === 'string' ? input.mailbox_id : '';
    const box = await this.requireVisibleMailbox(domainId, mailboxId, actor);
    const subject = typeof input.subject === 'string' ? input.subject.trim() : '';
    const body = typeof input.body === 'string' ? input.body : '';
    if (!subject || subject.length > 255) {
      throw new BadRequestException('subject must be 1-255 chars');
    }
    if (!body.trim() || body.length > 8192 || body.includes('\0')) {
      throw new BadRequestException('body must be 1-8192 bytes without NUL');
    }
    const startsAt = parseOptionalDate(input.starts_at, 'starts_at');
    const endsAt = parseOptionalDate(input.ends_at, 'ends_at');
    if (startsAt && endsAt && endsAt <= startsAt) {
      throw new BadRequestException('ends_at must be after starts_at');
    }
    if (startsAt && startsAt.getTime() > Date.now()) {
      // Honest: the window is stored, the Sieve file is written active, and
      // the UI will show "scheduled" — the B13 job framework will flip files
      // at window edges (not yet built).
      this.logger.warn(
        `autoresponder for ${box.local_part}@${domain.name} has a future start — stored, but the node file goes live now (B13 flips it)`,
      );
    }

    try {
      await this.agent.mailCreateAutoresponder(`${box.local_part}@${domain.name}`, subject, body);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.autoresponder.create',
        parameters: { mailbox_id: box.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.autoresponder.create({
        data: {
          mailbox_id: box.id,
          subject,
          body,
          starts_at: startsAt,
          ends_at: endsAt,
        },
        include: { mailbox: { select: { local_part: true } } },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.autoresponder.create',
        parameters: { autoresponder_id: created.id, mailbox_id: box.id },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      return created;
    });
    return toAutoresponderDto(row, box.local_part, domain.name);
  }

  async deleteAutoresponder(actor: Actor | undefined, domainId: string, autoresponderId: string): Promise<void> {
    await this.requireVisibleDomain(domainId, actor);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(autoresponderId)) {
      throw new NotFoundException('autoresponder not found');
    }
    const row = await this.prisma.autoresponder.findFirst({
      where: { id: autoresponderId, mailbox: { mail_domain_id: domainId, deleted_at: null } },
      include: { mailbox: { select: { id: true, local_part: true } } },
    });
    if (!row) throw new NotFoundException('autoresponder not found');
    const domain = await this.prisma.mailDomain.findFirstOrThrow({
      where: { id: domainId },
      select: { name: true, hosting_account_id: true },
    });
    try {
      await this.agent.mailDeleteAutoresponder(`${row.mailbox.local_part}@${domain.name}`);
    } catch (e) {
      await this.audit.append({
        operation: 'mail.autoresponder.delete',
        parameters: { autoresponder_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.autoresponder.delete({ where: { id: row.id } });
      await this.audit.appendWithClient(tx, {
        operation: 'mail.autoresponder.delete',
        parameters: { autoresponder_id: row.id, mailbox_id: row.mailbox.id },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
  }
}

function toMailboxDto(
  row: { id: string; mail_domain_id: string; local_part: string; quota_mb: number; used_mb: number; is_active: boolean; created_at: Date; updated_at: Date },
  domainName: string,
): MailboxDto {
  return {
    id: row.id,
    mail_domain_id: row.mail_domain_id,
    address: `${row.local_part}@${domainName}`,
    quota_mb: row.quota_mb,
    used_mb: row.used_mb,
    is_active: row.is_active,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
  };
}

function toAutoresponderDto(
  row: {
    id: string;
    mailbox_id: string;
    subject: string;
    starts_at: Date | null;
    ends_at: Date | null;
    created_at: Date;
  },
  localPart: string,
  domainName: string,
): AutoresponderDto {
  const now = Date.now();
  let scheduleState: AutoresponderDto['schedule_state'] = 'active';
  if (row.starts_at && row.starts_at.getTime() > now) scheduleState = 'scheduled';
  else if (row.ends_at && row.ends_at.getTime() < now) scheduleState = 'expired';
  return {
    id: row.id,
    mailbox_id: row.mailbox_id,
    address: `${localPart}@${domainName}`,
    subject: row.subject,
    starts_at: row.starts_at ? row.starts_at.toISOString() : null,
    ends_at: row.ends_at ? row.ends_at.toISOString() : null,
    schedule_state: scheduleState,
    created_at: row.created_at.toISOString(),
  };
}

function parseOptionalDate(v: unknown, field: string): Date | null {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string') throw new BadRequestException(`${field} must be an ISO 8601 timestamp`);
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) {
    throw new BadRequestException(`${field} must be an ISO 8601 timestamp`);
  }
  return d;
}
