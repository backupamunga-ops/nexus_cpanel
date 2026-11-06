import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { PhpService } from '../php/php.service';
import { renderVhost, logsDirForDocroot } from './vhost';

// The vhost renderer lives in ./vhost — shared with the php service, which
// refreshes the server block whenever a pool changes. Re-exported so the
// existing import sites keep working.
export { renderVhost, logsDirForDocroot } from './vhost';

/**
 * Sites & domains (API spec §4.7) — the P3 web-serving core.
 *
 * Ownership model (spec §3.2): every domain belongs to a hosting account.
 * Super admins see everything; every other caller only the domains of
 * accounts they hold an active access row for — and a resource they cannot
 * see is a 404, never a 403 (existence must not be enumerable across the
 * ownership boundary). The PermissionsGuard enforces the same boundary
 * before the service runs; these checks are the service-layer mirror for
 * list scoping and defense in depth.
 *
 * Provisioning order is agent-first (same contract as accounts): the agent
 * owns the machine, the database describes it. A failed agent call leaves
 * NO row behind; a failed DB write after a successful agent call is logged
 * loudly (the vhost serves but is unmanaged — the runbook covers repair).
 *
 * Every successful vhost apply writes a config_versions row (target_type
 * 'nginx_vhost') — the config engine (config-engine milestone) builds its
 * timeline, drift checks and rollback on top of that history.
 */

const FQDN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DOMAIN_TYPES = new Set(['primary', 'addon', 'parked']);
const REDIRECT_CODES = new Set([301, 302, 307, 308]);
// 8.5 joins the allowlist for distro-PHP nodes (Ubuntu 26.04 ships 8.5 and
// the ondrej/php repo has no resolute dist yet) — the same "use the distro
// archive on brand-new releases" ruling the installer already makes for
// PostgreSQL and Go.
const PHP_VERSIONS = new Set(['8.1', '8.2', '8.3', '8.4', '8.5']);

/**
 * Values embedded into nginx configuration get a strict allowlist, not a
 * blacklist: directive injection ("location /; return 302 evil") hides in
 * whitespace, quotes, braces and semicolons — none of those characters are
 * legal in the first place for paths and URLs of real sites.
 */
const PATH_RE = /^\/[A-Za-z0-9._~!$&'()*+,;=@%-]*$/;
const URL_RE = /^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/[A-Za-z0-9._~!$&'()*+,;=@%/-]*)?$/;

export interface DomainDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  name: string;
  type: string;
  document_root: string;
  php_version: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface SubdomainDto {
  id: string;
  domain_id: string;
  name: string;
  fqdn: string;
  document_root: string;
  php_version: string | null;
  created_at: string;
}

export interface AliasDto {
  id: string;
  domain_id: string;
  alias_name: string;
  created_at: string;
}

export interface RedirectDto {
  id: string;
  domain_id: string;
  source_path: string;
  destination_url: string;
  status_code: number;
  is_wildcard: boolean;
  created_at: string;
}

export interface Actor {
  userId?: string;
  isSuperAdmin?: boolean;
}

/**
 * Node serving posture for the Sites console (nginx.test is read-only).
 * installed=false is the documented pre-install state on a fresh node:
 * vhosts are recorded and serve once nginx lands — the console says so
 * instead of failing (live-VM finding #15).
 */
export interface ServingStatusDto {
  installed: boolean;
  healthy: boolean;
  detail: string | null;
}

interface DomainRow {
  id: string;
  hosting_account_id: string;
  name: string;
  type: string;
  document_root: string;
  php_version: string | null;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
  hosting_account?: { username: string } | null;
}

@Injectable()
export class SitesService {
  private readonly logger = new Logger(SitesService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
    private readonly php: PhpService,
  ) {}

  // ------------------------------------------------------------------ domains

  async list(actor?: Actor): Promise<{ data: DomainDto[] }> {
    const base = { deleted_at: null };
    const where =
      actor?.userId && !actor.isSuperAdmin
        ? {
            ...base,
            hosting_account: {
              user_hosting_account_access__hosting_account_id: {
                some: { user_id: actor.userId, revoked_at: null },
              },
            },
          }
        : base;
    const rows = await this.prisma.domain.findMany({
      where,
      orderBy: { created_at: 'desc' },
      take: 200,
      include: { hosting_account: { select: { username: true } } },
    });
    return { data: rows.map((r) => toDomainDto(r)) };
  }

  async get(id: string, actor?: Actor): Promise<DomainDto> {
    const row = await this.prisma.domain.findFirst({
      where: { id, deleted_at: null },
      include: { hosting_account: { select: { username: true } } },
    });
    if (!row || !(await this.canSee(row.hosting_account_id, actor))) {
      throw new NotFoundException('domain not found');
    }
    return toDomainDto(row);
  }

  /**
   * Node serving posture for the Sites console: is nginx installed and does
   * its config test pass? Read-only (nginx.test). installed=false is the
   * documented pre-install state (the vhost lands first; the health gate
   * reports the absent binary honestly). A failing `nginx -t` means nginx
   * IS present but its config is broken — surfaced here instead of hiding
   * behind a 503, so the operator sees what to fix.
   */
  async servingStatus(): Promise<ServingStatusDto> {
    try {
      const r = await this.agent.nginxTest();
      return {
        installed: r.status !== 'skipped',
        healthy: r.status === 'passed',
        detail: r.detail ?? null,
      };
    } catch (e) {
      const msg = (e as Error).message ?? '';
      if (e instanceof ServiceUnavailableException && msg.includes('nginx config test failed')) {
        return { installed: true, healthy: false, detail: msg };
      }
      throw e;
    }
  }

  async create(input: CreateDomainInput, actor?: Actor): Promise<DomainDto> {
    const name = normalizeName(input.name);
    if (!FQDN_RE.test(name) || name.length > 253) {
      throw new BadRequestException('name must be a lowercase FQDN (e.g. example.com)');
    }
    assertNotPanelHostname(name);
    const type = input.type === undefined || input.type === null ? 'primary' : input.type;
    if (typeof type !== 'string' || !DOMAIN_TYPES.has(type)) {
      throw new BadRequestException('type must be primary | addon | parked');
    }

    const accountId = typeof input.hosting_account_id === 'string' ? input.hosting_account_id : '';
    if (!/^[0-9a-f-]{36}$/i.test(accountId)) {
      throw new BadRequestException('hosting_account_id is required');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: {
        id: true,
        username: true,
        homedir: true,
        status: true,
        package: { select: { php_versions: true } },
      },
    });
    if (!account || !(await this.canSee(account.id, actor))) {
      throw new NotFoundException('hosting account not found');
    }
    if (account.status !== 'active') {
      throw new ConflictException('hosting account is not active');
    }

    const phpVersion = await this.validatePhpVersion(
      input.php_version,
      account.package?.php_versions ?? [],
    );

    const exists = await this.prisma.domain.findFirst({ where: { name }, select: { id: true } });
    if (exists) {
      throw new ConflictException('domain already exists');
    }

    const docroot = this.resolveDocroot(
      input.document_root,
      account.homedir,
      `domains/${name}/public_html`,
    );

    // Agent first: docroot, the logs dir (idempotent), then the vhost.
    // Any failure leaves no row.
    try {
      await this.agent.filesystemMkdir(account.username, docroot, 0o755);
      await this.agent.filesystemMkdir(account.username, logsDirForDocroot(docroot), 0o755);
      await this.agent.nginxApplyVhost(name, renderVhost(name, docroot, [], []));
      // A running nginx reads conf.d only on reload — apply without reload
      // leaves the block parked until some future restart. Skipped honestly
      // on nodes without the binary.
      await this.agent.nginxReload();
    } catch (e) {
      await this.audit.append({
        operation: 'site.create',
        parameters: { name, account_id: accountId, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: accountId,
      });
      throw e;
    }

    const content = renderVhost(name, docroot, [], []);
    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.domain.create({
        data: {
          hosting_account_id: accountId,
          name,
          type,
          document_root: docroot,
          php_version: phpVersion,
          is_active: true,
        },
      });
      await this.writeVhostVersion(tx, created.id, content, actor?.userId ?? null);
      await this.audit.appendWithClient(tx, {
        operation: 'site.create',
        parameters: { name, type, domain_id: created.id, document_root: docroot },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: accountId,
      });
      return created;
    });

    // PHP attach: the pool lifecycle (pool create, php_pool config_versions,
    // the domain's php_version column, the fastcgi vhost re-render + reload)
    // is the php service's single code path. A failure leaves the site live
    // and static — the honest pre-PHP state — audited here, reported by the
    // DTO as php_version null. The operator retries via PATCH php_version.
    let attachedPhp: string | null = phpVersion;
    if (phpVersion) {
      try {
        await this.php.update(row.id, { php_version: phpVersion }, actor);
      } catch (e) {
        attachedPhp = null;
        // The row was created with the requested version before the attach
        // ran — roll the column back to null so it stays honest with the
        // node (no pool exists).
        row.php_version = null;
        await this.prisma.domain
          .update({ where: { id: row.id }, data: { php_version: null, updated_at: new Date() } })
          .catch(() => undefined);
        this.logger.error(`php ${phpVersion} attach failed for ${name}: ${(e as Error).message}`);
        await this.audit.append({
          operation: 'site.php.attach',
          parameters: { domain_id: row.id, name, version: phpVersion, error: (e as Error).message },
          outcome: 'failure',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: accountId,
        });
      }
    }
    this.logger.log(`created domain ${name} for account ${account.username}`);
    return toDomainDto({ ...row, php_version: attachedPhp, hosting_account: { username: account.username } });
  }

  /**
   * PATCH /domains/{id}: name is immutable (it is the vhost filename and the
   * DNS contract — recreate the site instead). document_root, php_version,
   * type and is_active are mutable; a docroot change re-applies the vhost.
   */
  async update(id: string, input: UpdateDomainInput, actor?: Actor): Promise<DomainDto> {
    const row = await this.requireVisibleDomain(id, actor);
    const account = await this.requireAccount(row.hosting_account_id);
    const data: Record<string, unknown> = { updated_at: new Date() };
    let reapply = false;

    if (input.type !== undefined) {
      if (typeof input.type !== 'string' || !DOMAIN_TYPES.has(input.type)) {
        throw new BadRequestException('type must be primary | addon | parked');
      }
      data['type'] = input.type;
    }
    // PHP: validated here, provisioned by delegation below — the php service
    // owns BOTH the pool lifecycle and the php_version column (never written
    // from two code paths). undefined = untouched; null/'' = detach.
    let phpTarget: string | null | undefined;
    if (input.php_version !== undefined) {
      const pkg = await this.prisma.package.findFirst({
        where: { id: account.package_id, deleted_at: null },
        select: { php_versions: true },
      });
      phpTarget = await this.validatePhpVersion(input.php_version, pkg?.php_versions ?? []);
    }
    if (input.is_active !== undefined) {
      data['is_active'] = input.is_active === true;
    }
    if (input.document_root !== undefined) {
      const docroot = this.resolveDocroot(input.document_root, account.homedir, '');
      if (docroot !== row.document_root) {
        data['document_root'] = docroot;
        reapply = true;
      }
    }

    const [aliases, redirects] = await this.loadVhostInputs(row.id);
    const nextDocroot = (data['document_root'] as string) ?? row.document_root;
    const finalPhp = phpTarget !== undefined ? phpTarget : row.php_version;
    const content = renderVhost(row.name, nextDocroot, aliases, redirects, finalPhp);

    // Pool lifecycle FIRST: it re-renders the vhost against the current
    // committed docroot (a docroot change below re-renders again with the
    // new one — two applies that converge). "Nothing to remove" on a site
    // that never had PHP is the desired state, not an error.
    if (phpTarget !== undefined) {
      try {
        await this.php.update(row.id, { php_version: phpTarget }, actor);
      } catch (e) {
        if (phpTarget !== null || !/no PHP pool to remove/.test((e as Error).message)) {
          throw e;
        }
        data['php_version'] = null; // keep the column honest with the node
      }
    }

    if (reapply) {
      try {
        await this.agent.filesystemMkdir(account.username, nextDocroot, 0o755);
        await this.agent.nginxApplyVhost(row.name, content);
        await this.agent.nginxReload();
      } catch (e) {
        await this.audit.append({
          operation: 'site.update',
          parameters: { domain_id: row.id, name: row.name, error: (e as Error).message },
          outcome: 'failure',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: row.hosting_account_id,
        });
        throw e;
      }
    }

    const updated = await this.prisma.$transaction(async (tx) => {
      const u = await tx.domain.update({ where: { id: row.id }, data });
      if (reapply) {
        await this.writeVhostVersion(tx, row.id, content, actor?.userId ?? null);
      }
      await this.audit.appendWithClient(tx, {
        operation: 'site.update',
        parameters: {
          domain_id: row.id,
          name: row.name,
          fields: Object.keys(data).filter((k) => k !== 'updated_at'),
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      return u;
    });
    return toDomainDto({ ...updated, hosting_account: { username: account.username } });
  }

  /** Terminates a site: pool detached, vhost removed, then the row soft-deleted. */
  async remove(id: string, actor?: Actor): Promise<void> {
    const row = await this.requireVisibleDomain(id, actor);
    // Detach PHP first so a deleted domain never leaves an orphaned FPM pool
    // behind. A site whose pool already vanished detaches as a no-op.
    if (row.php_version) {
      try {
        await this.php.update(row.id, { php_version: null }, actor);
      } catch (e) {
        if (!/no PHP pool to remove/.test((e as Error).message)) {
          await this.audit.append({
            operation: 'site.delete',
            parameters: { domain_id: row.id, name: row.name, error: (e as Error).message },
            outcome: 'failure',
            actorUserId: actor?.userId ?? null,
            hostingAccountId: row.hosting_account_id,
          });
          throw e;
        }
      }
    }
    try {
      await this.agent.nginxRemoveVhost(row.name);
      await this.agent.nginxReload();
    } catch (e) {
      await this.audit.append({
        operation: 'site.delete',
        parameters: { domain_id: row.id, name: row.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }

    await this.prisma.$transaction(async (tx) => {
      const now = new Date();
      await tx.domain.update({ where: { id: row.id }, data: { deleted_at: now, is_active: false } });
      await tx.subdomain.updateMany({
        where: { domain_id: row.id, deleted_at: null },
        data: { deleted_at: now },
      });
      await tx.domainAliase.updateMany({
        where: { domain_id: row.id, deleted_at: null },
        data: { deleted_at: now },
      });
      await tx.redirect.updateMany({
        where: { domain_id: row.id, deleted_at: null },
        data: { deleted_at: now },
      });
      await tx.configVersion.updateMany({
        where: { target_type: 'nginx_vhost', target_id: row.id, is_active: true },
        data: { is_active: false },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'site.delete',
        parameters: { domain_id: row.id, name: row.name },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
    });
    this.logger.log(`deleted domain ${row.name} (${row.id})`);
  }

  // --------------------------------------------------------------- subdomains

  async listSubdomains(domainId: string, actor?: Actor): Promise<{ data: SubdomainDto[] }> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const rows = await this.prisma.subdomain.findMany({
      where: { domain_id: domain.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
    });
    return {
      data: rows.map((r) => ({
        id: r.id,
        domain_id: r.domain_id,
        name: r.name,
        fqdn: `${r.name}.${domain.name}`,
        document_root: r.document_root,
        php_version: r.php_version,
        created_at: r.created_at.toISOString(),
      })),
    };
  }

  async createSubdomain(
    domainId: string,
    input: { name?: unknown; document_root?: unknown },
    actor?: Actor,
  ): Promise<SubdomainDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const account = await this.requireAccount(domain.hosting_account_id);

    const label = typeof input.name === 'string' ? input.name.trim().toLowerCase() : '';
    if (!LABEL_RE.test(label)) {
      throw new BadRequestException(
        'name must be a single DNS label (e.g. blog for blog.example.com)',
      );
    }
    const fqdn = `${label}.${domain.name}`;
    assertNotPanelHostname(fqdn);
    const dup = await this.prisma.subdomain.findFirst({
      where: { domain_id: domain.id, name: label, deleted_at: null },
      select: { id: true },
    });
    if (dup) {
      throw new ConflictException('subdomain already exists for this domain');
    }

    const docroot = this.resolveDocroot(input.document_root, account.homedir, `subdomains/${label}`);
    try {
      await this.agent.filesystemMkdir(account.username, docroot, 0o755);
      // Shared per-account logs dir — idempotent, created with the first site.
      await this.agent.filesystemMkdir(account.username, logsDirForDocroot(docroot), 0o755);
      await this.agent.nginxApplyVhost(fqdn, renderVhost(fqdn, docroot, [], []));
      await this.agent.nginxReload();
    } catch (e) {
      await this.audit.append({
        operation: 'site.subdomain.create',
        parameters: { domain_id: domain.id, fqdn, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }

    const content = renderVhost(fqdn, docroot, [], []);
    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.subdomain.create({
        data: { domain_id: domain.id, name: label, document_root: docroot },
      });
      await this.writeVhostVersion(tx, created.id, content, actor?.userId ?? null);
      await this.audit.appendWithClient(tx, {
        operation: 'site.subdomain.create',
        parameters: {
          domain_id: domain.id,
          subdomain_id: created.id,
          fqdn,
          document_root: docroot,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      return created;
    });
    return {
      id: row.id,
      domain_id: row.domain_id,
      name: row.name,
      fqdn,
      document_root: row.document_root,
      php_version: row.php_version,
      created_at: row.created_at.toISOString(),
    };
  }

  async deleteSubdomain(domainId: string, subId: string, actor?: Actor): Promise<void> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const sub = await this.prisma.subdomain.findFirst({
      where: { id: subId, domain_id: domain.id, deleted_at: null },
    });
    if (!sub) {
      throw new NotFoundException('subdomain not found');
    }
    try {
      await this.agent.nginxRemoveVhost(`${sub.name}.${domain.name}`);
    } catch (e) {
      await this.audit.append({
        operation: 'site.subdomain.delete',
        parameters: {
          subdomain_id: sub.id,
          fqdn: `${sub.name}.${domain.name}`,
          error: (e as Error).message,
        },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.subdomain.update({ where: { id: sub.id }, data: { deleted_at: new Date() } });
      await tx.configVersion.updateMany({
        where: { target_type: 'nginx_vhost', target_id: sub.id, is_active: true },
        data: { is_active: false },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'site.subdomain.delete',
        parameters: { subdomain_id: sub.id, fqdn: `${sub.name}.${domain.name}` },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
  }

  // ------------------------------------------------------------------ aliases

  async listAliases(domainId: string, actor?: Actor): Promise<{ data: AliasDto[] }> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const rows = await this.prisma.domainAliase.findMany({
      where: { domain_id: domain.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
    });
    return {
      data: rows.map((r) => ({
        id: r.id,
        domain_id: r.domain_id,
        alias_name: r.alias_name,
        created_at: r.created_at.toISOString(),
      })),
    };
  }

  /** Adding/removing an alias rewrites the parent vhost (server_name list). */
  async createAlias(
    domainId: string,
    input: { alias_name?: unknown },
    actor?: Actor,
  ): Promise<AliasDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const alias = normalizeName(input.alias_name);
    if (!FQDN_RE.test(alias) || alias.length > 253) {
      throw new BadRequestException('alias_name must be a lowercase FQDN');
    }
    if (alias === domain.name) {
      throw new BadRequestException('alias cannot equal the domain itself');
    }
    assertNotPanelHostname(alias);
    const dup = await this.prisma.domainAliase.findFirst({
      where: { alias_name: alias },
      select: { id: true },
    });
    if (dup) {
      throw new ConflictException('alias is already in use');
    }

    await this.reapplyParentVhost(domain, 'site.alias.create', { alias }, actor, (aliases, redirects) => ({
      aliases: [...aliases, alias],
      redirects,
    }));

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.domainAliase.create({
        data: { domain_id: domain.id, alias_name: alias },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'site.alias.create',
        parameters: { domain_id: domain.id, alias },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      return created;
    });
    return {
      id: row.id,
      domain_id: row.domain_id,
      alias_name: row.alias_name,
      created_at: row.created_at.toISOString(),
    };
  }

  async deleteAlias(domainId: string, aliasId: string, actor?: Actor): Promise<void> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const alias = await this.prisma.domainAliase.findFirst({
      where: { id: aliasId, domain_id: domain.id, deleted_at: null },
    });
    if (!alias) {
      throw new NotFoundException('alias not found');
    }
    await this.reapplyParentVhost(
      domain,
      'site.alias.delete',
      { alias: alias.alias_name, removed: true },
      actor,
      (aliases, redirects) => ({ aliases: aliases.filter((a) => a !== alias.alias_name), redirects }),
    );
    await this.prisma.$transaction(async (tx) => {
      await tx.domainAliase.update({ where: { id: alias.id }, data: { deleted_at: new Date() } });
      await this.audit.appendWithClient(tx, {
        operation: 'site.alias.delete',
        parameters: { domain_id: domain.id, alias: alias.alias_name },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
  }

  // ---------------------------------------------------------------- redirects

  async listRedirects(domainId: string, actor?: Actor): Promise<{ data: RedirectDto[] }> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const rows = await this.prisma.redirect.findMany({
      where: { domain_id: domain.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
    });
    return { data: rows.map(toRedirectDto) };
  }

  async createRedirect(
    domainId: string,
    input: CreateRedirectInput,
    actor?: Actor,
  ): Promise<RedirectDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const { source_path, destination_url, status_code, is_wildcard } =
      validateRedirectInput(input);

    await this.reapplyParentVhost(
      domain,
      'site.redirect.create',
      { source_path, destination_url },
      actor,
      (aliases, redirects) => ({
        aliases,
        redirects: [
          ...redirects,
          {
            id: '',
            domain_id: domain.id,
            source_path,
            destination_url,
            status_code,
            is_wildcard,
            created_at: new Date().toISOString(),
          },
        ],
      }),
    );

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.redirect.create({
        data: {
          domain_id: domain.id,
          source_path,
          destination_url,
          status_code,
          is_wildcard,
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'site.redirect.create',
        parameters: { domain_id: domain.id, source_path, destination_url, status_code },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      return created;
    });
    return toRedirectDto(row);
  }

  async deleteRedirect(domainId: string, redirectId: string, actor?: Actor): Promise<void> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const row = await this.prisma.redirect.findFirst({
      where: { id: redirectId, domain_id: domain.id, deleted_at: null },
    });
    if (!row) {
      throw new NotFoundException('redirect not found');
    }
    await this.reapplyParentVhost(
      domain,
      'site.redirect.delete',
      { source_path: row.source_path, removed: true },
      actor,
      (aliases, redirects) => ({
        aliases,
        redirects: redirects.filter((r) => r.id !== row.id),
      }),
    );
    await this.prisma.$transaction(async (tx) => {
      await tx.redirect.update({ where: { id: row.id }, data: { deleted_at: new Date() } });
      await this.audit.appendWithClient(tx, {
        operation: 'site.redirect.delete',
        parameters: { domain_id: domain.id, source_path: row.source_path },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
  }

  // ---------------------------------------------------------------- site logs

  /**
   * GET /domains/{id}/logs — tail of the site's access or error log (P3).
   *
   * nginx writes the logs inside the account's own home (renderVhost emits
   * access_log/error_log under <homedir>/logs) and the tail is served
   * through the agent's ADR-0008 filesystem.read op — the viewer inherits
   * that path's confinement and the 10 MiB cap. A missing log file is an
   * honest empty answer (exists:false), not an error: the file appears
   * after the first request following a vhost (re)apply.
   */
  async logs(
    id: string,
    rawKind: unknown,
    rawLines: unknown,
    actor?: Actor,
  ): Promise<DomainLogDto> {
    const kind = rawKind === 'error' ? 'error' : 'access';
    const requested = Number(rawLines);
    const tail = Math.min(Math.max(Number.isFinite(requested) ? Math.trunc(requested) : 200, 10), 1000);

    const domain = await this.requireVisibleDomain(id, actor);
    const account = await this.requireAccount(domain.hosting_account_id);
    const file = `${logsDirForDocroot(domain.document_root)}/${domain.name}.${kind}.log`;

    let res: { size_bytes: number; content_b64: string; truncated: boolean };
    try {
      res = await this.agent.filesystemRead(account.username, file);
    } catch (e) {
      // The agent answers -32602 "path does not exist" for a log file that
      // has not been created yet; the client surfaces it as a 503 carrying
      // that message. An absent log is a state, not a failure.
      if (e instanceof ServiceUnavailableException && /path does not exist/.test(e.message)) {
        return {
          domain_id: domain.id,
          kind,
          file,
          exists: false,
          file_size_bytes: 0,
          file_truncated: false,
          total_lines: 0,
          lines: [],
        };
      }
      throw e;
    }

    const text = Buffer.from(res.content_b64, 'base64').toString('utf8');
    const all = text.split('\n');
    if (all.length > 0 && all[all.length - 1] === '') all.pop();
    return {
      domain_id: domain.id,
      kind,
      file,
      exists: true,
      file_size_bytes: res.size_bytes,
      file_truncated: res.truncated,
      total_lines: all.length,
      lines: all.slice(-tail),
    };
  }

  // ------------------------------------------------------------------ helpers

  /**
   * Alias/redirect changes rewrite the PARENT vhost. The apply happens
   * BEFORE the DB write (agent-first), so the rendered content is the
   * DESIRED state — `adjust` layers the pending change on top of the DB —
   * and the version row records exactly the bytes that were applied.
   */
  private async reapplyParentVhost(
    domain: DomainRow,
    operation: string,
    details: Record<string, unknown>,
    actor?: Actor,
    adjust?: (aliases: string[], redirects: RedirectDto[]) => { aliases: string[]; redirects: RedirectDto[] },
  ): Promise<void> {
    const current = { aliases: await this.activeAliases(domain.id), redirects: await this.activeRedirects(domain.id) };
    const desired = adjust ? adjust(current.aliases, current.redirects) : current;
    const content = renderVhost(domain.name, domain.document_root, desired.aliases, desired.redirects, domain.php_version);
    try {
      await this.agent.nginxApplyVhost(domain.name, content);
      await this.agent.nginxReload();
    } catch (e) {
      await this.audit.append({
        operation,
        parameters: {
          domain_id: domain.id,
          name: domain.name,
          ...details,
          error: (e as Error).message,
        },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await this.writeVhostVersion(tx, domain.id, content, actor?.userId ?? null);
    });
  }

  private async activeAliases(domainId: string): Promise<string[]> {
    const rows = await this.prisma.domainAliase.findMany({
      where: { domain_id: domainId, deleted_at: null },
      select: { alias_name: true },
    });
    return rows.map((r) => r.alias_name);
  }

  private async activeRedirects(domainId: string): Promise<RedirectDto[]> {
    const rows = await this.prisma.redirect.findMany({
      where: { domain_id: domainId, deleted_at: null },
    });
    return rows.map(toRedirectDto);
  }

  private async loadVhostInputs(domainId: string): Promise<[string[], RedirectDto[]]> {
    return [await this.activeAliases(domainId), await this.activeRedirects(domainId)];
  }

  /** Writes a new active config version, deactivating the previous one. */
  private async writeVhostVersion(
    tx: Prisma.TransactionClient,
    domainId: string,
    content: string,
    actorUserId: string | null,
  ): Promise<void> {
    const prev = await tx.configVersion.findFirst({
      where: { target_type: 'nginx_vhost', target_id: domainId },
      orderBy: { version: 'desc' },
      select: { version: true },
    });
    const nextVersion = (prev?.version ?? 0) + 1;
    await tx.configVersion.updateMany({
      where: { target_type: 'nginx_vhost', target_id: domainId, is_active: true },
      data: { is_active: false },
    });
    await tx.configVersion.create({
      data: {
        target_type: 'nginx_vhost',
        target_id: domainId,
        version: nextVersion,
        content,
        rendered_by: actorUserId,
        is_active: true,
      },
    });
  }

  private async canSee(accountId: string, actor?: Actor): Promise<boolean> {
    if (!actor?.userId) return false;
    if (actor.isSuperAdmin) return true;
    const access = await this.prisma.userHostingAccountAccess.findFirst({
      where: { user_id: actor.userId, hosting_account_id: accountId, revoked_at: null },
      select: { id: true },
    });
    return access !== null;
  }

  private async requireVisibleDomain(id: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('domain not found');
    }
    const row = await this.prisma.domain.findFirst({
      where: { id, deleted_at: null },
    });
    if (!row || !(await this.canSee(row.hosting_account_id, actor))) {
      throw new NotFoundException('domain not found');
    }
    return row;
  }

  private async requireAccount(accountId: string) {
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true, homedir: true, package_id: true },
    });
    if (!account) {
      throw new NotFoundException('hosting account not found');
    }
    return account;
  }

  /**
   * Docroots live inside the account home. The agent re-validates with the
   * full symlink-aware confinement; this prefix check keeps obviously-bad
   * input from ever reaching a signed command.
   */
  private resolveDocroot(requested: unknown, homedir: string, relativeDefault: string): string {
    if (requested === undefined || requested === null || String(requested).trim() === '') {
      return `${homedir}/${relativeDefault}`;
    }
    const raw = String(requested).trim();
    if (raw.includes('..') || raw.includes('\0') || !raw.startsWith(`${homedir}/`)) {
      throw new BadRequestException('document_root must stay inside the account home');
    }
    return raw;
  }

  private async validatePhpVersion(raw: unknown, allowed: string[]): Promise<string | null> {
    if (raw === undefined || raw === null || raw === '') {
      return null;
    }
    const v = String(raw);
    if (!PHP_VERSIONS.has(v)) {
      throw new BadRequestException('php_version must be one of 8.1 | 8.2 | 8.3 | 8.4 | 8.5');
    }
    if (allowed.length > 0 && !allowed.includes(v)) {
      throw new BadRequestException(`php_version ${v} is not offered by the account's package`);
    }
    return v;
  }
}

export interface CreateDomainInput {
  name?: unknown;
  type?: unknown;
  hosting_account_id?: unknown;
  document_root?: unknown;
  php_version?: unknown;
}

export interface UpdateDomainInput {
  type?: unknown;
  document_root?: unknown;
  php_version?: unknown;
  is_active?: unknown;
}

export interface CreateRedirectInput {
  source_path?: unknown;
  destination_url?: unknown;
  status_code?: unknown;
  is_wildcard?: unknown;
}

function normalizeName(raw: unknown): string {
  return typeof raw === 'string' ? raw.trim().toLowerCase() : '';
}

function validateRedirectInput(input: CreateRedirectInput): {
  source_path: string;
  destination_url: string;
  status_code: number;
  is_wildcard: boolean;
} {
  const sourcePath = typeof input.source_path === 'string' ? input.source_path.trim() : '';
  if (!PATH_RE.test(sourcePath) || sourcePath.length > 500) {
    throw new BadRequestException(
      'source_path must start with "/" and contain only URL-safe characters',
    );
  }
  const dest = typeof input.destination_url === 'string' ? input.destination_url.trim() : '';
  if (!URL_RE.test(dest) || dest.length > 1000) {
    throw new BadRequestException('destination_url must be an http(s) URL');
  }
  const code = input.status_code === undefined || input.status_code === null ? 301 : input.status_code;
  if (typeof code !== 'number' || !REDIRECT_CODES.has(code)) {
    throw new BadRequestException('status_code must be 301 | 302 | 307 | 308');
  }
  return {
    source_path: sourcePath,
    destination_url: dest,
    status_code: code,
    is_wildcard: input.is_wildcard === true,
  };
}

/**
 * The panel's own public hostname (ADR-0024): `infra/install.sh public-origin`
 * persists PANEL_PUBLIC_HOSTNAME into /etc/nexuspanel/nexuspanel.env. nginx
 * loads agent-managed site vhosts (conf.d/*.conf) BEFORE the panel-origin
 * vhost (sites-enabled), so a site claiming this exact hostname would shadow
 * the panel's own origin — creation is refused with a 409 instead
 * (live-VM finding #16). Unset on loopback-only boxes → nothing reserved.
 */
export function panelHostname(): string {
  return (process.env.PANEL_PUBLIC_HOSTNAME ?? '').trim().toLowerCase();
}

function assertNotPanelHostname(name: string): void {
  if (panelHostname() && name === panelHostname()) {
    throw new ConflictException(
      `${name} is the panel's own address — create the site on a different domain` +
        ' (a site on the panel hostname would take the panel itself offline)',
    );
  }
}

export interface DomainLogDto {
  domain_id: string;
  kind: 'access' | 'error';
  file: string;
  exists: boolean;
  file_size_bytes: number;
  file_truncated: boolean;
  total_lines: number;
  lines: string[];
}

function toDomainDto(row: DomainRow): DomainDto {
  return {
    id: row.id,
    hosting_account_id: row.hosting_account_id,
    account_username: row.hosting_account?.username ?? '',
    name: row.name,
    type: row.type,
    document_root: row.document_root,
    php_version: row.php_version,
    is_active: row.is_active,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
  };
}

function toRedirectDto(row: {
  id: string;
  domain_id: string;
  source_path: string;
  destination_url: string;
  status_code: number;
  is_wildcard: boolean;
  created_at: Date;
}): RedirectDto {
  return {
    id: row.id,
    domain_id: row.domain_id,
    source_path: row.source_path,
    destination_url: row.destination_url,
    status_code: row.status_code,
    is_wildcard: row.is_wildcard,
    created_at: row.created_at.toISOString(),
  };
}
