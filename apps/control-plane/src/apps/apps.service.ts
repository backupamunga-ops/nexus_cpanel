import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { DatabasesService } from '../databases/databases.service';
import { SitesService } from '../sites/sites.service';
import { Actor } from '../sites/sites.service';

/**
 * App installer (API spec §4.7a, ADR-0019, B14).
 *
 * WordPress first. The heavy lifting happens ON THE NODE through the
 * agent: WP-CLI runs as the account's unix user (never root), DB
 * credentials ride the signed command channel and land only inside
 * wp-config.php (0600), and the WP admin password is generated agent-side,
 * returned ONCE by this service, and never persisted.
 *
 * The panel owns the registry (installed_applications, DDL-first) and
 * orchestrates the one-click flow: a fresh MariaDB database is
 * provisioned through DatabasesService (B09 policy: engine lock, package
 * quotas, SecretBox credentials at rest) before the agent installs.
 *
 * One-click staging clone: provisions a second database, asks the agent
 * to copy the tree + swap the copied wp-config.php + dump/import/
 * search-replace, then publishes the clone on a staging subdomain
 * (staging_environments registry).
 */

const APP_PATH_RE = /^[\w][\w./ -]{0,255}$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/;

export interface InstalledAppDto {
  id: string;
  domain_id: string;
  domain: string;
  account_username: string;
  app_type: string;
  version: string | null;
  install_path: string;
  admin_user: string | null;
  status: string;
  created_at: string;
}

export interface InstalledAppSecretDto extends InstalledAppDto {
  admin_password?: string;
  log?: string;
}

@Injectable()
export class AppsService {
  private readonly logger = new Logger(AppsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    private readonly databases: DatabasesService,
    private readonly sites: SitesService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  async listApps(actor?: Actor): Promise<{ data: InstalledAppDto[] }> {
    const rows = await this.prisma.installedApplication.findMany({
      where: { deleted_at: null },
      orderBy: { created_at: 'desc' },
      include: {
        domain: {
          include: { hosting_account: { select: { id: true, username: true } } },
        },
      },
    });
    const visible = [] as typeof rows;
    for (const r of rows) {
      if (await this.canSee(r.domain.hosting_account.id, actor)) visible.push(r);
    }
    return { data: visible.map((r) => this.toDto(r)) };
  }

  /**
   * One-click WordPress install. Provisions a fresh database unless the
   * caller brings its own (create_db: false + explicit db_* fields).
   */
  async installWordPress(
    actor: Actor | undefined,
    input: {
      domain_id?: unknown;
      path?: unknown;
      title?: unknown;
      admin_user?: unknown;
      admin_email?: unknown;
      create_db?: unknown;
      db_name?: unknown;
      db_user?: unknown;
      db_password?: unknown;
    },
  ): Promise<InstalledAppSecretDto> {
    if (typeof input.domain_id !== 'string' || !input.domain_id) {
      throw new BadRequestException('domain_id is required');
    }
    const domain = await this.prisma.domain.findFirst({
      where: { id: input.domain_id, deleted_at: null, is_active: true },
      include: {
        hosting_account: { select: { id: true, username: true, homedir: true } },
      },
    });
    if (!domain) throw new NotFoundException('domain not found');
    const account = domain.hosting_account;
    if (!(await this.canSee(account.id, actor))) throw new NotFoundException('domain not found');

    // Install path — relative to the account home, confined by the agent.
    const docrootRel = domain.document_root.startsWith(`${account.homedir}/`)
      ? domain.document_root.slice(account.homedir.length + 1)
      : '';
    const path =
      typeof input.path === 'string' && input.path.trim() !== ''
        ? input.path.trim().replace(/^\/+|\/+$/g, '')
        : docrootRel;
    if (!path || path.includes('..') || !APP_PATH_RE.test(path)) {
      throw new BadRequestException(
        'path must be a directory relative to the account home (e.g. public_html)',
      );
    }

    // Site URL: the docroot itself maps to the bare domain; anything under
    // it becomes a subdirectory URL.
    const url =
      path === docrootRel
        ? `https://${domain.name}`
        : `https://${domain.name}/${path.slice(docrootRel.length + 1)}`;

    const title = typeof input.title === 'string' ? input.title.trim() : '';
    if (!title || title.length > 120 || /[<>{};`\r\n]/.test(title)) {
      throw new BadRequestException('title must be 1-120 plain characters');
    }
    const adminUser = typeof input.admin_user === 'string' ? input.admin_user.trim() : '';
    if (!/^[a-zA-Z0-9_.@-]{1,60}$/.test(adminUser)) {
      throw new BadRequestException('invalid admin_user');
    }
    const adminEmail = typeof input.admin_email === 'string' ? input.admin_email.trim() : '';
    if (!EMAIL_RE.test(adminEmail)) throw new BadRequestException('invalid admin_email');

    // Database: auto-provision through DatabasesService (policy + quotas +
    // SecretBox) or accept caller-provided credentials.
    let dbName: string;
    let dbUser: string;
    let dbPassword: string;
    let databaseId: string | null = null;
    if (input.create_db === false) {
      dbName = typeof input.db_name === 'string' ? input.db_name.trim() : '';
      dbUser = typeof input.db_user === 'string' ? input.db_user.trim() : '';
      dbPassword = typeof input.db_password === 'string' ? input.db_password : '';
      if (!dbName || !dbUser || dbPassword.length < 8) {
        throw new BadRequestException(
          'db_name, db_user and db_password (8+ chars) are required when create_db is false',
        );
      }
    } else {
      const dbNameGen = `wp${randomBytes(4).toString('hex')}`;
      dbPassword = randomBytes(24).toString('base64url');
      const created = await this.databases.create(actor, {
        account_id: account.id,
        engine: 'mariadb',
        name: dbNameGen,
        password: dbPassword, // we generate it — create() stores it SecretBox-ed and returns no secrets
      });
      dbName = created.name;
      dbUser = created.db_user;
      databaseId = created.id;
    }

    // Job-center mirror (B13): the install is visible in the jobs table.
    const jobRow = await this.prisma.jobMetadata.create({
      data: {
        bullmq_job_id: `apps_${randomBytes(8).toString('hex')}`,
        queue_name: 'apps',
        job_type: 'apps.install_wordpress',
        status: 'active',
        payload: {
          domain_id: domain.id,
          account_id: account.id,
          path,
          create_db: input.create_db !== false,
        } as object,
        attempts: 1,
      },
    });

    try {
      const res = await this.agent.appsInstallWordpress({
        username: account.username,
        path,
        url,
        title,
        admin_user: adminUser,
        admin_email: adminEmail,
        db_name: dbName,
        db_user: dbUser,
        db_password: dbPassword,
      });
      const row = await this.prisma.installedApplication.create({
        data: {
          domain_id: domain.id,
          app_type: 'wordpress',
          version: res.version || null,
          install_path: path,
          admin_user: adminUser,
          database_id: databaseId,
          status: 'active',
        },
      });
      await this.audit.append({
        operation: 'apps.install_wordpress',
        parameters: {
          app_id: row.id, domain: domain.name, path, url, db_name: dbName,
          version: res.version, executed_as: res.executed_as,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      await this.prisma.jobMetadata.update({
        where: { id: jobRow.id },
        data: {
          status: 'completed', progress: 100,
          result: { app_id: row.id, version: res.version } as object,
          completed_at: new Date(),
        },
      });
      // admin_password is returned ONCE — the caller must show and drop it.
      return {
        ...this.toDto({ ...row, domain }),
        admin_password: res.admin_password,
        log: res.log,
      };
    } catch (e) {
      await this.prisma.jobMetadata.update({
        where: { id: jobRow.id },
        data: { status: 'failed', result: { error: (e as Error).message } as object, completed_at: new Date() },
      }).catch(() => undefined);
      await this.audit.append({
        operation: 'apps.install_wordpress',
        parameters: { domain: domain.name, path, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }
  }

  /** Core + database update for an existing install (audited). */
  async updateApp(actor: Actor | undefined, appId: string): Promise<InstalledAppDto> {
    const { row, account } = await this.requireVisibleApp(actor, appId);
    if (row.app_type !== 'wordpress') {
      throw new BadRequestException('updates are wired for WordPress installs only');
    }
    const res = await this.agent.appsUpdateWordpress({
      username: account.username,
      path: row.install_path,
    });
    const updated = await this.prisma.installedApplication.update({
      where: { id: row.id },
      data: { version: res.version || row.version },
    });
    await this.audit.append({
      operation: 'apps.update_wordpress',
      parameters: { app_id: row.id, version: res.version, log_tail: res.log.slice(-400) },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: account.id,
    });
    return this.toDto({ ...updated, domain: row.domain });
  }

  /**
   * Allowlisted read-only WP-CLI maintenance pass-through (never an exec
   * hatch — the agent enforces the verb allowlist).
   */
  async runWpCli(
    actor: Actor | undefined,
    appId: string,
    input: { args?: unknown },
  ): Promise<{ status: string; output: string }> {
    const { row, account } = await this.requireVisibleApp(actor, appId);
    const args = Array.isArray(input.args) ? input.args.map(String) : [];
    if (args.length === 0 || args.length > 16) {
      throw new BadRequestException('args must be 1-16 wp-cli arguments');
    }
    const res = await this.agent.appsRunWpCli({
      username: account.username,
      path: row.install_path,
      args,
    });
    await this.audit.append({
      operation: 'apps.wp_cli',
      parameters: { app_id: row.id, args },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: account.id,
    });
    return { status: res.status, output: res.output };
  }

  /**
   * One-click staging clone: fresh staging database + full copy with
   * URL rewrite, published on <label>.<domain> with its own vhost.
   */
  async createStaging(
    actor: Actor | undefined,
    appId: string,
    input: { label?: unknown },
  ): Promise<{ staging_url: string; staging_path: string; database: string; log: string }> {
    const { row, domain, account } = await this.requireVisibleApp(actor, appId);
    if (row.app_type !== 'wordpress') {
      throw new BadRequestException('staging clones are wired for WordPress installs only');
    }
    const label =
      typeof input.label === 'string' && input.label.trim() !== ''
        ? input.label.trim().toLowerCase()
        : `stg${randomBytes(3).toString('hex')}`;
    if (!LABEL_RE.test(label)) {
      throw new BadRequestException('label must be a single DNS label (e.g. stg1)');
    }
    const dup = await this.prisma.stagingEnvironment.findFirst({
      where: {
        source_domain_id: domain.id,
        staging_subdomain: `${label}.${domain.name}`,
        deleted_at: null,
      },
      select: { id: true },
    });
    if (dup) throw new BadRequestException('this staging label already exists for the domain');

    const stagingPath = `staging-${label}`;
    const stagingUrl = `https://${label}.${domain.name}`;
    const prodUrl = `https://${domain.name}`;

    // 1. fresh staging database (B09 policy applies; credentials land in
    //    the staging wp-config.php only).
    const stagingDbPassword = randomBytes(24).toString('base64url');
    const db = await this.databases.create(actor, {
      account_id: account.id,
      engine: 'mariadb',
      name: `wp${randomBytes(3).toString('hex')}stg`,
      password: stagingDbPassword,
    });

    // 2. copy + config swap + dump/import/search-replace on the node.
    const res = await this.agent.appsStagingClone({
      username: account.username,
      source_path: row.install_path,
      staging_path: stagingPath,
      staging_url: stagingUrl,
      prod_url: prodUrl,
      db_name: db.name,
      db_user: db.db_user,
      db_password: stagingDbPassword,
    });

    // 3. publish the vhost + registry row.
    await this.sites.createSubdomain(
      domain.id,
      { name: label, document_root: `${account.homedir}/${stagingPath}` },
      actor,
    );
    await this.prisma.stagingEnvironment.create({
      data: {
        source_domain_id: domain.id,
        staging_subdomain: `${label}.${domain.name}`,
        document_root: `${account.homedir}/${stagingPath}`,
        cloned_at: new Date(),
      },
    });
    await this.audit.append({
      operation: 'apps.staging_clone',
      parameters: {
        app_id: row.id, staging_url: stagingUrl, staging_path: stagingPath,
        database: db.name,
      },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: account.id,
    });
    return {
      staging_url: stagingUrl,
      staging_path: res.staging_path,
      database: db.name,
      log: res.log,
    };
  }

  private toDto(r: {
    id: string;
    domain_id: string;
    domain: { name: string; hosting_account: { username: string } };
    app_type: string;
    version: string | null;
    install_path: string;
    admin_user: string | null;
    status: string;
    created_at: Date;
  }): InstalledAppDto {
    return {
      id: r.id,
      domain_id: r.domain_id,
      domain: r.domain.name,
      account_username: r.domain.hosting_account.username,
      app_type: r.app_type,
      version: r.version,
      install_path: r.install_path,
      admin_user: r.admin_user,
      status: r.status,
      created_at: r.created_at.toISOString(),
    };
  }

  private async requireVisibleApp(
    actor: Actor | undefined,
    appId: string,
  ): Promise<{
    row: {
      id: string; domain_id: string; app_type: string; install_path: string;
      admin_user: string | null; version: string | null; status: string; created_at: Date;
      domain: {
        id: string; name: string; hosting_account_id: string;
        hosting_account: { id: string; username: string; homedir: string };
      };
    };
    domain: { id: string; name: string };
    account: { id: string; username: string; homedir: string };
  }> {
    const row = await this.prisma.installedApplication.findFirst({
      where: { id: appId, deleted_at: null },
      include: {
        domain: {
          include: { hosting_account: { select: { id: true, username: true, homedir: true } } },
        },
      },
    });
    if (!row) throw new NotFoundException('app not found');
    const account = row.domain.hosting_account;
    if (!(await this.canSee(account.id, actor))) throw new NotFoundException('app not found');
    return {
      row,
      domain: { id: row.domain.id, name: row.domain.name },
      account,
    };
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
}
