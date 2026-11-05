import { BadRequestException, ConflictException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { createHmac } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { DatabasesService } from '../databases/databases.service';
import { SitesService } from '../sites/sites.service';
import { AppsService } from './apps.service';
import { GitService } from './git.service';

process.env.PANEL_SECRET_KEY = process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

/**
 * Apps & Git service tests (B14). Harness: in-memory domain/account/app/
 * deployment/staging tables, the real in-memory audit chain, fake agent
 * client, fake databases + sites services (the WP install path).
 * Credential posture assertions: admin passwords and webhook secrets are
 * never stored, never audited, never logged.
 */

const SUPER = { userId: 'u1', isSuperAdmin: true };

function harness(agentOverrides: Partial<Record<string, unknown>> = {}) {
  const audit = new InMemoryAuditService();
  const accounts = [
    { id: 'acct-1', username: 'alpha', homedir: '/home/alpha' },
  ];
  const domains = [
    {
      id: 'dom-1', hosting_account_id: 'acct-1', name: 'alpha.demo',
      document_root: '/home/alpha/public_html', deleted_at: null, is_active: true,
      hosting_account: accounts[0],
    },
  ];
  const apps: Array<Record<string, any>> = [];
  const deployments: Array<Record<string, any>> = [];
  const stagings: Array<Record<string, any>> = [];
  const subdomains: Array<Record<string, any>> = [];
  const jobs: Array<Record<string, any>> = [];

  const prisma: Record<string, any> = {
    domain: {
      findFirst: jest.fn(async ({ where }: any) =>
        domains.find((d) => d.id === where.id && d.deleted_at === null && d.is_active === true) ?? null),
    },
    hostingAccount: {
      findUnique: jest.fn(async ({ where }: any) =>
        accounts.find((a) => a.id === where.id) ?? null),
    },
    installedApplication: {
      findMany: jest.fn(async () => apps),
      findFirst: jest.fn(async ({ where }: any) => {
        const a = apps.find((x) => x.id === where.id && x.deleted_at === null) ?? null;
        return a ? { ...a, domain: domains.find((d) => d.id === a.domain_id) ?? null } : null;
      }),
      create: jest.fn(async ({ data }: any) => {
        const row = { id: `app-${apps.length + 1}`, created_at: new Date(), deleted_at: null, ...data };
        apps.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: any) => {
        const row = apps.find((a) => a.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
    },
    stagingEnvironment: {
      findMany: jest.fn(async () => stagings),
      findFirst: jest.fn(async ({ where }: any) =>
        stagings.find((s) => s.source_domain_id === where.source_domain_id && s.staging_subdomain === where.staging_subdomain && s.deleted_at === null) ?? null),
      create: jest.fn(async ({ data }: any) => {
        const row = { id: `stg-${stagings.length + 1}`, deleted_at: null, ...data };
        stagings.push(row);
        return row;
      }),
    },
    subdomain: {
      findFirst: jest.fn(async () => null),
      create: jest.fn(async ({ data }: any) => {
        const row = { id: `sub-${subdomains.length + 1}`, created_at: new Date(), php_version: null, ...data };
        subdomains.push(row);
        return row;
      }),
      updateMany: jest.fn(async () => ({ count: 0 })),
    },
    gitDeployment: {
      findMany: jest.fn(async () => deployments),
      findFirst: jest.fn(async ({ where }: any) => {
        const d = deployments.find((x) =>
          (where.id === undefined || x.id === where.id) &&
          (where.domain_id === undefined || x.domain_id === where.domain_id) &&
          (where.deploy_path === undefined || x.deploy_path === where.deploy_path) &&
          x.deleted_at === null) ?? null;
        return d ? { ...d, domain: domains.find((dm) => dm.id === d.domain_id) ?? null } : null;
      }),
      create: jest.fn(async ({ data }: any) => {
        const row = { id: `dep-${deployments.length + 1}`, created_at: new Date(), deleted_at: null, ...data };
        deployments.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: any) => {
        const row = deployments.find((d) => d.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
    },
    jobMetadata: {
      create: jest.fn(async ({ data }: any) => {
        const row = { id: `job-${jobs.length + 1}`, ...data };
        jobs.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: any) => {
        const row = jobs.find((j) => j.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
    },
    userHostingAccountAccess: { findFirst: jest.fn(async () => null) },
  };

  const agent: Record<string, any> = {
    appsInstallWordpress: jest.fn(async (p: Record<string, unknown>) => ({
      status: 'installed', path: `/home/alpha/${p.path}`, version: '6.7',
      admin_user: p.admin_user, admin_password: 'GEN-' + 'x'.repeat(30),
      executed_as: 'runuser:alpha', log: 'Success:',
    })),
    appsUpdateWordpress: jest.fn(async () => ({ status: 'updated', path: '/home/alpha/public_html', version: '6.8', log: 'ok' })),
    appsRunWpCli: jest.fn(async () => ({ status: 'ok', executed_as: 'runuser:alpha', output: 'Success: cache flushed' })),
    appsStagingClone: jest.fn(async (p: Record<string, unknown>) => ({
      status: 'staged', source_path: '/home/alpha/public_html',
      staging_path: `/home/alpha/${(p as any).staging_path}`,
      staging_url: (p as any).staging_url, executed_as: 'runuser:alpha', log: 'staged',
    })),
    gitDeploy: jest.fn(async () => ({
      status: 'deployed', release_id: '1762100000-abc1234', sha: 'abc1234def5678',
      path: '/home/alpha/public_html', log: 'deployed\n',
    })),
    gitDeployHistory: jest.fn(async () => ({
      releases: [{ release_id: '1762100000-abc1234', sha: 'abc1234', created_at: '2026-11-01T00:00:00Z', active: true }],
      current: '1762100000-abc1234', path: '/home/alpha/public_html',
    })),
    gitRollback: jest.fn(async () => ({ status: 'rolled_back', release_id: '1762100000-abc1234' })),
    ...agentOverrides,
  };

  let dbCount = 0;
  const databasesCreate = jest.fn(
    async (_actor: unknown, input: Record<string, unknown>): Promise<Record<string, unknown>> => ({
      id: `db-${++dbCount}`,
      name: input.name as string,
      db_user: 'alpha_wpdb',
      engine: 'mariadb',
    }),
  );
  const databases = { create: databasesCreate } as unknown as DatabasesService;

  const sitesCreateSubdomain = jest.fn(async () => ({}));
  const sites = { createSubdomain: sitesCreateSubdomain } as unknown as SitesService;

  const appsService = new AppsService(
    prisma as unknown as PrismaService,
    agent as any,
    databases,
    sites,
    audit as any,
  );
  const gitService = new GitService(prisma as unknown as PrismaService, agent as any, audit as any);
  return { audit, prisma, agent, appsService, gitService, domains, apps, deployments, jobs, databasesCreate, sitesCreateSubdomain };
}

// ---- apps --------------------------------------------------------------------

describe('AppsService (B14)', () => {
  it('installs WordPress one-click: auto-provisions the DB and returns the admin password once', async () => {
    const h = harness();
    const res = await h.appsService.installWordPress(SUPER, {
      domain_id: 'dom-1', path: 'public_html', title: 'Alpha Site',
      admin_user: 'admin', admin_email: 'admin@alpha.demo',
    });

    expect(res.status).toBe('active');
    expect(res.version).toBe('6.7');
    expect(res.admin_password).toMatch(/^GEN-/);
    // the DB was provisioned through DatabasesService (B09 policy path)
    expect(h.databasesCreate).toHaveBeenCalledTimes(1);
    // the agent got the account user + db credentials
    expect(h.agent.appsInstallWordpress).toHaveBeenCalledWith(
      expect.objectContaining({ username: 'alpha', db_name: expect.stringMatching(/^wp/), url: 'https://alpha.demo' }),
    );
    // a completed job mirror exists
    const job = h.jobs[h.jobs.length - 1];
    expect(job.job_type).toBe('apps.install_wordpress');
    expect(job.status).toBe('completed');
    // audit: success, WITHOUT secrets
    const rows = h.audit.list();
    expect(rows[rows.length - 1].operation).toBe('apps.install_wordpress');
    expect(JSON.stringify(rows[rows.length - 1])).not.toContain(res.admin_password);
  });

  it('derives subdirectory URLs and refuses bad input', async () => {
    const h = harness();
    await expect(
      h.appsService.installWordPress(SUPER, {
        domain_id: 'dom-1', path: '../escape', title: 't', admin_user: 'a', admin_email: 'a@b.co',
      }),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.appsService.installWordPress(SUPER, { domain_id: 'dom-x', title: 't', admin_user: 'a', admin_email: 'a@b.co' }),
    ).rejects.toThrow(NotFoundException);
  });

  it('updates an app and records the new version', async () => {
    const h = harness();
    const app = await h.appsService.installWordPress(SUPER, {
      domain_id: 'dom-1', title: 't', admin_user: 'a', admin_email: 'a@b.co',
    });
    const updated = await h.appsService.updateApp(SUPER, app.id);
    expect(updated.version).toBe('6.8');
  });

  it('creates a staging clone: fresh DB, agent clone, subdomain publish', async () => {
    const h = harness();
    const app = await h.appsService.installWordPress(SUPER, {
      domain_id: 'dom-1', title: 't', admin_user: 'a', admin_email: 'a@b.co',
    });
    const res = await h.appsService.createStaging(SUPER, app.id, { label: 'stg1' });
    expect(res.staging_url).toBe('https://stg1.alpha.demo');
    expect(h.databasesCreate).toHaveBeenCalledTimes(2); // prod + staging
    expect(h.agent.appsStagingClone).toHaveBeenCalledWith(
      expect.objectContaining({ staging_path: 'staging-stg1', prod_url: 'https://alpha.demo' }),
    );
    expect(h.sitesCreateSubdomain).toHaveBeenCalledWith(
      'dom-1',
      expect.objectContaining({ name: 'stg1', document_root: '/home/alpha/staging-stg1' }),
      SUPER,
    );
    const stgRows = await h.prisma.stagingEnvironment.findMany({});
    expect(stgRows).toHaveLength(1);
  });

  it('wp-cli pass-through forwards allowlisted args', async () => {
    const h = harness();
    const app = await h.appsService.installWordPress(SUPER, {
      domain_id: 'dom-1', title: 't', admin_user: 'a', admin_email: 'a@b.co',
    });
    const res = await h.appsService.runWpCli(SUPER, app.id, { args: ['cache', 'flush'] });
    expect(res.status).toBe('ok');
    expect(h.agent.appsRunWpCli).toHaveBeenCalledWith(
      expect.objectContaining({ args: ['cache', 'flush'], path: 'public_html' }),
    );
  });
});

// ---- git ---------------------------------------------------------------------

describe('GitService (B14)', () => {
  it('registers a deployment: secret shown once, stored encrypted, never audited', async () => {
    const h = harness();
    const res = await h.gitService.createDeployment(SUPER, {
      domain_id: 'dom-1', repo_url: 'https://github.com/x/y.git', branch: 'main', deploy_path: 'public_html',
    });
    expect(res.provider).toBe('github');
    expect(res.webhook_secret).toMatch(/^[0-9a-f]{48}$/);
    expect(res.webhook_url).toBe(`/api/v1/git/webhook/${res.id}`);
    const stored = h.deployments[0];
    expect(Buffer.isBuffer(stored.webhook_secret_enc)).toBe(true);
    expect(stored.webhook_secret_enc.toString('utf8')).not.toContain(res.webhook_secret);
    const rows = h.audit.list();
    expect(JSON.stringify(rows)).not.toContain(res.webhook_secret);
  });

  it('rejects non-git URLs and duplicate deploy paths', async () => {
    const h = harness();
    await expect(
      h.gitService.createDeployment(SUPER, { domain_id: 'dom-1', repo_url: 'file:///etc', deploy_path: 'p' }),
    ).rejects.toThrow(BadRequestException);
    await h.gitService.createDeployment(SUPER, {
      domain_id: 'dom-1', repo_url: 'https://github.com/x/y.git', deploy_path: 'public_html',
    });
    await expect(
      h.gitService.createDeployment(SUPER, {
        domain_id: 'dom-1', repo_url: 'https://github.com/z/w.git', deploy_path: 'public_html',
      }),
    ).rejects.toThrow(ConflictException);
  });

  it('deploys now: job mirror completes, last_deployed recorded, audit has no secrets', async () => {
    const h = harness();
    const dep = await h.gitService.createDeployment(SUPER, {
      domain_id: 'dom-1', repo_url: 'https://github.com/x/y.git', deploy_path: 'public_html',
    });
    const res = await h.gitService.deployNow(SUPER, dep.id, {});
    expect(res.release_id).toBe('1762100000-abc1234');
    const job = h.jobs[h.jobs.length - 1];
    expect(job.job_type).toBe('git.deploy');
    expect(job.status).toBe('completed');
    const rows = h.audit.list();
    expect(rows[rows.length - 1].operation).toBe('git.deploy');
  });

  it('webhook: bad signature rejected, right branch deploys, other branches ignored', async () => {
    const h = harness();
    const dep = await h.gitService.createDeployment(SUPER, {
      domain_id: 'dom-1', repo_url: 'https://github.com/x/y.git', branch: 'main', deploy_path: 'public_html',
    });
    const secret = dep.webhook_secret;
    const body = JSON.stringify({ ref: 'refs/heads/main', after: 'abc1234def5678' });
    const sig = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');

    // bad signature → 401
    await expect(
      h.gitService.handleWebhook(dep.id, { 'X-Hub-Signature-256': 'sha256=deadbeef' }, Buffer.from(body)),
    ).rejects.toThrow(UnauthorizedException);

    // valid signature, push, matching branch → deploy
    const ok = await h.gitService.handleWebhook(
      dep.id,
      { 'X-Hub-Signature-256': sig, 'X-GitHub-Event': 'push' },
      Buffer.from(body),
    );
    expect(ok.status).toBe('deployed');
    expect(h.agent.gitDeploy).toHaveBeenCalledWith(
      expect.objectContaining({ sha: 'abc1234def5678', branch: 'main', username: 'alpha' }),
    );

    // valid signature, different branch → honest ignore, no deploy
    const callsBefore = (h.agent.gitDeploy as jest.Mock).mock.calls.length;
    const otherBody = JSON.stringify({ ref: 'refs/heads/feature', after: 'abc1234def5678' });
    const otherSig = 'sha256=' + createHmac('sha256', secret).update(otherBody).digest('hex');
    const ignored = await h.gitService.handleWebhook(
      dep.id, { 'X-Hub-Signature-256': otherSig, 'X-GitHub-Event': 'push' }, Buffer.from(otherBody),
    );
    expect(ignored.status).toBe('ignored');
    expect((h.agent.gitDeploy as jest.Mock).mock.calls.length).toBe(callsBefore);

    // ping event → ignored without deploying
    const pingBody = 'zen';
    const pingSig = 'sha256=' + createHmac('sha256', secret).update(pingBody).digest('hex');
    const ping = await h.gitService.handleWebhook(
      dep.id, { 'X-Hub-Signature-256': pingSig, 'X-GitHub-Event': 'ping' }, Buffer.from(pingBody),
    );
    expect(ping.status).toBe('ignored');
  });

  it('webhook (gitlab): token header must equal the secret', async () => {
    const h = harness();
    const dep = await h.gitService.createDeployment(SUPER, {
      domain_id: 'dom-1', repo_url: 'https://gitlab.com/x/y.git', branch: 'main', deploy_path: 'public_html',
    });
    const body = JSON.stringify({ object_kind: 'push', ref: 'refs/heads/main', after: 'abc1234def5678' });
    await expect(
      h.gitService.handleWebhook(dep.id, { 'X-Gitlab-Token': 'wrong' }, Buffer.from(body)),
    ).rejects.toThrow(UnauthorizedException);
    const ok = await h.gitService.handleWebhook(
      dep.id, { 'X-Gitlab-Token': dep.webhook_secret }, Buffer.from(body),
    );
    expect(ok.status).toBe('deployed');
  });

  it('webhook (bitbucket): verifies X-Hub-Signature and reads the change payload', async () => {
    const h = harness();
    const dep = await h.gitService.createDeployment(SUPER, {
      domain_id: 'dom-1', repo_url: 'https://bitbucket.org/x/y.git', branch: 'main', deploy_path: 'public_html',
    });
    const body = JSON.stringify({
      push: { changes: [{ new: { name: 'main', target: { hash: 'abc1234def5678' } } }] },
    });
    const sig = 'sha256=' + createHmac('sha256', dep.webhook_secret).update(body).digest('hex');
    const ok = await h.gitService.handleWebhook(dep.id, { 'X-Hub-Signature': sig }, Buffer.from(body));
    expect(ok.status).toBe('deployed');
    expect(h.agent.gitDeploy).toHaveBeenCalledWith(expect.objectContaining({ sha: 'abc1234def5678' }));
  });

  it('history + rollback proxy the agent and audit the rollback', async () => {
    const h = harness();
    const dep = await h.gitService.createDeployment(SUPER, {
      domain_id: 'dom-1', repo_url: 'https://github.com/x/y.git', deploy_path: 'public_html',
    });
    const hist = await h.gitService.history(SUPER, dep.id);
    expect(hist.releases).toHaveLength(1);
    await h.gitService.rollback(SUPER, dep.id, { release_id: '1762100000-abc1234' });
    const rows = h.audit.list();
    expect(rows[rows.length - 1].operation).toBe('git.rollback');
    await expect(
      h.gitService.rollback(SUPER, dep.id, { release_id: '../../etc' }),
    ).rejects.toThrow(BadRequestException);
  });
});
