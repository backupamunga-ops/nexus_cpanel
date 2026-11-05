import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { getSecretBox } from '../common/secretbox';
import { Actor } from '../sites/sites.service';

/**
 * Git push-to-deploy (API spec §4.7 git routes, ADR-0019, B14).
 *
 * The panel owns the git_deployments registry (DDL-first); the node does
 * the work through the agent: every deploy clones into a timestamped
 * release directory and the deploy path is an atomic symlink swap — the
 * releases dir IS the deploy history, rollback re-points the symlink.
 *
 * Push triggers: one receiver route (`POST /git/webhook/{id}`, @Public)
 * verifies GitHub (X-Hub-Signature-256), GitLab (X-Gitlab-Token) and
 * Bitbucket (X-Hub-Signature) against the per-deployment secret, which is
 * generated here, shown ONCE, and stored SecretBox-encrypted
 * (webhook_secret_enc, ADR-0009). Non-push events and other branches are
 * answered honestly with { ignored: reason } and never deploy.
 */

const GIT_REPO_RE =
  /^(https:\/\/[^\s@/]+\/[^\s@]+\/[^\s@]+\.git|git@[a-zA-Z0-9.-]+:[^\s/]+\/[^\s]+\.git)$/;
const GIT_BRANCH_RE = /^[a-zA-Z0-9._/-]{1,128}$/;
const APP_PATH_RE = /^[\w][\w./ -]{0,255}$/;
const RELEASE_RE = /^([0-9]{10,12})-([0-9a-f]{7,40})(?:-([0-9]+))?$/;
const SHA_RE = /^[0-9a-f]{7,40}$/;

export interface GitDeploymentDto {
  id: string;
  domain_id: string;
  domain: string;
  account_username: string;
  provider: string;
  repo_url: string;
  branch: string;
  deploy_path: string;
  last_deployed_at: string | null;
  last_deployed_sha: string | null;
  webhook_url: string | null;
  created_at: string;
}

export interface GitDeployEventDto extends GitDeploymentDto {
  release_id?: string;
  sha?: string;
  log?: string;
}

type DeployTrigger = 'manual' | 'webhook';

@Injectable()
export class GitService {
  private readonly logger = new Logger(GitService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  async listDeployments(actor?: Actor): Promise<{ data: GitDeploymentDto[] }> {
    const rows = await this.prisma.gitDeployment.findMany({
      where: { deleted_at: null },
      orderBy: { created_at: 'desc' },
      include: {
        domain: { include: { hosting_account: { select: { id: true, username: true } } } },
      },
    });
    const visible = [] as typeof rows;
    for (const r of rows) {
      if (await this.canSee(r.domain.hosting_account.id, actor)) visible.push(r);
    }
    return { data: visible.map((r) => this.toDto(r)) };
  }

  /** Registers a deployment; the webhook secret is returned ONCE. */
  async createDeployment(
    actor: Actor | undefined,
    input: { domain_id?: unknown; repo_url?: unknown; branch?: unknown; deploy_path?: unknown },
  ): Promise<GitDeploymentDto & { webhook_secret: string }> {
    if (typeof input.domain_id !== 'string' || !input.domain_id) {
      throw new BadRequestException('domain_id is required');
    }
    const domain = await this.prisma.domain.findFirst({
      where: { id: input.domain_id, deleted_at: null, is_active: true },
      include: { hosting_account: { select: { id: true, username: true } } },
    });
    if (!domain) throw new NotFoundException('domain not found');
    if (!(await this.canSee(domain.hosting_account.id, actor))) {
      throw new NotFoundException('domain not found');
    }

    const repoUrl = typeof input.repo_url === 'string' ? input.repo_url.trim() : '';
    if (!GIT_REPO_RE.test(repoUrl)) {
      throw new BadRequestException('repo_url must be an https or ssh git URL');
    }
    const branch = typeof input.branch === 'string' && input.branch.trim() !== '' ? input.branch.trim() : 'main';
    if (!GIT_BRANCH_RE.test(branch)) throw new BadRequestException('invalid branch');

    const homedir = (await this.prisma.hostingAccount.findUnique({
      where: { id: domain.hosting_account.id },
      select: { homedir: true },
    }))!.homedir;
    const docrootRel = domain.document_root.startsWith(`${homedir}/`)
      ? domain.document_root.slice(homedir.length + 1)
      : '';
    const deployPath =
      typeof input.deploy_path === 'string' && input.deploy_path.trim() !== ''
        ? input.deploy_path.trim().replace(/^\/+|\/+$/g, '')
        : docrootRel;
    if (!deployPath || deployPath.includes('..') || !APP_PATH_RE.test(deployPath)) {
      throw new BadRequestException(
        'deploy_path must be a directory relative to the account home (it becomes a release symlink)',
      );
    }
    const dup = await this.prisma.gitDeployment.findFirst({
      where: { domain_id: domain.id, deploy_path: deployPath, deleted_at: null },
      select: { id: true },
    });
    if (dup) throw new ConflictException('this domain already has a git deployment at that path');

    const webhookSecret = randomBytes(24).toString('hex');
    const row = await this.prisma.gitDeployment.create({
      data: {
        domain_id: domain.id,
        provider: providerOf(repoUrl),
        repo_url: repoUrl,
        branch,
        deploy_path: deployPath,
        webhook_secret_enc: Buffer.from(getSecretBox().encrypt(webhookSecret), 'utf8'),
      },
    });
    await this.audit.append({
      operation: 'git.deployment.create',
      parameters: {
        deployment_id: row.id, domain: domain.name, repo: repoUrl,
        branch, deploy_path: deployPath, provider: row.provider,
        // ADR-0015 discipline: fingerprint, never the material.
        webhook_secret_fingerprint: fingerprint(webhookSecret),
      },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: domain.hosting_account.id,
    });
    return { ...this.toDto({ ...row, domain }), webhook_secret: webhookSecret };
  }

  /** Manual deploy from the panel: branch head (or pinned sha), audited. */
  async deployNow(
    actor: Actor | undefined,
    deploymentId: string,
    input: { sha?: unknown } = {},
  ): Promise<GitDeployEventDto> {
    const { row, domain, account } = await this.requireVisibleDeployment(actor, deploymentId);
    const sha = typeof input.sha === 'string' && input.sha.trim() !== '' ? input.sha.trim() : '';
    if (sha && !SHA_RE.test(sha)) throw new BadRequestException('invalid sha');
    return this.runDeploy(row, domain, account, sha, 'manual', actor?.userId ?? null);
  }

  /** Agent-side release history (the releases dir IS the history). */
  async history(
    actor: Actor | undefined,
    deploymentId: string,
  ): Promise<{
    releases: Array<{ release_id: string; sha: string; created_at: string; active: boolean }>;
    current: string;
    path: string;
  }> {
    const { row, domain, account } = await this.requireVisibleDeployment(actor, deploymentId);
    return this.agent.gitDeployHistory({
      username: account.username,
      domain: domain.name,
      deploy_path: row.deploy_path,
    });
  }

  /** Re-points the deploy symlink at an older release (audited). */
  async rollback(
    actor: Actor | undefined,
    deploymentId: string,
    input: { release_id?: unknown },
  ): Promise<{ status: string; release_id: string }> {
    const { row, domain, account } = await this.requireVisibleDeployment(actor, deploymentId);
    const releaseId = typeof input.release_id === 'string' ? input.release_id.trim() : '';
    if (!RELEASE_RE.test(releaseId)) throw new BadRequestException('invalid release_id');
    const res = await this.agent.gitRollback({
      username: account.username,
      domain: domain.name,
      deploy_path: row.deploy_path,
      release_id: releaseId,
    });
    await this.audit.append({
      operation: 'git.rollback',
      parameters: { deployment_id: row.id, domain: domain.name, release: releaseId },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: account.id,
    });
    return res;
  }

  /**
   * Webhook receiver — @Public, authenticated by signature only. Verify →
   * filter (push events on the configured branch) → deploy. Never 500s on
   * non-push pings: they are acknowledged with an honest `ignored`.
   */
  async handleWebhook(
    deploymentId: string,
    headers: Record<string, string | string[] | undefined>,
    rawBody: Buffer,
  ): Promise<{ status: string; release_id?: string; sha?: string; reason?: string }> {
    const row = await this.prisma.gitDeployment.findFirst({
      where: { id: deploymentId, deleted_at: null },
      include: {
        domain: { include: { hosting_account: { select: { id: true, username: true } } } },
      },
    });
    if (!row) throw new NotFoundException('deployment not found');
    if (!row.webhook_secret_enc) {
      throw new ConflictException('deployment has no webhook secret configured');
    }
    const secret = getSecretBox().decrypt(Buffer.from(row.webhook_secret_enc).toString('utf8'));
    const h = (name: string): string => {
      const v = headers[name] ?? headers[name.toLowerCase()];
      return Array.isArray(v) ? (v[0] ?? '') : (v ?? '');
    };

    const provider = row.provider;
    const body = safeJson(rawBody);

    if (provider === 'gitlab') {
      const token = h('X-Gitlab-Token');
      if (!token || !safeEqual(token, secret)) throw new UnauthorizedException('bad signature');
      if (body.object_kind !== 'push') return { status: 'ignored', reason: `event ${body.object_kind} does not deploy` };
    } else {
      // GitHub: X-Hub-Signature-256; Bitbucket: X-Hub-Signature (sha256=).
      const headerName = provider === 'bitbucket' ? 'X-Hub-Signature' : 'X-Hub-Signature-256';
      const sig = h(headerName);
      const expected = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');
      if (!sig || !safeEqual(sig, expected)) throw new UnauthorizedException('bad signature');
      const event = h('X-GitHub-Event');
      if (provider === 'github' && event && event !== 'push') {
        return { status: 'ignored', reason: `${event} events do not deploy` };
      }
    }

    // Branch + sha per provider payload shape.
    let ref = String(body.ref ?? '');
    let sha = String(body.after ?? '');
    if (provider === 'bitbucket') {
      const change = body.push?.changes?.[0];
      ref = `refs/heads/${String(change?.new?.name ?? '')}`;
      sha = String(change?.new?.target?.hash ?? '');
    }
    const want = `refs/heads/${row.branch}`;
    if (ref !== want) {
      return { status: 'ignored', reason: `branch ${ref || '(none)'} is not the deployed branch` };
    }
    if (sha && !SHA_RE.test(sha)) sha = '';

    const res = await this.runDeploy(row, row.domain, row.domain.hosting_account, sha || undefined, 'webhook', null);
    return { status: 'deployed', release_id: res.release_id, sha: res.sha };
  }

  /** Shared deploy executor: job mirror → agent → registry + audit. */
  private async runDeploy(
    row: {
      id: string; repo_url: string; branch: string; deploy_path: string; domain_id: string;
      provider: string; created_at: Date;
      last_deployed_at: Date | null; last_deployed_sha: string | null;
      domain: { id: string; name: string; hosting_account_id: string; hosting_account: { id: string; username: string } };
    },
    domain: { id: string; name: string },
    account: { id: string; username: string },
    sha: string | undefined,
    trigger: DeployTrigger,
    actorUserId: string | null,
  ): Promise<GitDeployEventDto> {
    const jobRow = await this.prisma.jobMetadata.create({
      data: {
        bullmq_job_id: `deploy_${randomBytes(8).toString('hex')}`,
        queue_name: 'git',
        job_type: 'git.deploy',
        status: 'active',
        payload: {
          deployment_id: row.id, domain: domain.name, repo: row.repo_url,
          branch: row.branch, sha: sha ?? null, source: trigger,
        } as object,
        attempts: 1,
      },
    });
    try {
      const res = await this.agent.gitDeploy({
        username: account.username,
        domain: domain.name,
        repo_url: row.repo_url,
        branch: row.branch,
        sha,
        deploy_path: row.deploy_path,
      });
      await this.prisma.gitDeployment.update({
        where: { id: row.id },
        data: { last_deployed_at: new Date(), last_deployed_sha: res.sha },
      });
      await this.prisma.jobMetadata.update({
        where: { id: jobRow.id },
        data: {
          status: 'completed', progress: 100,
          result: { release_id: res.release_id, sha: res.sha, log: res.log.slice(-4000) } as object,
          completed_at: new Date(),
        },
      });
      await this.audit.append({
        operation: 'git.deploy',
        parameters: {
          deployment_id: row.id, domain: domain.name, repo: row.repo_url,
          branch: row.branch, sha: res.sha, release: res.release_id, source: trigger,
        },
        outcome: 'success',
        actorUserId,
        hostingAccountId: account.id,
      });
      return {
        ...this.toDto({
          ...row,
          last_deployed_at: new Date(),
          last_deployed_sha: res.sha,
        }),
        release_id: res.release_id,
        sha: res.sha,
        log: res.log,
      };
    } catch (e) {
      const msg = (e as Error).message;
      await this.prisma.jobMetadata.update({
        where: { id: jobRow.id },
        data: { status: 'failed', result: { error: msg } as object, completed_at: new Date() },
      }).catch(() => undefined);
      await this.audit.append({
        operation: 'git.deploy',
        parameters: {
          deployment_id: row.id, domain: domain.name, branch: row.branch,
          sha: sha ?? null, source: trigger, error: msg,
        },
        outcome: 'failure',
        actorUserId,
        hostingAccountId: account.id,
      });
      throw e;
    }
  }

  private toDto(r: {
    id: string;
    domain_id: string;
    domain: { name: string; hosting_account: { username: string } };
    provider: string;
    repo_url: string;
    branch: string;
    deploy_path: string;
    last_deployed_at: Date | null;
    last_deployed_sha: string | null;
    created_at: Date;
  }): GitDeploymentDto {
    return {
      id: r.id,
      domain_id: r.domain_id,
      domain: r.domain.name,
      account_username: r.domain.hosting_account.username,
      provider: r.provider,
      repo_url: r.repo_url,
      branch: r.branch,
      deploy_path: r.deploy_path,
      last_deployed_at: r.last_deployed_at?.toISOString() ?? null,
      last_deployed_sha: r.last_deployed_sha,
      webhook_url: `/api/v1/git/webhook/${r.id}`,
      created_at: r.created_at.toISOString(),
    };
  }

  private async requireVisibleDeployment(
    actor: Actor | undefined,
    deploymentId: string,
  ): Promise<{
    row: {
      id: string; repo_url: string; branch: string; deploy_path: string; domain_id: string;
      provider: string; created_at: Date; webhook_secret_enc: Buffer | null;
      last_deployed_at: Date | null; last_deployed_sha: string | null;
      domain: {
        id: string; name: string; hosting_account_id: string;
        hosting_account: { id: string; username: string };
      };
    };
    domain: { id: string; name: string };
    account: { id: string; username: string };
  }> {
    const row = await this.prisma.gitDeployment.findFirst({
      where: { id: deploymentId, deleted_at: null },
      include: {
        domain: { include: { hosting_account: { select: { id: true, username: true } } } },
      },
    });
    if (!row) throw new NotFoundException('deployment not found');
    if (!(await this.canSee(row.domain.hosting_account.id, actor))) {
      throw new NotFoundException('deployment not found');
    }
    // The prisma row carries the full domain include; the narrowed shape is
    // what every caller needs (bytea arrives as Uint8Array — Buffer compatible).
    return {
      row: row as unknown as {
        id: string; repo_url: string; branch: string; deploy_path: string; domain_id: string;
        provider: string; created_at: Date; webhook_secret_enc: Buffer | null;
        last_deployed_at: Date | null; last_deployed_sha: string | null;
        domain: {
          id: string; name: string; hosting_account_id: string;
          hosting_account: { id: string; username: string };
        };
      },
      domain: { id: row.domain.id, name: row.domain.name },
      account: row.domain.hosting_account,
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

function providerOf(repoUrl: string): string {
  if (repoUrl.includes('github.com')) return 'github';
  if (repoUrl.includes('gitlab.com')) return 'gitlab';
  if (repoUrl.includes('bitbucket.org')) return 'bitbucket';
  return 'custom';
}

function safeJson(buf: Buffer): Record<string, any> {
  try {
    const v = JSON.parse(buf.toString('utf8'));
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    // Still burn a comparison to keep timing flat, then refuse.
    createHmac('sha256', 'x').update(ab).digest();
    return false;
  }
  return timingSafeEqual(ab, bb);
}

function fingerprint(secret: string): string {
  return createHmac('sha256', 'nexuspanel:fingerprint').update(secret).digest('hex').slice(0, 16);
}
