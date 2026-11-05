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
 * Per-site WAF (ModSecurity) — API spec §4.15a, ADR-0017, B12.
 *
 * The panel stores one policy row per domain (modsecurity_policies, DDL
 * v2.0) and drives the agent's per-domain nginx include. Every apply is
 * agent-first + health-gated: a failed nginx test rolls the include back
 * and no panel row changes. The applied include bytes are recorded as a
 * config_versions row (target_type `waf_include`) so the config engine's
 * version history and rollback cover WAF changes too.
 *
 * Visibility (C7/§3.2): a caller may only see policies for domains whose
 * hosting account they can see; invisible domains 404.
 */

const MODES = new Set(['off', 'detect', 'block']);
const RULE_ID_RE = /^([0-9]{1,9}|[a-zA-Z0-9_:.-]{1,128})$/;

export interface WafPolicyDto {
  domain_id: string;
  domain: string;
  account_username: string;
  mode: string;
  paranoia_level: number;
  exclusions: string[];
  updated_at: string;
}

@Injectable()
export class WafService {
  private readonly logger = new Logger(WafService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  /** All domains the actor can see, each with its effective policy. */
  async listPolicies(actor?: Actor): Promise<{ data: WafPolicyDto[] }> {
    const domains = await this.prisma.domain.findMany({
      where: { deleted_at: null },
      include: { hosting_account: { select: { username: true } } },
      orderBy: { name: 'asc' },
    });
    const visible: typeof domains = [];
    for (const d of domains) {
      if (await this.canSee(d.hosting_account_id, actor)) visible.push(d);
    }
    const ids = visible.map((d) => d.id);
    const policies = await this.prisma.modsecurityPolicy.findMany({
      where: { domain_id: { in: ids } },
    });
    const byDomain = new Map(policies.map((p) => [p.domain_id, p]));
    return { data: visible.map((d) => this.dto(d, byDomain.get(d.id))) };
  }

  async getPolicy(actor: Actor | undefined, domainId: string): Promise<WafPolicyDto> {
    const d = await this.prisma.domain.findFirst({
      where: { id: domainId, deleted_at: null },
      include: { hosting_account: { select: { username: true } } },
    });
    if (!d || !(await this.canSee(d.hosting_account_id, actor))) {
      throw new NotFoundException('domain not found');
    }
    const policy = await this.prisma.modsecurityPolicy.findFirst({
      where: { domain_id: d.id },
    });
    return this.dto(d, policy ?? undefined);
  }

  async updatePolicy(
    actor: Actor | undefined,
    domainId: string,
    input: { mode?: unknown; paranoia_level?: unknown; exclusions?: unknown },
  ): Promise<WafPolicyDto> {
    const d = await this.prisma.domain.findFirst({
      where: { id: domainId, deleted_at: null },
      include: { hosting_account: { select: { username: true } } },
    });
    if (!d || !(await this.canSee(d.hosting_account_id, actor))) {
      throw new NotFoundException('domain not found');
    }
    const mode = String(input.mode ?? 'off');
    if (!MODES.has(mode)) {
      throw new BadRequestException('mode must be off|detect|block');
    }
    let paranoia = 1;
    if (input.paranoia_level !== undefined && input.paranoia_level !== null && input.paranoia_level !== '') {
      paranoia = Number(input.paranoia_level);
      if (![1, 2].includes(paranoia)) throw new BadRequestException('paranoia_level must be 1 or 2');
    }
    let exclusions: string[] = [];
    if (Array.isArray(input.exclusions)) {
      if (input.exclusions.length > 200) {
        throw new BadRequestException('at most 200 exclusions');
      }
      exclusions = input.exclusions.map((x) => String(x).trim()).filter(Boolean);
      for (const x of exclusions) {
        if (!RULE_ID_RE.test(x)) {
          throw new BadRequestException(`invalid exclusion rule id "${x}"`);
        }
      }
    }

    try {
      await this.agent.wafApplyPolicy(d.name, mode as 'off' | 'detect' | 'block', paranoia, exclusions);
    } catch (e) {
      await this.audit.append({
        operation: 'waf.policy.update',
        parameters: { domain: d.name, mode, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: d.hosting_account_id,
      });
      throw new BadRequestException((e as Error).message);
    }

    const row = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.modsecurityPolicy.findFirst({ where: { domain_id: d.id } });
      const upserted = existing
        ? await tx.modsecurityPolicy.update({
            where: { id: existing.id },
            data: { mode, paranoia_level: paranoia, exclusions },
          })
        : await tx.modsecurityPolicy.create({
            data: {
              domain_id: d.id,
              mode,
              paranoia_level: paranoia,
              exclusions,
              ruleset_version: 'crs-4',
            },
          });
      // Config engine bookkeeping: the applied include bytes, versioned.
      const last = await tx.configVersion.findFirst({
        where: { target_type: 'waf_include', target_id: d.id },
        orderBy: { version: 'desc' },
        select: { version: true },
      });
      const content = this.renderIncludeForRecord(mode, paranoia, exclusions);
      await tx.configVersion.create({
        data: {
          target_type: 'waf_include',
          target_id: d.id,
          version: (last?.version ?? 0) + 1,
          content,
          rendered_by: actor?.userId ?? null,
          is_active: true,
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'waf.policy.update',
        parameters: { domain: d.name, mode, paranoia_level: paranoia, exclusions: exclusions.length },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: d.hosting_account_id,
      });
      return upserted;
    });
    this.logger.log(`WAF ${mode} applied to ${d.name} (health gate passed)`);
    return {
      domain_id: d.id,
      domain: d.name,
      account_username: d.hosting_account.username,
      mode: row.mode,
      paranoia_level: row.paranoia_level,
      exclusions: (row.exclusions as string[]) ?? [],
      updated_at: row.updated_at.toISOString(),
    };
  }

  /** Approximation of the agent's include — for the version record only. */
  private renderIncludeForRecord(mode: string, paranoia: number, exclusions: string[]): string {
    const engine = mode === 'detect' ? 'DetectionOnly' : mode === 'block' ? 'On' : 'Off';
    const lines = [
      `# Managed by NexusPanel (waf.apply_policy) — DO NOT EDIT.`,
      `# Per-site ModSecurity posture (recorded copy)`,
      `# mode: ${mode} (SecRuleEngine ${engine})`,
      `# paranoia_level: ${paranoia}`,
      ...exclusions.map((x) => `SecRuleRemoveById ${x}`),
    ];
    return lines.join('\n') + '\n';
  }

  private dto(
    d: { id: string; name: string; updated_at: Date; hosting_account: { username: string } },
    p?: { mode: string; paranoia_level: number; exclusions: unknown; updated_at: Date },
  ): WafPolicyDto {
    return {
      domain_id: d.id,
      domain: d.name,
      account_username: d.hosting_account.username,
      mode: p?.mode ?? 'off',
      paranoia_level: p?.paranoia_level ?? 1,
      exclusions: ((p?.exclusions as string[] | undefined) ?? []) as string[],
      updated_at: (p?.updated_at ?? d.updated_at).toISOString(),
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
