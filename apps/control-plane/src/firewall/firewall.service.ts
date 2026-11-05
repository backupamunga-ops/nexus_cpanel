import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { Actor } from '../sites/sites.service';

/**
 * Firewall & fail2ban (API spec §4.17, ADR-0016) — server-scoped (C6), B11.
 *
 * The panel owns the registry (firewall_rules, DDL-first) and mirrors what
 * the agent applied:
 *   - every mutation is agent-first — the FULL desired rule set is applied
 *     through one `firewall.apply_rules` reconcile BEFORE any row is written;
 *     a failed apply (including the agent's self-lockout guard) leaves the
 *     registry untouched;
 *   - the fail-closed contract lives in the agent (check → delete → apply);
 *     the panel duplicates the basic field validation for fast, readable 422s
 *     but never weakens the agent's guard;
 *   - fail2ban state is read LIVE from the node (jails + bans) — the panel
 *     never persists ban state, so what the UI shows is what the node does
 *     right now (D-11); unban is the only audited mutation.
 *
 * Server-scoped surface: super admins pass via C6; non-super users need an
 * explicit `firewall:*` grant (none exists yet — P5 review may add one).
 */

const DIRECTIONS = new Set(['inbound', 'outbound']);
const PROTOCOLS = new Set(['tcp', 'udp', 'icmp']);
const ACTIONS = new Set(['accept', 'drop', 'reject']);
const RULE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9 ._:-]{0,63}$/;
const JAIL_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

export interface FirewallRuleDto {
  id: string;
  name: string;
  direction: string;
  protocol: string;
  port_from: number | null;
  port_to: number | null;
  source_cidr: string | null;
  action: string;
  is_active: boolean;
  created_at: string;
}

function isSuper(actor?: Actor): boolean {
  return actor?.isSuperAdmin === true;
}

function requireSuper(actor?: Actor): void {
  if (!isSuper(actor)) {
    // 404-style uniform denial is for resource enumeration; this is a
    // server-scope capability, so a plain forbidden is correct here (§3.1).
    throw new ForbiddenException('server administrator access required');
  }
}

@Injectable()
export class FirewallService {
  private readonly logger = new Logger(FirewallService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  // ---- rules registry -------------------------------------------------------

  async listRules(actor?: Actor): Promise<{ data: FirewallRuleDto[] }> {
    requireSuper(actor);
    const rows = await this.prisma.firewallRule.findMany({
      where: { deleted_at: null },
      orderBy: { created_at: 'asc' },
    });
    return { data: rows.map((r) => this.toDto(r)) };
  }

  async createRule(
    actor: Actor | undefined,
    input: Record<string, unknown>,
  ): Promise<FirewallRuleDto> {
    requireSuper(actor);
    const rule = this.validateRuleInput(input);

    // Agent-first: apply the full desired set including the new rule.
    const existing = await this.prisma.firewallRule.findMany({
      where: { deleted_at: null, is_active: true },
      orderBy: { created_at: 'asc' },
    });
    const desired = [...existing.map(this.fromRow), rule];
    await this.applyDesired(actor, desired, { op: 'firewall.rule.create', name: rule.name });

    const created = await this.prisma.firewallRule.create({
      data: {
        name: rule.name,
        direction: rule.direction,
        protocol: rule.protocol,
        port_from: rule.port_from ?? null,
        port_to: rule.port_to ?? null,
        source_cidr: rule.source_cidr || null,
        action: rule.action,
        is_active: true,
      },
    });
    return this.toDto(created);
  }

  async updateRule(
    actor: Actor | undefined,
    id: string,
    input: Record<string, unknown>,
  ): Promise<FirewallRuleDto> {
    requireSuper(actor);
    const row = await this.prisma.firewallRule.findFirst({ where: { id, deleted_at: null } });
    if (!row) throw new NotFoundException('rule not found');
    const merged = this.validateRuleInput({
      name: input.name ?? row.name,
      direction: input.direction ?? row.direction,
      protocol: input.protocol ?? row.protocol,
      port_from: input.port_from ?? row.port_from,
      port_to: input.port_to ?? row.port_to,
      source_cidr: input.source_cidr ?? row.source_cidr ?? '',
      action: input.action ?? row.action,
    });

    const existing = await this.prisma.firewallRule.findMany({
      where: { deleted_at: null, is_active: true, NOT: { id } },
      orderBy: { created_at: 'asc' },
    });
    const desired = [...existing.map(this.fromRow), merged];
    await this.applyDesired(actor, desired, { op: 'firewall.rule.update', name: merged.name });

    const updated = await this.prisma.firewallRule.update({
      where: { id },
      data: {
        name: merged.name,
        direction: merged.direction,
        protocol: merged.protocol,
        port_from: merged.port_from ?? null,
        port_to: merged.port_to ?? null,
        source_cidr: merged.source_cidr || null,
        action: merged.action,
      },
    });
    return this.toDto(updated);
  }

  async deleteRule(actor: Actor | undefined, id: string): Promise<void> {
    requireSuper(actor);
    const row = await this.prisma.firewallRule.findFirst({ where: { id, deleted_at: null } });
    if (!row) throw new NotFoundException('rule not found');

    const remaining = await this.prisma.firewallRule.findMany({
      where: { deleted_at: null, is_active: true, NOT: { id } },
      orderBy: { created_at: 'asc' },
    });
    await this.applyDesired(actor, remaining.map(this.fromRow), {
      op: 'firewall.rule.delete',
      name: row.name,
    });

    await this.prisma.firewallRule.update({ where: { id }, data: { deleted_at: new Date() } });
  }

  // ---- live state -----------------------------------------------------------

  async status(actor?: Actor) {
    requireSuper(actor);
    try {
      const s = await this.agent.firewallStatus();
      return s;
    } catch (e) {
      // Honest offline state: the panel says the agent is unreachable rather
      // than pretending the firewall is configured (D-11).
      return {
        configured: false,
        table: 'inet nexuspanel',
        ruleset: (e as Error).message,
      };
    }
  }

  async jails(actor?: Actor) {
    requireSuper(actor);
    try {
      return await this.agent.fail2banJails();
    } catch (e) {
      return {
        jails: [],
        note: (e as Error).message,
      };
    }
  }

  async unban(actor: Actor | undefined, jail: string, ip: string) {
    requireSuper(actor);
    if (!JAIL_NAME_RE.test(jail)) throw new BadRequestException('invalid jail name');
    if (!/^[0-9a-fA-F.:]{3,45}$/.test(ip)) throw new BadRequestException('invalid IP address');
    try {
      const res = await this.agent.fail2banUnban(jail, ip);
      await this.audit.append({
        operation: 'firewall.fail2ban.unban',
        parameters: { jail, ip, unbanned: res.unbanned },
        outcome: res.unbanned ? 'success' : 'failure',
        actorUserId: actor?.userId ?? null,
      });
      return res;
    } catch (e) {
      await this.audit.append({
        operation: 'firewall.fail2ban.unban',
        parameters: { jail, ip, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
      });
      throw e;
    }
  }

  // ---- internals -------------------------------------------------------------

  private async applyDesired(
    actor: Actor | undefined,
    desired: Array<{
      name: string;
      direction: string;
      protocol: string;
      port_from: number | null;
      port_to: number | null;
      source_cidr: string;
      action: string;
    }>,
    audit: { op: string; name: string },
  ): Promise<void> {
    try {
      await this.agent.firewallApplyRules(desired);
    } catch (e) {
      await this.audit.append({
        operation: audit.op,
        parameters: { rule: audit.name, rule_count: desired.length, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
      });
      // Surface the agent's message verbatim: the self-lockout guard text is
      // written to be operator-readable (ADR-0016).
      throw new BadRequestException((e as Error).message);
    }
    await this.audit.append({
      operation: audit.op,
      parameters: { rule: audit.name, rule_count: desired.length },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
    });
  }

  private validateRuleInput(input: Record<string, unknown>): {
    name: string;
    direction: string;
    protocol: string;
    port_from: number | null;
    port_to: number | null;
    source_cidr: string;
    action: string;
  } {
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (!RULE_NAME_RE.test(name)) {
      throw new BadRequestException(
        'name must be 1-64 chars of letters, digits, space, dot, dash, colon, underscore',
      );
    }
    const direction = String(input.direction ?? '');
    if (!DIRECTIONS.has(direction)) throw new BadRequestException('direction must be inbound|outbound');
    const protocol = String(input.protocol ?? '');
    if (!PROTOCOLS.has(protocol)) throw new BadRequestException('protocol must be tcp|udp|icmp');
    const action = String(input.action ?? '');
    if (!ACTIONS.has(action)) throw new BadRequestException('action must be accept|drop|reject');

    let portFrom: number | null = null;
    let portTo: number | null = null;
    if (input.port_from !== null && input.port_from !== undefined && input.port_from !== '') {
      portFrom = Number(input.port_from);
      if (!Number.isInteger(portFrom) || portFrom < 1 || portFrom > 65535) {
        throw new BadRequestException('port_from must be an integer 1-65535');
      }
      if (input.port_to !== null && input.port_to !== undefined && input.port_to !== '') {
        portTo = Number(input.port_to);
        if (!Number.isInteger(portTo) || portTo < portFrom || portTo > 65535) {
          throw new BadRequestException('port_to must be an integer >= port_from, <= 65535');
        }
      }
    } else if (input.port_to !== null && input.port_to !== undefined && input.port_to !== '') {
      throw new BadRequestException('port_to without port_from');
    }
    if (protocol === 'icmp' && portFrom !== null) {
      throw new BadRequestException('icmp rules carry no ports');
    }

    let sourceCidr = typeof input.source_cidr === 'string' ? input.source_cidr.trim() : '';
    if (sourceCidr) {
      if (sourceCidr.includes('/')) {
        const [addr, bitsRaw] = sourceCidr.split('/', 2);
        const bits = Number(bitsRaw);
        const isV4 = /^[0-9.]+$/.test(addr);
        if (!isV4 && !addr.includes(':')) throw new BadRequestException(`invalid CIDR "${sourceCidr}"`);
        const maxBits = isV4 ? 32 : 128;
        if (!Number.isInteger(bits) || bits < 0 || bits > maxBits) {
          throw new BadRequestException(`invalid CIDR "${sourceCidr}"`);
        }
      } else if (!/^[0-9a-fA-F.:]{3,45}$/.test(sourceCidr)) {
        throw new BadRequestException(`invalid IP "${sourceCidr}"`);
      }
    }
    return { name, direction, protocol, port_from: portFrom, port_to: portTo, source_cidr: sourceCidr, action };
  }

  private fromRow = (r: {
    name: string;
    direction: string;
    protocol: string;
    port_from: number | null;
    port_to: number | null;
    source_cidr: string | null;
    action: string;
  }) => ({
    name: r.name,
    direction: r.direction,
    protocol: r.protocol,
    port_from: r.port_from,
    port_to: r.port_to,
    source_cidr: r.source_cidr ?? '',
    action: r.action,
  });

  private toDto(r: {
    id: string;
    name: string;
    direction: string;
    protocol: string;
    port_from: number | null;
    port_to: number | null;
    source_cidr: string | null;
    action: string;
    is_active: boolean;
    created_at: Date;
  }): FirewallRuleDto {
    return {
      id: r.id,
      name: r.name,
      direction: r.direction,
      protocol: r.protocol,
      port_from: r.port_from,
      port_to: r.port_to,
      source_cidr: r.source_cidr,
      action: r.action,
      is_active: r.is_active,
      created_at: r.created_at.toISOString(),
    };
  }
}
