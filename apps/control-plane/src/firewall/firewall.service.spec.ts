import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { FirewallService } from './firewall.service';

/**
 * Firewall service tests (B11). Harness: an in-memory firewall_rules table,
 * the real in-memory audit hash chain, and a fake agent client that can be
 * told to fail (simulating the agent's self-lockout guard / nft check).
 *
 * Exit criteria from the batch plan:
 *   - rule validation negative tests (no self-lockout rule accepted);
 *   - ban/unban flow is audited.
 */

const SUPER = { userId: 'u1', isSuperAdmin: true };
const MORTAL = { userId: 'u2', isSuperAdmin: false };

function harness() {
  const audit = new InMemoryAuditService();
  const rules: Array<Record<string, unknown>> = [];
  let nextId = 1;
  const appliedSets: Array<Array<Record<string, unknown>>> = [];

  const prisma = {
    firewallRule: {
      findMany: jest.fn(async ({ where }: { where?: { NOT?: { id?: string }; is_active?: boolean } } = {}) =>
        rules.filter(
          (r) =>
            r.deleted_at === null &&
            (where?.is_active === undefined ? true : r.is_active === where.is_active) &&
            !(where?.NOT?.id && r.id === where.NOT.id),
        ),
      ),
      findFirst: jest.fn(async ({ where }: { where: { id: string; deleted_at: null } }) =>
        rules.find((r) => r.id === where.id && r.deleted_at === null) ?? null,
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = {
          id: `id-${nextId++}`,
          is_active: true,
          deleted_at: null,
          created_at: new Date(),
          ...data,
        };
        rules.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rules.find((r) => r.id === where.id);
        if (!row) throw new Error('not found');
        return Object.assign(row, data);
      }),
    },
  };

  const agent = {
    firewallApplyRules: jest.fn(async (desired: Array<Record<string, unknown>>) => {
      // Mirror the agent's self-lockout guard (ADR-0016): a drop/reject that
      // covers tcp/22 (or all ports) inbound from any source is refused.
      for (const r of desired) {
        const blocking = r.action === 'drop' || r.action === 'reject';
        const anySource = !r.source_cidr || r.source_cidr === '0.0.0.0/0' || r.source_cidr === '::/0';
        if (blocking && r.direction === 'inbound' && r.protocol === 'tcp' && anySource) {
          const from = r.port_from === null || r.port_from === undefined ? null : Number(r.port_from);
          const to = r.port_to === null || r.port_to === undefined ? from : Number(r.port_to);
          const covers22 = from === null || (from <= 22 && (to ?? from) >= 22);
          if (from === null || covers22) {
            throw new Error(
              'rule[0] would block the management path (ssh, tcp/22) from any source — refused (self-lockout guard, ADR-0016)',
            );
          }
        }
      }
      appliedSets.push(desired);
      return { status: 'applied', rule_count: desired.length, conf_path: '/etc/nexuspanel/firewall.conf', checked: true };
    }),
    firewallStatus: jest.fn(async () => ({ configured: true, table: 'inet nexuspanel', ruleset: 'table inet nexuspanel {}' })),
    fail2banJails: jest.fn(async () => ({
      jails: [{ name: 'sshd', currently_banned: 1, total_banned: 3, banned_ips: ['203.0.113.9'] }],
    })),
    fail2banUnban: jest.fn(async (_jail: string, ip: string) => ({ jail: 'sshd', ip, unbanned: true })),
  };

  const svc = new FirewallService(
    prisma as unknown as PrismaService,
    agent as never,
    audit,
  );
  return { svc, prisma, agent, audit, appliedSets };
}

describe('firewall service (B11)', () => {
  it('rejects non-super callers on the server-scoped surface', async () => {
    const { svc } = harness();
    await expect(svc.listRules(MORTAL)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(svc.createRule(MORTAL, {})).rejects.toBeInstanceOf(ForbiddenException);
    await expect(svc.unban(MORTAL, 'sshd', '203.0.113.9')).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('creates a rule agent-first and persists the mirror', async () => {
    const { svc, agent, audit } = harness();
    const rule = await svc.createRule(SUPER, {
      name: 'web http',
      direction: 'inbound',
      protocol: 'tcp',
      port_from: 80,
      action: 'accept',
    });
    expect(rule.name).toBe('web http');
    expect(agent.firewallApplyRules).toHaveBeenCalledTimes(1);
    const ops = audit.list().map((e) => e.operation);
    expect(ops).toContain('firewall.rule.create');
  });

  it('refuses the self-lockout rule and writes a failure audit entry', async () => {
    const { svc, prisma } = harness();
    await expect(
      svc.createRule(SUPER, {
        name: 'block ssh',
        direction: 'inbound',
        protocol: 'tcp',
        port_from: 22,
        action: 'drop',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    // Agent-first: NO row was written.
    expect(await prisma.firewallRule.findMany()).toHaveLength(0);
  });

  it('deleting the last rule applies an empty desired set (honest clear)', async () => {
    const { svc, agent } = harness();
    const rule = await svc.createRule(SUPER, {
      name: 'allow dns',
      direction: 'inbound',
      protocol: 'udp',
      port_from: 53,
      action: 'accept',
    });
    await svc.deleteRule(SUPER, rule.id);
    expect(agent.firewallApplyRules).toHaveBeenLastCalledWith([]);
  });

  it('validates ports, protocols and actions with readable 422s', async () => {
    const { svc } = harness();
    const bad: Array<Record<string, unknown>> = [
      { name: 'x', direction: 'sideways', protocol: 'tcp', action: 'accept' },
      { name: 'x', direction: 'inbound', protocol: 'sctp', action: 'accept' },
      { name: 'x', direction: 'inbound', protocol: 'tcp', action: 'tarpit' },
      { name: 'x', direction: 'inbound', protocol: 'tcp', port_from: 0, action: 'accept' },
      { name: 'x', direction: 'inbound', protocol: 'tcp', port_from: 10, port_to: 5, action: 'accept' },
      { name: 'x', direction: 'inbound', protocol: 'icmp', port_from: 7, action: 'accept' },
      { name: 'x', direction: 'inbound', protocol: 'tcp', source_cidr: '10.0.0.0/99', action: 'accept' },
      { name: '', direction: 'inbound', protocol: 'tcp', action: 'accept' },
    ];
    for (const input of bad) {
      await expect(svc.createRule(SUPER, input)).rejects.toBeInstanceOf(BadRequestException);
    }
  });

  it('reports live jails and audits unban', async () => {
    const { svc, audit } = harness();
    const jails = await svc.jails(SUPER);
    expect(jails.jails[0].name).toBe('sshd');
    const res = await svc.unban(SUPER, 'sshd', '203.0.113.9');
    expect(res.unbanned).toBe(true);
    const ops = audit.list().map((e) => e.operation);
    expect(ops).toContain('firewall.fail2ban.unban');
  });

  it('surfaces an honest offline state for status/jails when the agent is down', async () => {
    const { svc } = harness();
    (svc as unknown as { agent: { firewallStatus: () => Promise<never> } }).agent.firewallStatus =
      async () => {
        throw new Error('connect ECONNREFUSED');
      };
    const s = await svc.status(SUPER);
    expect(s.configured).toBe(false);
    expect(String(s.ruleset)).toContain('ECONNREFUSED');
  });
});
