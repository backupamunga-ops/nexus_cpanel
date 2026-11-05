import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { DnsService } from './dns.service';

/**
 * DNS zones & records (API spec §4.9, ADR-0012): agent-first provisioning
 * (failed agent call leaves no row), full-set apply semantics, SOA
 * protection, C7 404s, honest DNSSEC handling.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true } as const;
const VIEWER = { userId: 'u-viewer', isSuperAdmin: false } as const;

const ACCOUNT = { id: '01900000-0000-7000-8000-00000000a001', username: 'alice' };

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

/** Generic where-matcher: every where-key must equal the row value. */
function matches(row: Record<string, unknown>, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([k, v]) => {
    if (v !== null && typeof v === 'object' && 'in' in (v as object)) {
      return (v as { in: unknown[] }).in.includes(row[k]);
    }
    return row[k] === v;
  });
}

function harness(opts: { accessRows?: Array<{ user_id: string; hosting_account_id: string }> } = {}) {
  const audit = new InMemoryAuditService();
  const zones: Record<string, unknown>[] = [];
  const records: Record<string, unknown>[] = [];
  const accessRows = opts.accessRows ?? [];

  const prisma = {
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = { ...ACCOUNT, deleted_at: null };
        return row.id === where['id'] ? row : null;
      }),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        accessRows.find((a) => a.user_id === where['user_id'] && a.hosting_account_id === where['hosting_account_id']) ?? null,
      ),
    },
    dnZone: {
      findMany: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) =>
        zones
          .filter((z) => matches(z, where))
          .map((z) => ({
            ...z,
            hosting_account: { username: ACCOUNT.username },
            ...(include?.['dns_records__zone_id']
              ? {
                  dns_records__zone_id: records.filter(
                    (r) => r['zone_id'] === z['id'] && r['deleted_at'] === null,
                  ),
                }
              : {}),
          })),
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = zones.find((z) => matches(z, where));
        return row ? { ...row, hosting_account: { id: ACCOUNT.id, username: ACCOUNT.username } } : null;
      }),
      create: jest.fn(async ({ data, include }: { data: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const row = {
          id: uid(zones.length + 10),
          ...data,
          created_at: new Date(),
          deleted_at: null,
          ...(include?.['dns_records__zone_id']
            ? { hosting_account: { id: ACCOUNT.id, username: ACCOUNT.username }, dns_records__zone_id: [] }
            : {}),
        };
        zones.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = zones.find((z) => z['id'] === where.id)!;
        Object.assign(row, data);
        return row;
      }),
      updateMany: jest.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        for (const z of zones) {
          if (z['id'] === where['id']) Object.assign(z, data);
        }
      }),
      count: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        records.filter((r) => r['zone_id'] === where['zone_id'] && r['deleted_at'] === null).length,
      ),
    },
    dnRecord: {
      findMany: jest.fn(async ({ where, orderBy }: { where: Record<string, unknown>; orderBy?: unknown }) => {
        let rows = records.filter((r) => matches(r, where));
        return [...rows].sort((a, b) => String(a['created_at']).localeCompare(String(b['created_at'])));
      }),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        records.find((r) => matches(r, where)) ?? null,
      ),
      createMany: jest.fn(async ({ data }: { data: Array<Record<string, unknown>> }) => {
        for (const d of data) {
          records.push({
            ...d,
            id: uid(records.length + 100),
            is_active: true,
            created_at: new Date(),
            updated_at: new Date(),
            deleted_at: null,
          });
        }
      }),
      updateMany: jest.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        for (const r of records) {
          if (r['zone_id'] === where['zone_id'] && r['deleted_at'] === null) Object.assign(r, data);
        }
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };

  const agent = {
    dnsCreateZone: jest.fn(async (_zone: string, recs: unknown[]) => ({
      status: 'created',
      zone: _zone,
      kind: 'Native',
      record_count: recs.length + 1,
      soa_seeded: true,
    })),
    dnsDeleteZone: jest.fn(async (_zone: string) => ({ status: 'removed', zone: _zone })),
    dnsApplyRecords: jest.fn(async (_zone: string, recs: unknown[]) => ({
      status: 'applied',
      zone: _zone,
      applied: recs.length,
      removed: 0,
    })),
    dnsGetDnssec: jest.fn(async (zone: string) => ({
      zone,
      enabled: true,
      ds: ['example.com. IN DS 1234 8 2 abc'],
      dnskey: ['example.com. IN DNSKEY 257 3 8 AwEAA'],
      keys: [{ key_type: 'KSK', key_id: '1', detail: 'KSK: id = 1' }],
    })),
    dnsEnableDnssec: jest.fn(async (zone: string) => ({
      status: 'enabled',
      zone,
      ds: ['example.com. IN DS 1234 8 2 abc'],
      dnskey: ['example.com. IN DNSKEY 257 3 8 AwEAA'],
      keys: [{ key_type: 'KSK', key_id: '1', detail: 'KSK: id = 1' }],
    })),
    dnsDisableDnssec: jest.fn(async (zone: string) => ({ status: 'disabled', zone })),
    dnsZoneCheck: jest.fn(async (zone: string) => ({ zone, ok: true, issues: ['Checked 2 records of ' + zone] })),
    dnsAXFRExport: jest.fn(async (zone: string) => ({ zone, content: `${zone}. 3600 IN SOA ns1.${zone}. hostmaster.${zone}. 1 1 1 1 1\n` })),
  };

  const svc = new DnsService(prisma as unknown as PrismaService, agent as never, audit);
  return { svc, agent, audit, zones, records, prisma };
}

async function seedZone(h: ReturnType<typeof harness>, name = 'example.com') {
  return h.svc.createZone(SUPER, {
    account_id: ACCOUNT.id,
    name,
    records: [
      { name: 'www', type: 'A', content: '192.0.2.10', ttl: 3600 },
      { name: '@', type: 'TXT', content: 'hello world' },
    ],
  });
}

describe('dns zones (ADR-0012)', () => {
  it('creates a zone agent-first, mirrors records, audits success', async () => {
    const h = harness();
    const dto = await seedZone(h);
    expect(dto.name).toBe('example.com');
    expect(dto.record_count).toBe(2);
    expect(h.agent.dnsCreateZone).toHaveBeenCalledTimes(1);
    // Mirror stores the wire content for TXT (quoted) and the FQDN name.
    const www = h.records.find((r) => r['type'] === 'A');
    expect(www?.['name']).toBe('www.example.com');
    expect(www?.['content']).toBe('192.0.2.10');
    const txt = h.records.find((r) => r['type'] === 'TXT');
    expect(txt?.['content']).toBe('"hello world"');
    const ops = h.audit.list().filter((e) => e.operation === 'dns.zone.create');
    expect(ops).toHaveLength(1);
    expect(ops[0]['outcome']).toBe('success');
  });

  it('rejects invalid zones and records before any agent call', async () => {
    const h = harness();
    await expect(h.svc.createZone(SUPER, { account_id: ACCOUNT.id, name: 'single-label' })).rejects.toThrow(
      BadRequestException,
    );
    await expect(
      h.svc.createZone(SUPER, {
        account_id: ACCOUNT.id,
        name: 'ok.example.com',
        records: [{ name: 'x', type: 'A', content: 'not-an-ip' }],
      }),
    ).rejects.toThrow('not a valid IPv4');
    await expect(
      h.svc.createZone(SUPER, {
        account_id: ACCOUNT.id,
        name: 'ok.example.com',
        records: [{ name: 'x', type: 'SOA', content: 'ns1.ok.example.com.' }],
      }),
    ).rejects.toThrow('SOA');
    await expect(
      h.svc.createZone(SUPER, {
        account_id: ACCOUNT.id,
        name: 'ok.example.com',
        records: [{ name: '@', type: 'CNAME', content: 'elsewhere.example' }],
      }),
    ).rejects.toThrow('CNAME at the zone apex');
    await expect(
      h.svc.createZone(SUPER, {
        account_id: ACCOUNT.id,
        name: 'ok.example.com',
        records: [{ name: 'x', type: 'MX', content: 'mail.example.com' }],
      }),
    ).rejects.toThrow('MX records require a priority');
    expect(h.agent.dnsCreateZone).not.toHaveBeenCalled();
  });

  it('conflicts on a duplicated zone and rejects out-of-zone absolute names', async () => {
    const h = harness();
    await seedZone(h);
    await expect(h.svc.createZone(SUPER, { account_id: ACCOUNT.id, name: 'example.com' })).rejects.toThrow(
      ConflictException,
    );
    await expect(
      h.svc.addRecord(SUPER, (await h.zones[0] as { id: string }).id, {
        name: 'other.org.',
        type: 'A',
        content: '192.0.2.1',
      }),
    ).rejects.toThrow('outside the zone');
  });

  it('leaves no row when the agent fails and audits the failure', async () => {
    const h = harness();
    h.agent.dnsCreateZone.mockRejectedValueOnce(new Error('PowerDNS API unreachable'));
    await expect(h.svc.createZone(SUPER, { account_id: ACCOUNT.id, name: 'doomed.example.com' })).rejects.toThrow(
      'PowerDNS API unreachable',
    );
    expect(h.zones).toHaveLength(0);
    const ops = h.audit.list().filter((e) => e.operation === 'dns.zone.create');
    expect(ops[0]['outcome']).toBe('failure');
  });

  it('adds, updates and deletes records through one full-set agent diff', async () => {
    const h = harness();
    const zone = await seedZone(h);

    const added = await h.svc.addRecord(SUPER, zone.id, {
      name: 'mail',
      type: 'MX',
      content: 'mail.example.com',
      priority: 10,
    });
    // Mirror (and PowerDNS) hold the wire content: priority composed for MX.
    expect(added.content).toBe('10 mail.example.com');
    // The agent saw the full set (2 originals + the new one) with composed wire content.
    const applyCalls = h.agent.dnsApplyRecords.mock.calls as unknown as Array<[string, Array<Record<string, unknown>>]>;
    expect(applyCalls).toHaveLength(1);
    expect(applyCalls[0]![1]).toHaveLength(3);
    expect(applyCalls[0]![1].find((r) => r['type'] === 'MX')).toMatchObject({ wire: '10 mail.example.com' });

    const updated = await h.svc.updateRecord(SUPER, zone.id, added.id, {
      name: 'mail',
      type: 'MX',
      content: 'mail2.example.com',
      priority: 20,
    });
    expect(updated.content).toBe('20 mail2.example.com');

    await h.svc.deleteRecord(SUPER, zone.id, updated.id);
    const remaining = h.records.filter((r) => r['deleted_at'] === null);
    expect(remaining).toHaveLength(2);
    const ops = h.audit.list().filter((e) => e.operation.startsWith('dns.record.'));
    expect(ops.map((o) => o['outcome'])).toEqual(['success', 'success', 'success']);
  });

  it('record failures keep the mirror untouched and audit loudly', async () => {
    const h = harness();
    const zone = await seedZone(h);
    h.agent.dnsApplyRecords.mockRejectedValueOnce(new Error('agent rejected dns.apply_records'));
    await expect(
      h.svc.addRecord(SUPER, zone.id, { name: 'x', type: 'A', content: '192.0.2.5' }),
    ).rejects.toThrow('agent rejected');
    // Original mirror rows still live.
    expect(h.records.filter((r) => r['deleted_at'] === null)).toHaveLength(2);
    const ops = h.audit.list().filter((e) => e.operation === 'dns.record.create');
    expect(ops[0]['outcome']).toBe('failure');
  });

  it('scopes zones to the account and 404s invisible resources (C7)', async () => {
    const h = harness({ accessRows: [] });
    const zone = await seedZone(h);
    const out = await h.svc.listZones(SUPER, ACCOUNT.id);
    expect(out.data).toHaveLength(1);
    await expect(h.svc.listZones(VIEWER, ACCOUNT.id)).rejects.toThrow(NotFoundException);
    await expect(h.svc.getZone(VIEWER, zone.id)).rejects.toThrow(NotFoundException);
  });

  it('deletes the zone agent-first then soft-deletes zone + records', async () => {
    const h = harness();
    const zone = await seedZone(h);
    await h.svc.deleteZone(SUPER, zone.id);
    expect(h.agent.dnsDeleteZone).toHaveBeenCalledWith('example.com');
    expect(h.zones[0]!['deleted_at']).not.toBeNull();
    expect(h.records.every((r) => r['deleted_at'] !== null)).toBe(true);

    h.agent.dnsDeleteZone.mockRejectedValueOnce(new Error('agent down'));
    const doomed = await seedZone(h, 'doomed.example.com');
    await expect(h.svc.deleteZone(SUPER, doomed.id)).rejects.toThrow('agent down');
    expect(h.zones.find((z) => z['name'] === 'doomed.example.com')?.['deleted_at']).toBeNull();
  });
});

describe('dns dnssec + checks (ADR-0012)', () => {
  it('reads live DNSSEC state from the node and enables/disables honestly', async () => {
    const h = harness();
    const zone = await seedZone(h);
    const state = await h.svc.getDnssec(SUPER, zone.id);
    expect(state.enabled).toBe(true);
    expect(state.ds).toHaveLength(1);

    const enabled = await h.svc.enableDnssec(SUPER, zone.id);
    expect(enabled.status).toBe('enabled');
    expect(h.zones[0]!['dnssec_enabled']).toBe(true);
    await h.svc.disableDnssec(SUPER, zone.id);
    expect(h.zones[0]!['dnssec_enabled']).toBe(false);
    const ops = h.audit.list().filter((e) => e.operation.startsWith('dns.dnssec.'));
    expect(ops.map((o) => o['outcome'])).toEqual(['success', 'success']);
  });

  it('keeps the dnssec_enabled flag false when the node fails to secure', async () => {
    const h = harness();
    const zone = await seedZone(h);
    h.agent.dnsEnableDnssec.mockRejectedValueOnce(new Error('pdnsutil secure-zone failed: no keys'));
    await expect(h.svc.enableDnssec(SUPER, zone.id)).rejects.toThrow('secure-zone failed');
    expect(h.zones[0]!['dnssec_enabled']).toBe(false);
    const ops = h.audit.list().filter((e) => e.operation === 'dns.dnssec.enable');
    expect(ops[0]['outcome']).toBe('failure');
  });

  it('runs the node zone-check and rejects bad resolver lists for propagation', async () => {
    const h = harness();
    const zone = await seedZone(h);
    const check = await h.svc.zoneCheck(SUPER, zone.id);
    expect(check.ok).toBe(true);
    await expect(h.svc.checkPropagation(SUPER, zone.id, ['not-an-ip'])).rejects.toThrow(BadRequestException);
    // Valid call: stdlib resolver will fail fast in tests (no network required
    // for the error path) — the result shape must still be honest.
    const propagation = await h.svc.checkPropagation(SUPER, zone.id, ['127.0.0.1']);
    expect(propagation.resolvers).toEqual(['127.0.0.1']);
    expect(Array.isArray(propagation.results)).toBe(true);
  });
});
