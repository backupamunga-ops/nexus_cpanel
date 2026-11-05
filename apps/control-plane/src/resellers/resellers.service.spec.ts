import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import {
  ResellersService,
  resellerMaxDepth,
  validateBranding,
  validateCustomDomain,
} from './resellers.service';

/**
 * Resellers CRUD (API spec §4.6): nesting with the Decision-3 depth cap,
 * fail-closed branding validation, custom-domain lifecycle (ADR-0003) and
 * soft-delete with child refusal. The prisma seam is a plain in-memory
 * table; the audit seam is the real in-memory chain.
 */

interface Row {
  [key: string]: unknown;
}

/** Minimal where-engine covering the filters this service issues. */
function matches(row: Row, where: Row): boolean {
  for (const [key, cond] of Object.entries(where)) {
    if (cond === null) {
      if (row[key] !== null && row[key] !== undefined) return false;
      continue;
    }
    if (typeof cond === 'object' && !Array.isArray(cond) && !(cond instanceof Date)) {
      for (const [op, val] of Object.entries(cond as Row)) {
        if (op === 'not' && row[key] === val) return false;
        if (op === 'in' && !(val as unknown[]).includes(row[key])) return false;
      }
      continue;
    }
    if (row[key] !== cond) return false;
  }
  return true;
}

let seq = 0;
function uuid(): string {
  seq += 1;
  return `019a0000-0000-7000-8000-${String(seq).padStart(12, '0')}`;
}

function harness(
  accounts: Array<{ id: string; username: string; status?: string }> = [],
  resellers: Array<Record<string, unknown>> = [],
) {
  const audit = new InMemoryAuditService();
  const resellerTable: Row[] = resellers.map((r, i) => ({
    id: uuid(),
    hosting_account_id: 'unlinked',
    parent_reseller_id: null,
    depth: 1,
    branding: {},
    custom_domain: null,
    custom_domain_status: null,
    deleted_at: null,
    created_at: new Date(Date.now() + i * 1000),
    updated_at: new Date(),
    ...r,
  }));
  const accountTable: Row[] = accounts.map((a) => ({
    id: a.id,
    username: a.username,
    status: a.status ?? 'active',
    deleted_at: null,
  }));

  const attach = (row: Row): Row => {
    const account = accountTable.find((a) => a.id === row['hosting_account_id']);
    return {
      ...row,
      // Mirror the service's include projection: id, username, status only.
      hosting_account: account
        ? { id: account.id, username: account.username, status: account.status }
        : null,
    };
  };

  const prisma = {
    hostingAccount: {
      findFirst: jest.fn(async (args: { where: Row }) => {
        const found = accountTable.filter((a) => matches(a, args.where))[0];
        // Mirror the service's select projection: id, username, status.
        return found ? { id: found.id, username: found.username, status: found.status } : null;
      }),
    },
    reseller: {
      findMany: jest.fn(
        async (args: { where?: Row; orderBy?: Record<string, string>; take?: number } = {}) => {
          let rows = resellerTable.filter((r) => matches(r, args.where ?? {})).map(attach);
          if (args.orderBy?.['created_at'] === 'asc') {
            rows = rows.sort(
              (a, b) => (a.created_at as Date).getTime() - (b.created_at as Date).getTime(),
            );
          }
          return args.take ? rows.slice(0, args.take) : rows;
        },
      ),
      findFirst: jest.fn(async (args: { where: Row }) => {
        const found = resellerTable.filter((r) => matches(r, args.where))[0];
        return found ? attach(found) : null;
      }),
      create: jest.fn(async ({ data }: { data: Row }) => {
        const row: Row = {
          id: uuid(),
          branding: {},
          custom_domain: null,
          custom_domain_status: null,
          deleted_at: null,
          created_at: new Date(),
          updated_at: new Date(),
          ...data,
        };
        resellerTable.push(row);
        return attach(row);
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Row }) => {
        const row = resellerTable.find((r) => r['id'] === where['id']);
        if (!row) throw new Error('reseller row missing in harness');
        Object.assign(row, data);
        return attach(row);
      }),
      count: jest.fn(async (args: { where: Row }) =>
        resellerTable.filter((r) => matches(r, args.where)).length,
      ),
    },
  };
  const svc = new ResellersService(prisma as unknown as PrismaService, audit);
  return { svc, prisma, audit, resellerTable, accountTable };
}

const ACCOUNT_A = '01990000-0000-7000-8000-00000000000a';
const ACCOUNT_B = '01990000-0000-7000-8000-00000000000b';
const ACCOUNT_C = '01990000-0000-7000-8000-00000000000c';
const ACCOUNT_D = '01990000-0000-7000-8000-00000000000d';
const ACCOUNT_E = '01990000-0000-7000-8000-00000000000e';
const ADMIN = '01900000-0000-7000-8000-000000000001';

/** Saves/restores RESELLER_MAX_DEPTH around tests that touch the policy knob. */
function depthEnvHooks() {
  const original = process.env['RESELLER_MAX_DEPTH'];
  afterEach(() => {
    if (original === undefined) delete process.env['RESELLER_MAX_DEPTH'];
    else process.env['RESELLER_MAX_DEPTH'] = original;
  });
}

describe('nesting depth policy (resellers.service)', () => {
  depthEnvHooks();

  it('defaults the cap to 2 levels (Decision 3)', () => {
    delete process.env['RESELLER_MAX_DEPTH'];
    expect(resellerMaxDepth()).toBe(2);
  });

  it('server admins can raise the cap — no code ceiling', () => {
    process.env['RESELLER_MAX_DEPTH'] = '5';
    expect(resellerMaxDepth()).toBe(5);
  });

  it('falls back to 2 on nonsense values', () => {
    process.env['RESELLER_MAX_DEPTH'] = 'zero';
    expect(resellerMaxDepth()).toBe(2);
    process.env['RESELLER_MAX_DEPTH'] = '0';
    expect(resellerMaxDepth()).toBe(2);
  });
});

describe('reseller create (§4.6 POST /resellers)', () => {
  depthEnvHooks();

  it('grants reseller capability on an existing live account (depth 1)', async () => {
    const { svc, audit } = harness([{ id: ACCOUNT_A, username: 'brandco' }]);
    const dto = await svc.create({ hosting_account_id: ACCOUNT_A }, ADMIN);
    expect(dto.depth).toBe(1);
    expect(dto.parent_reseller_id).toBeNull();
    expect(dto.hosting_account).toEqual({ id: ACCOUNT_A, username: 'brandco', status: 'active' });
    expect(audit.list().at(-1)?.operation).toBe('reseller.create');
  });

  it('404s an unknown hosting account (uniform, no enumeration)', async () => {
    const { svc } = harness([]);
    await expect(svc.create({ hosting_account_id: ACCOUNT_A }, ADMIN)).rejects.toThrow(NotFoundException);
  });

  it('409s when the account already carries a live reseller row', async () => {
    const { svc } = harness([{ id: ACCOUNT_A, username: 'brandco' }], [
      { hosting_account_id: ACCOUNT_A },
    ]);
    await expect(svc.create({ hosting_account_id: ACCOUNT_A }, ADMIN)).rejects.toThrow(ConflictException);
  });

  it('nests under a parent reseller with depth = parent + 1', async () => {
    const { svc, audit } = harness(
      [
        { id: ACCOUNT_A, username: 'brandco' },
        { id: ACCOUNT_B, username: 'brandco-sub' },
      ],
      [{ hosting_account_id: ACCOUNT_A, depth: 1 }],
    );
    const parent = (await svc.list()).data[0];
    const child = await svc.create(
      { hosting_account_id: ACCOUNT_B, parent_reseller_id: parent.id },
      ADMIN,
    );
    expect(child.depth).toBe(2);
    expect(child.parent_reseller_id).toBe(parent.id);
    expect(audit.list().at(-1)?.parameters).toMatchObject({ depth: 2 });
  });

  it('rejects nesting beyond the configured cap (RESELLER_MAX_DEPTH)', async () => {
    process.env['RESELLER_MAX_DEPTH'] = '2';
    const { svc } = harness(
      [
        { id: ACCOUNT_B, username: 'sub' },
        { id: ACCOUNT_C, username: 'subsub' },
      ],
      [{ hosting_account_id: ACCOUNT_A, depth: 2 }],
    );
    const parent = (await svc.list()).data[0];
    await expect(
      svc.create({ hosting_account_id: ACCOUNT_B, parent_reseller_id: parent.id }, ADMIN),
    ).rejects.toThrow(BadRequestException);
  });

  it('400s a malformed hosting_account_id', async () => {
    const { svc } = harness();
    await expect(svc.create({ hosting_account_id: 'not-a-uuid' }, ADMIN)).rejects.toThrow(
      BadRequestException,
    );
  });
});

describe('reseller re-parent (§4.6 PATCH /resellers/{id})', () => {
  depthEnvHooks();

  it('moves a subtree: node and descendants shift together', async () => {
    process.env['RESELLER_MAX_DEPTH'] = '5';
    // A(d1) ← B(d2) ← C(d3); moving A under top-level D shifts all: A→2, B→3, C→4.
    const h = harness(
      [
        { id: ACCOUNT_A, username: 'a' },
        { id: ACCOUNT_B, username: 'b' },
        { id: ACCOUNT_C, username: 'c' },
        { id: ACCOUNT_D, username: 'd' },
      ],
      [
        { hosting_account_id: ACCOUNT_A, depth: 1 },
        { hosting_account_id: ACCOUNT_B, depth: 2 },
        { hosting_account_id: ACCOUNT_C, depth: 3 },
        { hosting_account_id: ACCOUNT_D, depth: 1 },
      ],
    );
    const rows = (await h.svc.list()).data;
    const byUser = new Map(rows.map((r) => [r.hosting_account.username, r]));
    const a = byUser.get('a')!;
    const b = byUser.get('b')!;
    const c = byUser.get('c')!;
    const d = byUser.get('d')!;
    h.resellerTable.find((r) => r['id'] === b.id)!['parent_reseller_id'] = a.id;
    h.resellerTable.find((r) => r['id'] === c.id)!['parent_reseller_id'] = b.id;

    const moved = await h.svc.update(a.id, { parent_reseller_id: d.id }, ADMIN);
    expect(moved.depth).toBe(2);
    expect(moved.parent_reseller_id).toBe(d.id);
    expect(h.resellerTable.find((r) => r['id'] === b.id)!['depth']).toBe(3);
    expect(h.resellerTable.find((r) => r['id'] === c.id)!['depth']).toBe(4);
  });

  it('rejects re-parenting under an own descendant (cycle) or itself', async () => {
    const h = harness(
      [
        { id: ACCOUNT_A, username: 'a' },
        { id: ACCOUNT_B, username: 'b' },
      ],
      [
        { hosting_account_id: ACCOUNT_A, depth: 1 },
        { hosting_account_id: ACCOUNT_B, depth: 2 },
      ],
    );
    const [a, b] = (await h.svc.list()).data;
    h.resellerTable.find((r) => r['id'] === b.id)!['parent_reseller_id'] = a.id;

    await expect(h.svc.update(a.id, { parent_reseller_id: b.id }, ADMIN)).rejects.toThrow(
      'own descendant',
    );
    await expect(h.svc.update(a.id, { parent_reseller_id: a.id }, ADMIN)).rejects.toThrow(
      'own parent',
    );
  });

  it('rejects moves that would push a descendant past the cap', async () => {
    process.env['RESELLER_MAX_DEPTH'] = '3';
    // B(d1) with child C(d2). E sits at depth 2 (under A). Moving B under E
    // would push B→3 (ok) but C→4 (beyond cap 3) — rejected wholesale.
    const h = harness(
      [
        { id: ACCOUNT_A, username: 'a' },
        { id: ACCOUNT_B, username: 'b' },
        { id: ACCOUNT_C, username: 'c' },
        { id: ACCOUNT_E, username: 'e' },
      ],
      [
        { hosting_account_id: ACCOUNT_A, depth: 1 },
        { hosting_account_id: ACCOUNT_B, depth: 1 },
        { hosting_account_id: ACCOUNT_C, depth: 2 },
        { hosting_account_id: ACCOUNT_E, depth: 2 },
      ],
    );
    const rows = (await h.svc.list()).data;
    const byUser = new Map(rows.map((r) => [r.hosting_account.username, r]));
    const a = byUser.get('a')!;
    const b = byUser.get('b')!;
    const c = byUser.get('c')!;
    const e = byUser.get('e')!;
    h.resellerTable.find((r) => r['id'] === c.id)!['parent_reseller_id'] = b.id;
    h.resellerTable.find((r) => r['id'] === e.id)!['parent_reseller_id'] = a.id;

    await expect(h.svc.update(b.id, { parent_reseller_id: e.id }, ADMIN)).rejects.toThrow(
      /beyond the cap of 3/,
    );
    // The rejected move must not have shifted anything.
    expect(h.resellerTable.find((r) => r['id'] === c.id)!['depth']).toBe(2);
  });

  it('re-parents to the top level with parent_reseller_id: null', async () => {
    const h = harness(
      [
        { id: ACCOUNT_A, username: 'a' },
        { id: ACCOUNT_B, username: 'b' },
      ],
      [
        { hosting_account_id: ACCOUNT_A, depth: 1 },
        { hosting_account_id: ACCOUNT_B, depth: 2 },
      ],
    );
    const [a, b] = (await h.svc.list()).data;
    h.resellerTable.find((r) => r['id'] === b.id)!['parent_reseller_id'] = a.id;

    const moved = await h.svc.update(b.id, { parent_reseller_id: null }, ADMIN);
    expect(moved.parent_reseller_id).toBeNull();
    expect(moved.depth).toBe(1);
    expect(h.audit.list().at(-1)?.operation).toBe('reseller.update');
  });

  it('404s an unknown parent and 400s a malformed id', async () => {
    const { svc } = harness([{ id: ACCOUNT_A, username: 'a' }], [
      { hosting_account_id: ACCOUNT_A, depth: 1 },
    ]);
    const [a] = (await svc.list()).data;
    await expect(svc.update(a.id, { parent_reseller_id: ACCOUNT_B }, ADMIN)).rejects.toThrow(
      NotFoundException,
    );
    await expect(svc.update(a.id, { parent_reseller_id: 'junk' }, ADMIN)).rejects.toThrow(
      BadRequestException,
    );
  });

  it('400s an empty update (nothing mutable)', async () => {
    const { svc } = harness([{ id: ACCOUNT_A, username: 'a' }], [
      { hosting_account_id: ACCOUNT_A, depth: 1 },
    ]);
    const [a] = (await svc.list()).data;
    await expect(svc.update(a.id, {}, ADMIN)).rejects.toThrow('nothing to update');
  });
});

describe('reseller delete (§4.6 DELETE /resellers/{id})', () => {
  it('soft-deletes a childless reseller and audits it', async () => {
    const { svc, audit, resellerTable } = harness([{ id: ACCOUNT_A, username: 'a' }], [
      { hosting_account_id: ACCOUNT_A, depth: 1 },
    ]);
    const [a] = (await svc.list()).data;
    await svc.remove(a.id, ADMIN);
    expect(resellerTable[0]['deleted_at']).toBeInstanceOf(Date);
    expect(audit.list().at(-1)?.operation).toBe('reseller.delete');
  });

  it('409s while live child resellers exist', async () => {
    const h = harness(
      [
        { id: ACCOUNT_A, username: 'a' },
        { id: ACCOUNT_B, username: 'b' },
      ],
      [
        { hosting_account_id: ACCOUNT_A, depth: 1 },
        { hosting_account_id: ACCOUNT_B, depth: 2 },
      ],
    );
    const [a, b] = (await h.svc.list()).data;
    h.resellerTable.find((r) => r['id'] === b.id)!['parent_reseller_id'] = a.id;
    await expect(h.svc.remove(a.id, ADMIN)).rejects.toThrow(ConflictException);
  });

  it('404s unknown ids uniformly (including malformed uuids)', async () => {
    const { svc } = harness();
    await expect(svc.remove('nope', ADMIN)).rejects.toThrow(NotFoundException);
    await expect(svc.get('nope')).rejects.toThrow(NotFoundException);
  });
});

describe('branding (§4.6 GET/PATCH /resellers/{id}/branding)', () => {
  it('round-trips a valid branding object', async () => {
    const { svc, audit } = harness([{ id: ACCOUNT_A, username: 'a' }], [
      { hosting_account_id: ACCOUNT_A, depth: 1 },
    ]);
    const [a] = (await svc.list()).data;
    const branding = {
      brand_name: 'BrandCo',
      primary_color: '#0a84ff',
      logo_url: 'https://cdn.brand.co/logo.svg',
      login_message: 'Welcome to BrandCo hosting',
      show_powered_by: false,
    };
    const res = await svc.updateBranding(a.id, { branding }, ADMIN);
    expect(res.branding).toEqual(branding);
    expect((await svc.getBranding(a.id)).branding).toEqual(branding);
    expect(audit.list().at(-1)?.operation).toBe('reseller.branding.update');
  });

  it('rejects non-objects, bad keys, oversized strings and nested objects', () => {
    expect(() => validateBranding('nope')).toThrow(BadRequestException);
    expect(() => validateBranding({ 'Bad Key': 'x' })).toThrow(BadRequestException);
    expect(() => validateBranding({ ok: 'x'.repeat(301) })).toThrow(BadRequestException);
    expect(() => validateBranding({ nested: { deep: true } })).toThrow(BadRequestException);
  });

  it('enforces the semantic formats: brand name, colors, https logo', () => {
    expect(() => validateBranding({ brand_name: '' })).toThrow(BadRequestException);
    expect(() => validateBranding({ primary_color: 'blue' })).toThrow(BadRequestException);
    expect(() => validateBranding({ accent_color: '#0a84f' })).toThrow(BadRequestException);
    expect(() => validateBranding({ logo_url: 'http://insecure/logo.png' })).toThrow(BadRequestException);
    expect(() => validateBranding({ login_message: 'x'.repeat(301) })).toThrow(BadRequestException);
    expect(validateBranding(undefined)).toEqual({});
  });

  it('rejects branding over 8 KiB', () => {
    expect(() => validateBranding({ blob: 'x'.repeat(9000) })).toThrow(BadRequestException);
  });
});

describe('custom domain (§4.6 POST/DELETE /resellers/{id}/custom-domain)', () => {
  it('sets a valid domain with status pending, normalized', async () => {
    const { svc, audit } = harness([{ id: ACCOUNT_A, username: 'a' }], [
      { hosting_account_id: ACCOUNT_A, depth: 1 },
    ]);
    const [a] = (await svc.list()).data;
    const dto = await svc.setCustomDomain(a.id, { custom_domain: 'Panel.BrandCo.COM.' }, ADMIN);
    expect(dto.custom_domain).toBe('panel.brandco.com');
    expect(dto.custom_domain_status).toBe('pending');
    expect(audit.list().at(-1)?.operation).toBe('reseller.custom_domain.set');
  });

  it('rejects ports, paths, wildcards, underscores and bare labels', () => {
    expect(() => validateCustomDomain('panel.brand.co:8443')).toThrow(BadRequestException);
    expect(() => validateCustomDomain('panel.brand.co/login')).toThrow(BadRequestException);
    expect(() => validateCustomDomain('*.brand.co')).toThrow(BadRequestException);
    expect(() => validateCustomDomain('panel_brand.co')).toThrow(BadRequestException);
    expect(() => validateCustomDomain('localhost')).toThrow(BadRequestException);
    expect(() => validateCustomDomain('-bad.label')).toThrow(BadRequestException);
    expect(() => validateCustomDomain(42)).toThrow(BadRequestException);
  });

  it('409s when another live reseller claims the domain; own re-set is fine', async () => {
    const h = harness(
      [
        { id: ACCOUNT_A, username: 'a' },
        { id: ACCOUNT_B, username: 'b' },
      ],
      [
        { hosting_account_id: ACCOUNT_A, depth: 1 },
        { hosting_account_id: ACCOUNT_B, depth: 1 },
      ],
    );
    const [a, b] = (await h.svc.list()).data;
    await h.svc.setCustomDomain(a.id, { custom_domain: 'panel.brandco.com' }, ADMIN);
    await expect(
      h.svc.setCustomDomain(b.id, { custom_domain: 'panel.brandco.com' }, ADMIN),
    ).rejects.toThrow(ConflictException);
    const again = await h.svc.setCustomDomain(a.id, { custom_domain: 'panel.brandco.com' }, ADMIN);
    expect(again.custom_domain).toBe('panel.brandco.com');
  });

  it('clears the domain and records the previous value in the audit', async () => {
    const { svc, audit } = harness([{ id: ACCOUNT_A, username: 'a' }], [
      {
        hosting_account_id: ACCOUNT_A,
        depth: 1,
        custom_domain: 'panel.brandco.com',
        custom_domain_status: 'pending',
      },
    ]);
    const [a] = (await svc.list()).data;
    const dto = await svc.clearCustomDomain(a.id, ADMIN);
    expect(dto.custom_domain).toBeNull();
    expect(dto.custom_domain_status).toBeNull();
    expect(audit.list().at(-1)?.operation).toBe('reseller.custom_domain.clear');
    expect(audit.list().at(-1)?.parameters).toMatchObject({ previous_domain: 'panel.brandco.com' });
  });
});

describe('list (§4.6 GET /resellers)', () => {
  it('returns live resellers with account + nesting info, oldest first', async () => {
    const h = harness(
      [
        { id: ACCOUNT_A, username: 'a' },
        { id: ACCOUNT_B, username: 'b' },
      ],
      [
        { hosting_account_id: ACCOUNT_A, depth: 1 },
        {
          hosting_account_id: ACCOUNT_B,
          depth: 2,
          custom_domain: 'panel.b.co',
          custom_domain_status: 'pending',
        },
      ],
    );
    const { data } = await h.svc.list();
    expect(data.map((r) => r.hosting_account.username)).toEqual(['a', 'b']);
    expect(data[1].custom_domain).toBe('panel.b.co');
    expect(typeof data[0].created_at).toBe('string');
  });
});
