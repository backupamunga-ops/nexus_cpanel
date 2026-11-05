import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { MailService } from './mail.service';
import { hashMailboxPassword, verifyMailboxPassword } from './mailbox-hash';

/**
 * Email core (ADR-0013): strict address shaping, package limit enforcement
 * (features.mail_enabled + quotas.mailbox_count / mailbox_quota_mb),
 * agent-first provisioning (failed agent call leaves no row), SSHA512
 * password hashing (agent never sees a password), audited mutations,
 * C7 404s, domain delete refused while mailboxes/aliases exist.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true } as const;
const VIEWER = { userId: 'u-viewer', isSuperAdmin: false } as const;

const ACCOUNT_ID = '01900000-0000-7000-8000-00000000a001';
const PACKAGE_ID = '01900000-0000-7000-8000-00000000p001';

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

interface Row {
  id: string;
  kind?: string;
  deleted_at: Date | null;
  [k: string]: unknown;
}

function harness(opts: {
  accessRows?: Array<{ user_id: string; hosting_account_id: string }>;
  packageRow?: { features: Record<string, unknown>; quotas: Record<string, unknown> } | null;
} = {}) {
  const audit = new InMemoryAuditService();
  const rows: Row[] = [];
  const accessRows = opts.accessRows ?? [];
  const packageRow = opts.packageRow ?? null;

  const prisma = {
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.find((r) => r.kind === 'account' && r.id === where['id'] && r.deleted_at === null) ?? null,
      ),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        accessRows.find((a) => a.user_id === where['user_id'] && a.hosting_account_id === where['hosting_account_id']) ?? null,
      ),
    },
    package: {
      findFirst: jest.fn(async () => packageRow),
    },
    mailDomain: {
      findFirst: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const row = rows.find(
          (r) =>
            r.kind === 'maildomain' &&
            (where['id'] === undefined || r.id === where['id']) &&
            (where['name'] === undefined || r['name'] === where['name']) &&
            (where['hosting_account_id'] === undefined || r['hosting_account_id'] === where['hosting_account_id']) &&
            r.deleted_at === null,
        );
        return row ? decorate(row, include) : null;
      }),
      findMany: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) =>
        rows
          .filter((r) => r.kind === 'maildomain' && r['hosting_account_id'] === where['hosting_account_id'] && r.deleted_at === null)
          .map((r) => decorate(r, include)),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = {
          id: uid(rows.length + 50),
          kind: 'maildomain',
          ...data,
          created_at: new Date(),
          deleted_at: null,
        };
        rows.push(row);
        return decorate(row);
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rows.find((r) => r.id === where.id)!;
        Object.assign(row, data);
        return row;
      }),
      findFirstOrThrow: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const row = rows.find((r) => r.kind === 'maildomain' && r.id === where['id']);
        if (!row) throw new NotFoundException('mail domain not found');
        return decorate(row, include);
      }),
    },
    mailboxe: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.find(
          (r) =>
            r.kind === 'mailbox' &&
            (where['id'] === undefined || r.id === where['id']) &&
            (where['local_part'] === undefined || r['local_part'] === where['local_part']) &&
            (where['mail_domain_id'] === undefined || r['mail_domain_id'] === where['mail_domain_id']) &&
            r.deleted_at === null,
        ) ?? null,
      ),
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.filter((r) => r.kind === 'mailbox' && r['mail_domain_id'] === where['mail_domain_id'] && r.deleted_at === null),
      ),
      count: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const domainWhere = (where['mail_domain'] ?? {}) as Record<string, unknown>;
        return rows.filter(
          (r) =>
            r.kind === 'mailbox' &&
            r.deleted_at === null &&
            (domainWhere['hosting_account_id'] === undefined ||
              rows.find((d) => d.kind === 'maildomain' && d.id === r['mail_domain_id'])?.['hosting_account_id'] ===
                domainWhere['hosting_account_id']),
        ).length;
      }),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = { id: uid(rows.length + 100), kind: 'mailbox', ...data, created_at: new Date(), updated_at: new Date(), deleted_at: null };
        rows.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rows.find((r) => r.id === where.id)!;
        Object.assign(row, data);
        return row;
      }),
    },
    mailAliase: {
      count: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.filter(
          (r) =>
            r.kind === 'alias' &&
            r.deleted_at === null &&
            (where['mail_domain_id'] === undefined || r['mail_domain_id'] === where['mail_domain_id']),
        ).length,
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.find(
          (r) =>
            r.kind === 'alias' &&
            (where['id'] === undefined || r.id === where['id']) &&
            (where['source_address'] === undefined || r['source_address'] === where['source_address']) &&
            (where['mail_domain_id'] === undefined || r['mail_domain_id'] === where['mail_domain_id']) &&
            r.deleted_at === null,
        ) ?? null,
      ),
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        rows.filter(
          (r) =>
            r.kind === 'alias' &&
            r.deleted_at === null &&
            (where['mail_domain_id'] === undefined || r['mail_domain_id'] === where['mail_domain_id']) &&
            (where['destination_address'] === undefined || r['destination_address'] === where['destination_address']),
        ),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = { id: uid(rows.length + 150), kind: 'alias', ...data, created_at: new Date(), deleted_at: null };
        rows.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rows.find((r) => r.id === where.id)!;
        Object.assign(row, data);
        return row;
      }),
    },
    autoresponder: {
      findFirst: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const mw = (where['mailbox'] ?? {}) as Record<string, unknown>;
        const row = rows.find(
          (r) =>
            r.kind === 'autoresponder' &&
            (where['id'] === undefined || r.id === where['id']) &&
            (mw['mail_domain_id'] === undefined ||
              rows.find((b) => b.kind === 'mailbox' && b.id === r['mailbox_id'])?.['mail_domain_id'] === mw['mail_domain_id']),
        );
        return row ? decorate(row, include) : null;
      }),
      findMany: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        const mw = (where['mailbox'] ?? {}) as Record<string, unknown>;
        const boxDomain = (id: string) => rows.find((b) => b.kind === 'mailbox' && b.id === id)?.['mail_domain_id'];
        return rows
          .filter(
            (r) =>
              r.kind === 'autoresponder' &&
              (mw['mail_domain_id'] === undefined || boxDomain(r['mailbox_id'] as string) === mw['mail_domain_id']),
          )
          .map((r) => decorate(r, include));
      }),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row: Row = { id: uid(rows.length + 200), kind: 'autoresponder', ...data, created_at: new Date(), deleted_at: null };
        rows.push(row);
        return decorate(row);
      }),
      delete: jest.fn(async ({ where }: { where: { id: string } }) => {
        const idx = rows.findIndex((r) => r.id === where.id);
        return rows.splice(idx, 1)[0];
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };

  function decorate(row: Row, include?: Record<string, unknown>): Row {
    const out: Row = { ...row };
    if (include?.['hosting_account'] || out.kind === 'maildomain') {
      out['hosting_account'] = {
        id: ACCOUNT_ID,
        username: 'alice',
        package_id: packageRow ? PACKAGE_ID : null,
      };
    }
    if (include?.['mailboxes__mail_domain_id']) {
      out['mailboxes__mail_domain_id'] = rows.filter((r) => r.kind === 'mailbox' && r['mail_domain_id'] === row.id && r.deleted_at === null);
    }
    if (include?.['mailbox'] && typeof out['mailbox_id'] === 'string') {
      const box = rows.find((b) => b.kind === 'mailbox' && b.id === out['mailbox_id']);
      out['mailbox'] = box ? { id: box.id, local_part: box['local_part'], deleted_at: null } : { id: '', local_part: '', deleted_at: null };
    }
    return out;
  }

  const agent = {
    mailCreateDomain: jest.fn(async () => ({ status: 'created', maps: { built: true } })),
    mailDeleteDomain: jest.fn(async () => ({ status: 'removed', maps: { built: true } })),
    mailCreateMailbox: jest.fn(async (email: string, quotaMb: number) => ({
      status: 'created',
      email,
      maildir: `/srv/vmail/${email.split('@')[1]}/${email.split('@')[0]}`,
      quota_mb: quotaMb,
      ownership: { applied: true },
      maps: { built: true },
    })),
    mailModifyMailbox: jest.fn(async () => ({ status: 'updated' })),
    mailDeleteMailbox: jest.fn(async (_email: string, preserve: boolean) => ({
      status: 'removed',
      preserved_as: preserve ? '/srv/vmail/.trash/x' : undefined,
    })),
    mailCreateAlias: jest.fn(async () => ({ status: 'created', maps: { built: true } })),
    mailDeleteAlias: jest.fn(async () => ({ status: 'removed' })),
    mailCreateAutoresponder: jest.fn(async () => ({ status: 'created' })),
    mailDeleteAutoresponder: jest.fn(async () => ({ status: 'removed' })),
  };

  const svc = new MailService(prisma as unknown as PrismaService, agent as never, audit);
  rows.push({ id: ACCOUNT_ID, kind: 'account', username: 'alice', package_id: packageRow ? PACKAGE_ID : null, deleted_at: null });
  return { svc, agent, audit, rows, prisma };
}

async function seedDomain(h: ReturnType<typeof harness>, name = 'example.com') {
  return h.svc.createDomain(SUPER, { account_id: ACCOUNT_ID, name });
}

describe('mail domains (B07, ADR-0013)', () => {
  it('creates a domain agent-first and audits it', async () => {
    const h = harness();
    const dto = await seedDomain(h);
    expect(dto.name).toBe('example.com');
    expect(h.agent.mailCreateDomain).toHaveBeenCalledWith('example.com');
    const ops = h.audit.list().filter((e) => e.operation === 'mail.domain.create');
    expect(ops).toHaveLength(1);
    expect(ops[0]['outcome']).toBe('success');
  });

  it('leaves no row when the agent fails, and audits the failure', async () => {
    const h = harness();
    h.agent.mailCreateDomain.mockRejectedValueOnce(new Error('agent unreachable'));
    await expect(h.svc.createDomain(SUPER, { account_id: ACCOUNT_ID, name: 'example.com' })).rejects.toThrow('agent unreachable');
    expect(h.rows.filter((r) => r.kind === 'maildomain')).toHaveLength(0);
    const ops = h.audit.list().filter((e) => e.operation === 'mail.domain.create');
    expect(ops[0]['outcome']).toBe('failure');
  });

  it('rejects bad domain shapes and duplicates without calling the agent', async () => {
    const h = harness();
    await seedDomain(h);
    await expect(h.svc.createDomain(SUPER, { account_id: ACCOUNT_ID, name: 'not-a-fqdn' })).rejects.toThrow(BadRequestException);
    await expect(h.svc.createDomain(SUPER, { account_id: ACCOUNT_ID, name: 'example.com' })).rejects.toThrow(ConflictException);
    expect(h.agent.mailCreateDomain).toHaveBeenCalledTimes(1);
  });

  it('refuses to delete a domain that still has mailboxes or aliases (no orphaned node state)', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const box = await h.svc.createMailbox(SUPER, d.id, { local_part: 'pam', password: 's3cretpass', quota_mb: 64 });
    await expect(h.svc.deleteDomain(SUPER, d.id)).rejects.toThrow(ConflictException);
    await h.svc.deleteMailbox(SUPER, d.id, box.id, {});
    await h.svc.deleteDomain(SUPER, d.id);
    const row = h.rows.find((r) => r.id === d.id) as Record<string, unknown>;
    expect(row['deleted_at']).not.toBeNull();
  });
});

describe('mailboxes (B07)', () => {
  it('creates agent-first, hashes the password SSHA512, never sends it to the agent', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const dto = await h.svc.createMailbox(SUPER, d.id, { local_part: 'Pam', password: 's3cretpass', quota_mb: 512 });
    expect(dto.address).toBe('pam@example.com');
    expect(dto.quota_mb).toBe(512);
    expect(h.agent.mailCreateMailbox).toHaveBeenCalledWith('pam@example.com', 512);
    const raw = JSON.stringify(h.agent.mailCreateMailbox.mock.calls);
    expect(raw).not.toContain('s3cretpass');
    const stored = Buffer.from(h.rows.find((r) => r.kind === 'mailbox')!['password_hash'] as Uint8Array).toString('utf8');
    expect(stored.startsWith('{SSHA512}')).toBe(true);
    expect(verifyMailboxPassword('s3cretpass', stored)).toBe(true);
  });

  it('enforces package limits: feature gate, mailbox_count, mailbox_quota_mb', async () => {
    // Feature gate: with mail disabled even the mail domain is refused.
    const h0 = harness({ packageRow: { features: { mail_enabled: false }, quotas: {} } });
    await expect(h0.svc.createDomain(SUPER, { account_id: ACCOUNT_ID, name: 'example.com' })).rejects.toThrow(
      /mail is disabled/,
    );
    expect(h0.agent.mailCreateDomain).not.toHaveBeenCalled();

    // Quota caps: mailbox_count + mailbox_quota_mb.
    const h = harness({ packageRow: { features: {}, quotas: { mailbox_count: 1, mailbox_quota_mb: 100 } } });
    const d = await seedDomain(h);
    await h.svc.createMailbox(SUPER, d.id, { local_part: 'one', password: 's3cretpass', quota_mb: 100 });
    await expect(h.svc.createMailbox(SUPER, d.id, { local_part: 'two', password: 's3cretpass', quota_mb: 100 })).rejects.toThrow(
      /caps the account at 1 mailboxes/,
    );
    await expect(h.svc.createMailbox(SUPER, d.id, { local_part: 'big', password: 's3cretpass', quota_mb: 200 })).rejects.toThrow(
      /caps mailbox quota at 100 MB/,
    );
    expect(h.agent.mailCreateMailbox).toHaveBeenCalledTimes(1);
  });

  it('rejects bad local parts, weak passwords and duplicates before the agent call', async () => {
    const h = harness();
    const d = await seedDomain(h);
    await expect(h.svc.createMailbox(SUPER, d.id, { local_part: '../etc', password: 's3cretpass', quota_mb: 64 })).rejects.toThrow(
      BadRequestException,
    );
    await expect(h.svc.createMailbox(SUPER, d.id, { local_part: 'ok', password: 'short', quota_mb: 64 })).rejects.toThrow(
      BadRequestException,
    );
    await h.svc.createMailbox(SUPER, d.id, { local_part: 'ok', password: 's3cretpass', quota_mb: 64 });
    await expect(h.svc.createMailbox(SUPER, d.id, { local_part: 'ok', password: 's3cretpass', quota_mb: 64 })).rejects.toThrow(
      ConflictException,
    );
    expect(h.agent.mailCreateMailbox).toHaveBeenCalledTimes(1);
  });

  it('rotates the password panel-side only (agent not in the password path) and audits it', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const box = await h.svc.createMailbox(SUPER, d.id, { local_part: 'pw', password: 's3cretpass', quota_mb: 64 });
    await h.svc.setMailboxPassword(SUPER, d.id, box.id, { password: 'n3wpassword' });
    expect(h.agent.mailModifyMailbox).not.toHaveBeenCalled();
    const stored = Buffer.from(
      (h.rows.find((r) => r.kind === 'mailbox')!['password_hash'] as Uint8Array),
    ).toString('utf8');
    expect(verifyMailboxPassword('n3wpassword', stored)).toBe(true);
    const ops = h.audit.list().filter((e) => e.operation === 'mail.mailbox.password');
    expect(ops).toHaveLength(1);
  });

  it('deletes with preserve_mail, cascading aliases that pointed at it', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const box = await h.svc.createMailbox(SUPER, d.id, { local_part: 'gone', password: 's3cretpass', quota_mb: 64 });
    await h.svc.createAlias(SUPER, d.id, { source: 'reach', destination: 'gone@example.com' });
    const out = await h.svc.deleteMailbox(SUPER, d.id, box.id, { preserve_mail: true });
    expect(out.preserved_as).toBeTruthy();
    expect(h.agent.mailDeleteAlias).toHaveBeenCalledWith('reach@example.com');
    const alias = h.rows.find((r) => r.kind === 'alias') as Record<string, unknown>;
    expect(alias['deleted_at']).not.toBeNull();
    const boxRow = h.rows.find((r) => r.kind === 'mailbox') as Record<string, unknown>;
    expect(boxRow['deleted_at']).not.toBeNull();
  });

  it('404s invisible mailboxes for non-admin users (C7)', async () => {
    const h = harness({ accessRows: [] });
    const d = await seedDomain(h);
    await expect(h.svc.listMailboxes(VIEWER, d.id)).rejects.toThrow(NotFoundException);
  });
});

describe('aliases (B07)', () => {
  it('creates plain + catch-all aliases with node map updates', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const a = await h.svc.createAlias(SUPER, d.id, { source: 'help', destination: 'pam@example.com' });
    expect(a.source_address).toBe('help@example.com');
    const c = await h.svc.createAlias(SUPER, d.id, { source: '@example.com', destination: 'pam@example.com' });
    expect(c.is_catchall).toBe(true);
    expect(h.agent.mailCreateAlias).toHaveBeenNthCalledWith(1, 'help@example.com', 'pam@example.com');
    expect(h.agent.mailCreateAlias).toHaveBeenNthCalledWith(2, '@example.com', 'pam@example.com');
  });

  it('rejects cross-domain sources, self-loops and duplicates', async () => {
    const h = harness();
    const d = await seedDomain(h);
    await expect(h.svc.createAlias(SUPER, d.id, { source: 'help@other.com', destination: 'pam@example.com' })).rejects.toThrow(
      BadRequestException,
    );
    await expect(h.svc.createAlias(SUPER, d.id, { source: 'loop', destination: 'loop@example.com' })).rejects.toThrow(
      /must differ/,
    );
    await h.svc.createAlias(SUPER, d.id, { source: 'help', destination: 'pam@example.com' });
    await expect(h.svc.createAlias(SUPER, d.id, { source: 'help', destination: 'pam@example.com' })).rejects.toThrow(
      ConflictException,
    );
  });
});

describe('autoresponders (B07)', () => {
  it('creates with a schedule window and reports schedule_state honestly', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const box = await h.svc.createMailbox(SUPER, d.id, { local_part: 'away', password: 's3cretpass', quota_mb: 64 });
    const future = new Date(Date.now() + 86_400_000);
    const past = new Date(Date.now() - 86_400_000);
    const dto = await h.svc.createAutoresponder(SUPER, d.id, {
      mailbox_id: box.id,
      subject: 'OOO',
      body: 'On vacation.',
      starts_at: future.toISOString(),
    });
    expect(dto.schedule_state).toBe('scheduled');
    const dto2 = await h.svc.createAutoresponder(SUPER, d.id, {
      mailbox_id: box.id,
      subject: 'Back in the day',
      body: 'Historic.',
      starts_at: past.toISOString(),
    });
    expect(dto2.schedule_state).toBe('active');
  });

  it('rejects inverted windows and empty bodies before any node call', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const box = await h.svc.createMailbox(SUPER, d.id, { local_part: 'away', password: 's3cretpass', quota_mb: 64 });
    await expect(
      h.svc.createAutoresponder(SUPER, d.id, {
        mailbox_id: box.id,
        subject: 'x',
        body: 'y',
        starts_at: new Date(Date.now() + 1000).toISOString(),
        ends_at: new Date(Date.now() - 1000).toISOString(),
      }),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.createAutoresponder(SUPER, d.id, { mailbox_id: box.id, subject: 'x', body: '   ' }),
    ).rejects.toThrow(BadRequestException);
    expect(h.agent.mailCreateAutoresponder).not.toHaveBeenCalled();
  });

  it('deletes through the agent and removes the row', async () => {
    const h = harness();
    const d = await seedDomain(h);
    const box = await h.svc.createMailbox(SUPER, d.id, { local_part: 'away', password: 's3cretpass', quota_mb: 64 });
    const dto = await h.svc.createAutoresponder(SUPER, d.id, { mailbox_id: box.id, subject: 'OOO', body: 'Gone.' });
    await h.svc.deleteAutoresponder(SUPER, d.id, dto.id);
    expect(h.agent.mailDeleteAutoresponder).toHaveBeenCalledWith('away@example.com');
    expect(h.rows.filter((r) => r.kind === 'autoresponder')).toHaveLength(0);
  });
});

describe('mailbox-hash (SSHA512)', () => {
  it('round-trips and rejects tampering', () => {
    const h = hashMailboxPassword('correct horse battery');
    expect(h.startsWith('{SSHA512}')).toBe(true);
    expect(verifyMailboxPassword('correct horse battery', h)).toBe(true);
    expect(verifyMailboxPassword('wrong', h)).toBe(false);
    expect(verifyMailboxPassword('correct horse battery', h.slice(0, -4) + 'AAAA')).toBe(false);
  });

  it('salts: two hashes of the same password differ but both verify', () => {
    const a = hashMailboxPassword('same-password-1');
    const b = hashMailboxPassword('same-password-1');
    expect(a).not.toBe(b);
    expect(verifyMailboxPassword('same-password-1', a)).toBe(true);
    expect(verifyMailboxPassword('same-password-1', b)).toBe(true);
  });
});
