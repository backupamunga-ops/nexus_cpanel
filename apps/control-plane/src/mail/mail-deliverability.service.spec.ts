import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { MailDeliverabilityService } from './mail-deliverability.service';

// SecretBox (ADR-0009) is fail-closed on a missing key; the suite pins a
// deterministic test key before the service resolves the box.
process.env.PANEL_SECRET_KEY = process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

/**
 * Deliverability (ADR-0014): DKIM minting is agent-first + DNS-module
 * writes; no zone → 409 with honest guidance; rotation keeps the old
 * selector published; relay credentials are SecretBox-encrypted and never
 * returned; queue failures are audited.
 */

const SUPER = { userId: 'u-admin', isSuperAdmin: true } as const;
const DOMAIN_ID = '01900000-0000-7000-8000-00000000d001';
const ACCOUNT_ID = '01900000-0000-7000-8000-00000000a001';
const ZONE_ID = '01900000-0000-7000-8000-00000000z001';

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

function harness(opts: { zone?: { id: string; name: string } | null; dkimRow?: Record<string, unknown> | null } = {}) {
  const audit = new InMemoryAuditService();
  const zone = opts.zone === undefined ? { id: ZONE_ID, name: 'example.com' } : opts.zone;
  const dnsRecords: Array<Record<string, unknown>> = [];

  const prisma = {
    mailDomain: {
      findFirst: jest.fn(async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
        if (where['id'] !== DOMAIN_ID) return null;
        const row = {
          id: DOMAIN_ID,
          name: 'example.com',
          hosting_account_id: ACCOUNT_ID,
          deleted_at: null,
          ...(include?.['hosting_account'] ? { hosting_account: { id: ACCOUNT_ID, username: 'alice' } } : {}),
        };
        return row;
      }),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async () => null),
    },
    dnZone: {
      findFirst: jest.fn(async () => zone),
    },
    mailDomainDkim: {
      findUnique: jest.fn(async () => dkimState.value),
      upsert: jest.fn(async ({ create, update }: { create: Record<string, unknown>; update: Record<string, unknown> }) => {
        dkimState.value = dkimState.value ? { ...dkimState.value, ...update } : { id: uid(900), ...create };
        return dkimState.value;
      }),
    },
    dnRecord: {
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        dnsRecords.find(
          (r) =>
            r['zone_id'] === where['zone_id'] &&
            r['name'] === where['name'] &&
            r['type'] === where['type'] &&
            r['deleted_at'] === null,
        ) ?? null,
      ),
    },
    systemSetting: {
      findUnique: jest.fn(async ({ where }: { where: { key: string } }) =>
        settings[where.key] ? { key: where.key, value: settings[where.key], updated_at: new Date() } : null,
      ),
      upsert: jest.fn(async ({ where, update }: { where: { key: string }; update: { value: unknown } }) => {
        settings[where.key] = update.value;
        return { key: where.key, value: settings[where.key], updated_at: new Date() };
      }),
      delete: jest.fn(async ({ where }: { where: { key: string } }) => {
        const v = settings[where.key];
        delete settings[where.key];
        return { key: where.key, value: v };
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };
  const settings: Record<string, unknown> = {};
  const dkimState: { value: Record<string, unknown> | null } = { value: opts.dkimRow ?? null };

  const agent = {
    mailApplyDkim: jest.fn(async (domain: string, selector: string) => ({
      status: 'created',
      domain,
      selector,
      dns_txt: 'v=DKIM1; k=rsa; p=AGENT',
      key_fingerprint: 'abcd1234',
      opendkim: { applied: true },
    })),
    mailQueueList: jest.fn(async () => ({ queue: [{ queue_id: 'AB12CD34EF', size: 512, arrival: 'Tue Nov  4 09:15:22', sender: 's@x.com', recipient: 'r@y.net', reason: 'Connection refused' }], total: 1, source: 'postqueue -p' })),
    mailQueueFlush: jest.fn(async () => ({ status: 'flushed' })),
    mailQueueRetry: jest.fn(async (id: string) => ({ status: 'requeued', message_id: id })),
  };
  const dns = {
    addRecord: jest.fn(async (_actor: unknown, _zoneId: string, input: Record<string, unknown>) => {
      dnsRecords.push({ id: uid(dnsRecords.length + 300), ...input, deleted_at: null, zone_id: ZONE_ID });
      return input;
    }),
    updateRecord: jest.fn(async (_actor: unknown, _zoneId: string, recordId: string, input: Record<string, unknown>) => {
      const row = dnsRecords.find((r) => r['id'] === recordId);
      Object.assign(row!, input);
      return input;
    }),
  };

  const svc = new MailDeliverabilityService(prisma as unknown as PrismaService, agent as never, dns as never, audit);
  return { svc, agent, dns, audit, dnsRecords, settings };
}

describe('DKIM (B08, ADR-0014)', () => {
  it('mints a key, stores it via the agent, and publishes the DNS record through the DNS module', async () => {
    const h = harness();
    const out = await h.svc.enableDkim(SUPER, DOMAIN_ID, {});
    expect(out.selector).toMatch(/^s\d+$/);
    expect(out.dns_record).toContain('._domainkey.example.com');
    expect(h.agent.mailApplyDkim).toHaveBeenCalledWith('example.com', out.selector, expect.stringContaining('PRIVATE KEY'));
    expect(h.dns.addRecord).toHaveBeenCalledWith(
      SUPER,
      ZONE_ID,
      expect.objectContaining({ type: 'TXT', content: expect.stringContaining('v=DKIM1') }),
    );
    const ops = h.audit.list().filter((e) => e.operation === 'mail.dkim.enable');
    expect(ops).toHaveLength(1);
    expect(JSON.stringify(ops[0])).not.toContain('PRIVATE KEY');
  });

  it('409s honestly when the domain has no managed DNS zone', async () => {
    const h = harness({ zone: null });
    await expect(h.svc.enableDkim(SUPER, DOMAIN_ID, {})).rejects.toThrow(ConflictException);
    expect(h.agent.mailApplyDkim).not.toHaveBeenCalled();
  });

  it('conflicts on double enable and 404s rotate without an existing key', async () => {
    const h = harness();
    await h.svc.enableDkim(SUPER, DOMAIN_ID, { selector: 'mail1' });
    await expect(h.svc.enableDkim(SUPER, DOMAIN_ID, {})).rejects.toThrow(ConflictException);

    const h2 = harness();
    await expect(h2.svc.rotateDkim(SUPER, DOMAIN_ID, {})).rejects.toThrow(NotFoundException);
  });

  it('rotates to a new selector, keeping the previous one published (manual TXT removal)', async () => {
    const h = harness({ dkimRow: { id: uid(1), mail_domain_id: DOMAIN_ID, selector: 'oldsel', rotated_at: null, created_at: new Date() } });
    const out = await h.svc.rotateDkim(SUPER, DOMAIN_ID, {});
    expect(out.selector).not.toBe('oldsel');
    expect(out.rotated_at).toBeTruthy();
    const op = h.audit.list().find((e) => e.operation === 'mail.dkim.rotate');
    expect(op?.['parameters']).toMatchObject({ previous_selector: 'oldsel' });
  });

  it('rejects malformed selectors and unknown domains', async () => {
    const h = harness();
    await expect(h.svc.enableDkim(SUPER, DOMAIN_ID, { selector: 'BAD SELECTOR' })).rejects.toThrow(BadRequestException);
    await expect(h.svc.enableDkim(SUPER, '01900000-0000-7000-8000-00000000dead', {})).rejects.toThrow(NotFoundException);
  });
});

describe('SPF/DMARC (B08)', () => {
  it('publishes the default SPF record and is idempotent', async () => {
    const h = harness();
    const out = await h.svc.applySpf(SUPER, DOMAIN_ID, {});
    expect(out.record).toBe('v=spf1 mx a ~all');
    expect(h.dns.addRecord).toHaveBeenCalledTimes(1);
    const again = await h.svc.applySpf(SUPER, DOMAIN_ID, { record: 'v=spf1 mx a ~all' });
    expect(again.record).toBe('v=spf1 mx a ~all');
    expect(h.dns.addRecord).toHaveBeenCalledTimes(1); // unchanged → no write
  });

  it('replaces an existing panel-written SPF record instead of duplicating it', async () => {
    const h = harness();
    await h.svc.applySpf(SUPER, DOMAIN_ID, { record: 'v=spf1 a ~all' });
    await h.svc.applySpf(SUPER, DOMAIN_ID, { record: 'v=spf1 mx a ~all' });
    expect(h.dns.updateRecord).toHaveBeenCalledTimes(1);
    expect(h.dns.addRecord).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed SPF and DMARC input before any node call', async () => {
    const h = harness();
    await expect(h.svc.applySpf(SUPER, DOMAIN_ID, { record: 'not-spf' })).rejects.toThrow(BadRequestException);
    await expect(h.svc.applyDmarc(SUPER, DOMAIN_ID, { policy: 'nuke' })).rejects.toThrow(BadRequestException);
    await expect(h.svc.applyDmarc(SUPER, DOMAIN_ID, { policy: 'reject', rua: 'not-an-email' })).rejects.toThrow(BadRequestException);
    expect(h.dns.addRecord).not.toHaveBeenCalled();
  });

  it('publishes DMARC at _dmarc with the chosen policy', async () => {
    const h = harness();
    const out = await h.svc.applyDmarc(SUPER, DOMAIN_ID, { policy: 'reject', rua: 'dmarc@example.com' });
    expect(out.record).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
    expect(h.dns.addRecord).toHaveBeenCalledWith(
      SUPER,
      ZONE_ID,
      expect.objectContaining({ name: '_dmarc.example.com', type: 'TXT' }),
    );
  });
});

describe('relay (B08, server-wide per ADR-0002)', () => {
  it('stores an encrypted profile and never returns credential material', async () => {
    const h = harness();
    const out = await h.svc.putRelay(SUPER, {
      provider: 'mailgun',
      smtp_host: 'smtp.mailgun.org',
      smtp_port: 587,
      username: 'postmaster',
      password: 'relay-secret',
    });
    expect(out.has_credentials).toBe(true);
    expect(JSON.stringify(out)).not.toContain('relay-secret');
    const stored = JSON.stringify(h.settings['mail.relay']);
    expect(stored).not.toContain('relay-secret');
    expect(stored).toContain('v1:');
    const ops = h.audit.list().filter((e) => e.operation === 'mail.relay.configure');
    expect(ops).toHaveLength(1);
  });

  it('keeps stored credentials when the password is blank (rotation-friendly)', async () => {
    const h = harness();
    await h.svc.putRelay(SUPER, { provider: 'ses', smtp_host: 'email-smtp.eu-west-1.amazonaws.com', smtp_port: 587, username: 'AKIA', password: 'first-secret' });
    await h.svc.putRelay(SUPER, { provider: 'ses', smtp_host: 'email-smtp.eu-west-1.amazonaws.com', smtp_port: 587, username: 'AKIA', password: '' });
    const stored = JSON.stringify(h.settings['mail.relay']);
    expect(stored).toContain('v1:');
  });

  it('rejects bad providers, hosts and ports before storing anything', async () => {
    const h = harness();
    await expect(h.svc.putRelay(SUPER, { provider: 'gmail', smtp_host: 'h', smtp_port: 587 })).rejects.toThrow(BadRequestException);
    await expect(h.svc.putRelay(SUPER, { provider: 'ses', smtp_host: 'bad host!', smtp_port: 587 })).rejects.toThrow(BadRequestException);
    await expect(h.svc.putRelay(SUPER, { provider: 'ses', smtp_host: 'ok.host', smtp_port: 99999 })).rejects.toThrow(BadRequestException);
    expect(h.settings['mail.relay']).toBeUndefined();
  });

  it('reads the empty state honestly and deletes cleanly', async () => {
    const h = harness();
    const empty = await h.svc.getRelay();
    expect(empty.is_active).toBe(false);
    await h.svc.deleteRelay(SUPER);
    const ops = h.audit.list().filter((e) => e.operation === 'mail.relay.remove');
    expect(ops).toHaveLength(1);
  });
});

describe('queue tools (B08, server-wide)', () => {
  it('lists the queue through the agent', async () => {
    const h = harness();
    const out = await h.svc.queueList();
    expect(out.total).toBe(1);
    expect(out.queue[0].queue_id).toBe('AB12CD34EF');
  });

  it('flushes and retries with audit entries, failures audited too', async () => {
    const h = harness();
    await h.svc.queueFlush(SUPER);
    await h.svc.queueRetry(SUPER, 'AB12CD34EF');
    expect(h.agent.mailQueueFlush).toHaveBeenCalledWith(undefined);
    expect(h.agent.mailQueueRetry).toHaveBeenCalledWith('AB12CD34EF');
    const ops = h.audit.list().filter((e) => e.operation.startsWith('mail.queue.'));
    expect(ops.map((o) => o['outcome'])).toEqual(['success', 'success']);

    h.agent.mailQueueFlush.mockRejectedValueOnce(new Error('agent down'));
    await expect(h.svc.queueFlush(SUPER)).rejects.toThrow('agent down');
    const failures = h.audit.list().filter((e) => e.operation === 'mail.queue.flush' && e['outcome'] === 'failure');
    expect(failures).toHaveLength(1);
  });
});
