import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { SecretBox } from '../common/secretbox';
import { SslService } from './ssl.service';

/**
 * SSL service: encrypted-at-rest storage contract (ADR-0009), metadata-only
 * responses, issue/renew/revoke lifecycle, and visibility scoping.
 */

// The service uses the env-backed singleton; tests set the env before any
// call and derive the verification box from the SAME key.
process.env.PANEL_SECRET_KEY =
  'nexuspanel-ssl-spec-key-0123456789abcdef0123456789abcdef';

const SUPER = { userId: 'u-admin', isSuperAdmin: true };

const ACCOUNT = { id: '01900000-0000-7000-8000-00000000a001', username: 'alice' };
const DOMAIN = {
  id: '01900000-0000-7000-8000-00000000d001',
  hosting_account_id: ACCOUNT.id,
  name: 'example.com',
  document_root: '/home/alice/domains/example.com/public_html',
  deleted_at: null,
};

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

function harness(opts: { access?: boolean } = {}) {
  const audit = new InMemoryAuditService();
  const certs: Record<string, unknown>[] = [];
  const box = new SecretBox(process.env.PANEL_SECRET_KEY as string);
  const prisma = {
    domain: {
      findFirst: jest.fn(async ({ where }: { where: { id: string } }) =>
        where.id === DOMAIN.id ? { ...DOMAIN } : null,
      ),
    },
    hostingAccount: {
      findFirst: jest.fn(async () => ({ username: ACCOUNT.username })),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(async () => (opts.access ? { id: 'row' } : null)),
    },
    user: {
      findFirst: jest.fn(async () => ({ email: 'admin@example.com' })),
    },
    certificate: {
      findFirst: jest.fn(async ({ where, orderBy }: { where: Record<string, unknown>; orderBy?: unknown }) =>
        certs.find((c) => c['domain_id'] === where['domain_id'] || c['id'] === where['id']) ?? null,
      ),
      findMany: jest.fn(async () =>
        certs.map((c) => ({ ...c, domain: { name: DOMAIN.name, hosting_account_id: ACCOUNT.id, deleted_at: null } })),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = {
          id: uid(certs.length + 80),
          last_renewed_at: null,
          auto_renew: true,
          created_at: new Date(),
          san_names: [],
          ...data,
        };
        certs.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = certs.find((c) => c['id'] === where.id);
        Object.assign(row!, data);
        return row;
      }),
      delete: jest.fn(async ({ where }: { where: { id: string } }) => {
        const i = certs.findIndex((c) => c['id'] === where.id);
        const [row] = certs.splice(i, 1);
        return row;
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>): Promise<unknown> => fn(prisma)),
  };
  const agent = {
    sslIssueAcme: jest.fn(async () => ({
      domain: DOMAIN.name,
      issuer: 'letsencrypt',
      san_names: ['example.com'],
      expires_at: new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString(),
      cert_pem: '-----BEGIN CERTIFICATE-----TEST-----END CERTIFICATE-----',
      key_pem: '-----BEGIN EC PRIVATE KEY-----TEST-----END EC PRIVATE KEY-----',
    })),
    sslInstallCert: jest.fn(async () => ({
      domain: DOMAIN.name,
      issuer: 'Test Org',
      san_names: ['example.com'],
      expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
      common_name: 'example.com',
      health_check: 'passed',
    })),
    sslRevoke: jest.fn(async () => ({ status: 'revoked', existed: true })),
  };
  const svc = new SslService(
    prisma as unknown as PrismaService,
    agent as unknown as ConstructorParameters<typeof SslService>[1],
    audit,
  );
  return { svc, certs, agent, audit, box };
}

describe('ssl issue (ACME)', () => {
  it('requires a valid email', async () => {
    const h = harness();
    await expect(h.svc.issue(DOMAIN.id, { email: 'nope' }, SUPER)).rejects.toThrow(BadRequestException);
    expect(h.agent.sslIssueAcme).not.toHaveBeenCalled();
  });

  it('issues, stores ENCRYPTED material, exposes metadata only', async () => {
    const h = harness();
    const dto = await h.svc.issue(DOMAIN.id, { email: 'ops@example.com' }, SUPER);
    expect(dto.issuer).toBe('letsencrypt');
    expect(h.certs).toHaveLength(1);

    const row = h.certs[0];
    const certEnc = Buffer.from(row['cert_pem_enc'] as Uint8Array).toString('utf8');
    const keyEnc = Buffer.from(row['key_pem_enc'] as Uint8Array).toString('utf8');
    expect(certEnc).toMatch(/^v1:/);
    expect(keyEnc).toMatch(/^v1:/);
    // The stored envelope must not contain the plaintext PEM.
    expect(certEnc).not.toContain('BEGIN CERTIFICATE');
    // And it decrypts back to the exact material the agent returned.
    expect(h.box.decrypt(certEnc)).toContain('BEGIN CERTIFICATE');
    expect(h.box.decrypt(keyEnc)).toContain('BEGIN EC PRIVATE KEY');

    // The DTO carries no PEM material.
    expect(JSON.stringify(dto)).not.toContain('BEGIN CERTIFICATE');
  });

  it('refuses a second certificate while one exists', async () => {
    const h = harness();
    await h.svc.issue(DOMAIN.id, { email: 'ops@example.com' }, SUPER);
    await expect(h.svc.issue(DOMAIN.id, { email: 'ops@example.com' }, SUPER)).rejects.toThrow(
      ConflictException,
    );
  });

  it('audits agent failures and stores nothing', async () => {
    const h = harness();
    h.agent.sslIssueAcme.mockRejectedValueOnce(new Error('acme: order invalid'));
    await expect(h.svc.issue(DOMAIN.id, { email: 'ops@example.com' }, SUPER)).rejects.toThrow(
      'order invalid',
    );
    expect(h.certs).toHaveLength(0);
    const ops = h.audit.list().filter((e) => e.operation === 'ssl.issue');
    expect(ops).toHaveLength(1);
    expect(ops[0].outcome).toBe('failure');
  });
});

describe('ssl renew / revoke / manual install', () => {
  it('renews ACME certs and updates the encrypted material + last_renewed_at', async () => {
    const h = harness();
    await h.svc.issue(DOMAIN.id, { email: 'ops@example.com' }, SUPER);
    const dto = await h.svc.renew(DOMAIN.id, SUPER);
    expect(dto.last_renewed_at).not.toBeNull();
    expect(h.agent.sslIssueAcme).toHaveBeenCalledTimes(2);
  });

  it('manual certs refuse renewal via ACME (reinstall instead)', async () => {
    const h = harness();
    await h.svc.installManual(
      { domain_id: DOMAIN.id, cert_pem: '-----BEGIN CERTIFICATE-----X', key_pem: '-----BEGIN EC PRIVATE KEY-----X' },
      SUPER,
    );
    await expect(h.svc.renew(DOMAIN.id, SUPER)).rejects.toThrow(/manual certificates/);
  });

  it('revokes: node files removed, row deleted, audited', async () => {
    const h = harness();
    await h.svc.issue(DOMAIN.id, { email: 'ops@example.com' }, SUPER);
    await h.svc.revoke(DOMAIN.id, SUPER);
    expect(h.agent.sslRevoke).toHaveBeenCalledWith(DOMAIN.name);
    expect(h.certs).toHaveLength(0);
    await expect(h.svc.revoke(DOMAIN.id, SUPER)).rejects.toThrow(NotFoundException);
  });

  it('visibility: 404 for domains outside the caller\u2019s scope', async () => {
    const h = harness();
    await expect(h.svc.issue(DOMAIN.id, { email: 'ops@example.com' }, { userId: 'u2', isSuperAdmin: false })).rejects.toThrow(
      NotFoundException,
    );
  });
});
