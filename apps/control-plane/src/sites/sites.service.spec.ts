import { BadRequestException, ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { SitesService, renderVhost, Actor } from './sites.service';

/**
 * Sites & domains (API spec §4.7): ownership scoping (C7, 404-not-403),
 * agent-first provisioning, config_versions bookkeeping, and the strict
 * value allowlists that keep user input out of nginx directive positions.
 */

const SUPER: Actor = { userId: '01900000-0000-7000-8000-000000000001', isSuperAdmin: true };
const USER = '01900000-0000-7000-8000-0000000000aa';
const VIEWER: Actor = { userId: USER, isSuperAdmin: false };

const ACCOUNT = {
  id: '01900000-0000-7000-8000-00000000a001',
  username: 'alice',
  homedir: '/home/alice',
  status: 'active',
  package_id: 'pkg-1',
  package: { php_versions: ['8.2', '8.3'] },
};

function uid(n: number): string {
  return `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
}

function harness(opts: { accessRows?: Array<{ user_id: string; hosting_account_id: string; revoked_at: null }> } = {}) {
  const audit = new InMemoryAuditService();
  const domains: Record<string, unknown>[] = [];
  const subdomains: Record<string, unknown>[] = [];
  const aliases: Record<string, unknown>[] = [];
  const redirects: Record<string, unknown>[] = [];
  const versions: Record<string, unknown>[] = [];
  const accessRows = opts.accessRows ?? [];

  let idSeq = 100;
  const nextId = () => uid(++idSeq);

  const byId = (table: Record<string, unknown>[], id: string) =>
    table.find((r) => r['id'] === id && r['deleted_at'] === null) ?? null;

  /** Shallow-recursive where matcher covering every shape the service uses. */
  function matchesWhere(row: Record<string, unknown>, where: Record<string, unknown>): boolean {
    for (const [k, v] of Object.entries(where)) {
      if (v === null) {
        if (row[k] !== null) return false;
        continue;
      }
      if (typeof v === 'object') {
        const rel = v as Record<string, unknown>;
        if (
          k === 'hosting_account' &&
          rel['user_hosting_account_access__hosting_account_id'] !== undefined
        ) {
          const some = (
            rel['user_hosting_account_access__hosting_account_id'] as { some?: { user_id: string } }
          ).some;
          if (
            !accessRows.some(
              (a) => a.user_id === some?.user_id && a.hosting_account_id === row['hosting_account_id'],
            )
          ) {
            return false;
          }
          continue;
        }
        const nested = row[k];
        if (nested === undefined || nested === null || typeof nested !== 'object') return false;
        if (!matchesWhere(nested as Record<string, unknown>, rel)) return false;
        continue;
      }
      if (row[k] !== v) return false;
    }
    return true;
  }

  const first = (table: Record<string, unknown>[], where: Record<string, unknown>) =>
    table.find((r) => matchesWhere(r, where)) ?? null;

  const prisma = {
    domain: {
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        domains.filter((r) => matchesWhere(r, where)),
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        first(domains, where),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: nextId(), php_version: null, ...data, created_at: new Date(), updated_at: new Date() };
        domains.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = byId(domains, where.id);
        if (!row) throw new Error('not found');
        Object.assign(row, data);
        return row;
      }),
      updateMany: jest.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        for (const r of domains) {
          if (r['id'] === where['id'] || r['domain_id'] === where['domain_id']) Object.assign(r, data);
        }
        return { count: 0 };
      }),
    },
    subdomain: {
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        subdomains.filter((r) => matchesWhere(r, where)),
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        first(subdomains, where),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: nextId(), php_version: null, ...data, created_at: new Date(), deleted_at: null };
        subdomains.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = subdomains.find((r) => r['id'] === where.id);
        if (!row) throw new Error('not found');
        Object.assign(row, data);
        return row;
      }),
      updateMany: jest.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        let count = 0;
        for (const r of subdomains) {
          if (matchesWhere(r, where)) {
            Object.assign(r, data);
            count++;
          }
        }
        return { count };
      }),
    },
    domainAliase: {
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        aliases.filter((r) => matchesWhere(r, where)),
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        first(aliases, where),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: nextId(), ...data, created_at: new Date(), deleted_at: null };
        aliases.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = aliases.find((r) => r['id'] === where.id);
        if (!row) throw new Error('not found');
        Object.assign(row, data);
        return row;
      }),
      updateMany: jest.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        let count = 0;
        for (const r of aliases) {
          if (matchesWhere(r, where)) {
            Object.assign(r, data);
            count++;
          }
        }
        return { count };
      }),
    },
    redirect: {
      findMany: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        redirects.filter((r) => matchesWhere(r, where)),
      ),
      findFirst: jest.fn(async ({ where }: { where: Record<string, unknown> }) =>
        first(redirects, where),
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: nextId(), status_code: 301, is_wildcard: false, ...data, created_at: new Date(), deleted_at: null };
        redirects.push(row);
        return row;
      }),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = redirects.find((r) => r['id'] === where.id);
        if (!row) throw new Error('not found');
        Object.assign(row, data);
        return row;
      }),
      updateMany: jest.fn(async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        let count = 0;
        for (const r of redirects) {
          if (matchesWhere(r, where)) {
            Object.assign(r, data);
            count++;
          }
        }
        return { count };
      }),
    },
    hostingAccount: {
      findFirst: jest.fn(async ({ where }: { where: { id: string; deleted_at: null } }) =>
        where.id === ACCOUNT.id ? { ...ACCOUNT } : null,
      ),
    },
    package: {
      findFirst: jest.fn(async () => ({ php_versions: ['8.2', '8.3'] })),
    },
    userHostingAccountAccess: {
      findFirst: jest.fn(
        async ({ where }: { where: { user_id: string; hosting_account_id: string; revoked_at: null } }) =>
          accessRows.find(
            (a) => a.user_id === where.user_id && a.hosting_account_id === where.hosting_account_id,
          ) ?? null,
      ),
    },
    configVersion: {
      findFirst: jest.fn(
        async ({ where, orderBy }: { where: Record<string, unknown>; orderBy?: Record<string, string> }) => {
          const rows = versions
            .filter((v) => v['target_type'] === where['target_type'] && v['target_id'] === where['target_id'])
            .sort((a, b) => Number(b['version']) - Number(a['version']));
          return rows[0] ?? null;
        },
      ),
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: nextId(), ...data, created_at: new Date() };
        versions.push(row);
        return row;
      }),
      updateMany: jest.fn(
        async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
          for (const v of versions) {
            if (
              v['target_type'] === where['target_type'] &&
              v['target_id'] === where['target_id'] &&
              v['is_active'] === true
            ) {
              Object.assign(v, data);
            }
          }
          return { count: 0 };
        },
      ),
    },
    $transaction: jest.fn(async (fn: (tx: never) => Promise<unknown>): Promise<unknown> => fn(prisma as never)),
  };

  const agent = {
    filesystemMkdir: jest.fn(async (_username: string, _path: string, _mode?: number) => ({ path: '/x', created: true })),
    nginxApplyVhost: jest.fn(async (_domain: string, _content: string) => ({
      status: 'applied',
      health_check: 'skipped',
      previous_existed: false,
    })),
    nginxRemoveVhost: jest.fn(async (_domain: string) => ({ status: 'removed', health_check: 'skipped' })),
    nginxTest: jest.fn(async () => ({ status: 'skipped', detail: 'nginx binary not found on this node' })),
    filesystemRead: jest.fn(async (_username: string, path: string) => ({
      path,
      size_bytes: 0,
      content_b64: '',
      truncated: false,
    })),
  };

  const svc = new SitesService(
    prisma as unknown as PrismaService,
    agent as unknown as ConstructorParameters<typeof SitesService>[1],
    audit,
  );
  return { svc, prisma, agent, audit, domains, subdomains, aliases, redirects, versions, accessRows };
}

function seedDomain(h: ReturnType<typeof harness>, overrides: Record<string, unknown> = {}) {
  const row = {
    id: uid(10),
    hosting_account_id: ACCOUNT.id,
    name: 'example.com',
    type: 'primary',
    document_root: '/home/alice/domains/example.com/public_html',
    php_version: null,
    is_active: true,
    created_at: new Date(),
    updated_at: new Date(),
    deleted_at: null,
    hosting_account: { username: ACCOUNT.username },
    ...overrides,
  };
  h.domains.push(row);
  return row;
}

describe('renderVhost', () => {
  it('is deterministic and embeds server_name, docroot and redirects', () => {
    const a = renderVhost('example.com', '/home/a/www', ['mirror.example.org'], [
      { source_path: '/old', destination_url: 'https://example.net/new', status_code: 301, is_wildcard: false },
      { source_path: '/promo', destination_url: 'https://promo.example.net', status_code: 302, is_wildcard: true },
    ]);
    const b = renderVhost('example.com', '/home/a/www', ['mirror.example.org'], [
      { source_path: '/old', destination_url: 'https://example.net/new', status_code: 301, is_wildcard: false },
      { source_path: '/promo', destination_url: 'https://promo.example.net', status_code: 302, is_wildcard: true },
    ]);
    expect(a).toBe(b);
    expect(a).toContain('server_name example.com www.example.com mirror.example.org;');
    expect(a).toContain('root /home/a/www;');
    expect(a).toContain('access_log /home/a/logs/example.com.access.log;');
    expect(a).toContain('error_log /home/a/logs/example.com.error.log;');
    expect(a).toContain('location = /old {');
    expect(a).toContain('location ^~ /promo {');
    expect(a).toContain('return 301 https://example.net/new;');
  });

  it('refuses docroots outside /home/<username>/ (log paths would be unconstrained)', () => {
    expect(() => renderVhost('example.com', '/srv/www', [], [])).toThrow(BadRequestException);
  });
});

describe('site logs', () => {
  const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

  function seedLogAgent(h: ReturnType<typeof harness>, content: string) {
    h.agent.filesystemRead.mockResolvedValue({
      path: '/home/alice/logs/example.com.access.log',
      size_bytes: content.length,
      content_b64: b64(content),
      truncated: false,
    });
  }

  it('tails the access log with line capping and reports the full size', async () => {
    const h = harness();
    const d = seedDomain(h);
    const content = Array.from({ length: 350 }, (_, i) => `line ${i + 1}`).join('\n') + '\n';
    seedLogAgent(h, content);
    const out = await h.svc.logs(d.id, 'access', 100, SUPER);
    expect(out.exists).toBe(true);
    expect(out.total_lines).toBe(350);
    expect(out.lines).toHaveLength(100);
    expect(out.lines[0]).toBe('line 251');
    expect(out.lines[99]).toBe('line 350');
    expect(out.file).toBe('/home/alice/logs/example.com.access.log');
    expect(h.agent.filesystemRead).toHaveBeenCalledWith('alice', '/home/alice/logs/example.com.access.log');
  });

  it('clamps lines into 10..1000 and defaults the kind to access', async () => {
    const h = harness();
    const d = seedDomain(h);
    seedLogAgent(h, Array.from({ length: 2000 }, (_, i) => `l${i}`).join('\n'));
    const out = await h.svc.logs(d.id, undefined, '99999', SUPER);
    expect(out.kind).toBe('access');
    expect(out.lines).toHaveLength(1000);
  });

  it('answers exists:false when the log file does not exist yet', async () => {
    const h = harness();
    const d = seedDomain(h);
    h.agent.filesystemRead.mockRejectedValue(
      new ServiceUnavailableException('agent rejected filesystem.read: path does not exist (-32602)'),
    );
    const out = await h.svc.logs(d.id, 'error', undefined, SUPER);
    expect(out).toMatchObject({ exists: false, kind: 'error', total_lines: 0, lines: [] });
    expect(out.file).toBe('/home/alice/logs/example.com.error.log');
  });

  it('propagates agent failures that are not "missing file"', async () => {
    const h = harness();
    const d = seedDomain(h);
    h.agent.filesystemRead.mockRejectedValue(new ServiceUnavailableException('agent unreachable at /tmp/agent.sock'));
    await expect(h.svc.logs(d.id, 'access', undefined, SUPER)).rejects.toThrow(ServiceUnavailableException);
  });

  it('404s for a domain the caller cannot see (C7 anti-enumeration)', async () => {
    const h = harness();
    const d = seedDomain(h);
    await expect(h.svc.logs(d.id, 'access', undefined, VIEWER)).rejects.toThrow(NotFoundException);
    expect(h.agent.filesystemRead).not.toHaveBeenCalled();
  });
});

describe('domain create', () => {
  it('validates the FQDN, type and account id before any agent call', async () => {
    const h = harness();
    await expect(
      h.svc.create({ name: 'Not a Domain', hosting_account_id: ACCOUNT.id }, SUPER),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.create({ name: 'ok.example.com', type: 'wildcard', hosting_account_id: ACCOUNT.id }, SUPER),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.create({ name: 'ok.example.com', hosting_account_id: 'nope' }, SUPER),
    ).rejects.toThrow(BadRequestException);
    expect(h.agent.filesystemMkdir).not.toHaveBeenCalled();
  });

  it('404s when the account does not exist or the caller cannot see it', async () => {
    const h = harness();
    await expect(
      h.svc.create({ name: 'ok.example.com', hosting_account_id: uid(999) }, SUPER),
    ).rejects.toThrow(NotFoundException);
    await expect(
      h.svc.create({ name: 'ok.example.com', hosting_account_id: ACCOUNT.id }, VIEWER),
    ).rejects.toThrow(NotFoundException);
    expect(h.agent.nginxApplyVhost).not.toHaveBeenCalled();
  });

  it('provisions agent-first and writes v1 of the vhost history', async () => {
    const h = harness();
    const dto = await h.svc.create(
      { name: 'Example.COM', hosting_account_id: ACCOUNT.id, php_version: '8.3' },
      SUPER,
    );
    expect(dto.name).toBe('example.com');
    expect(dto.php_version).toBe('8.3');
    expect(dto.account_username).toBe('alice');
    expect(h.agent.filesystemMkdir).toHaveBeenCalledWith('alice', '/home/alice/domains/example.com/public_html', 0o755);
    expect(h.agent.nginxApplyVhost).toHaveBeenCalledTimes(1);
    expect(h.versions).toHaveLength(1);
    expect(h.versions[0]).toMatchObject({ target_type: 'nginx_vhost', version: 1, is_active: true });
  });

  it('rejects duplicate domains and docroot escapes without touching the agent', async () => {
    const h = harness();
    seedDomain(h);
    await expect(
      h.svc.create({ name: 'example.com', hosting_account_id: ACCOUNT.id }, SUPER),
    ).rejects.toThrow(ConflictException);
    await expect(
      h.svc.create(
        { name: 'other.com', hosting_account_id: ACCOUNT.id, document_root: '/etc/nginx' },
        SUPER,
      ),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.create(
        { name: 'other.com', hosting_account_id: ACCOUNT.id, document_root: '/home/alice/../etc' },
        SUPER,
      ),
    ).rejects.toThrow(BadRequestException);
    expect(h.agent.filesystemMkdir).not.toHaveBeenCalled();
  });

  it('rejects php versions outside the package allowlist', async () => {
    const h = harness();
    await expect(
      h.svc.create({ name: 'ok.example.com', hosting_account_id: ACCOUNT.id, php_version: '8.1' }, SUPER),
    ).rejects.toThrow(/not offered/);
  });

  it('audits agent failures and leaves no row', async () => {
    const h = harness();
    h.agent.nginxApplyVhost.mockRejectedValueOnce(new Error('agent unreachable'));
    await expect(
      h.svc.create({ name: 'ok.example.com', hosting_account_id: ACCOUNT.id }, SUPER),
    ).rejects.toThrow('agent unreachable');
    expect(h.domains).toHaveLength(0);
    expect(h.versions).toHaveLength(0);
    const ops = h.audit.list().filter((e) => e.operation === 'site.create');
    expect(ops).toHaveLength(1);
    expect(ops[0].outcome).toBe('failure');
  });
});

describe('visibility (C7)', () => {
  it('404s a domain the caller has no access row for', async () => {
    const h = harness();
    seedDomain(h);
    await expect(h.svc.get(uid(10), VIEWER)).rejects.toThrow(NotFoundException);
    await expect(h.svc.get(uid(10), SUPER)).resolves.toMatchObject({ name: 'example.com' });
  });

  it('shows the domain to a caller with an active access row', async () => {
    const h = harness({
      accessRows: [{ user_id: USER, hosting_account_id: ACCOUNT.id, revoked_at: null }],
    });
    seedDomain(h);
    await expect(h.svc.get(uid(10), VIEWER)).resolves.toMatchObject({ name: 'example.com' });
  });
});

describe('domain update', () => {
  it('re-applies the vhost when the docroot changes and bumps the version', async () => {
    const h = harness();
    seedDomain(h);
    await h.svc.update(uid(10), { document_root: '/home/alice/newroot' }, SUPER);
    expect(h.agent.filesystemMkdir).toHaveBeenCalledWith('alice', '/home/alice/newroot', 0o755);
    expect(h.agent.nginxApplyVhost).toHaveBeenCalledTimes(1);
    expect(h.domains[0]['document_root']).toBe('/home/alice/newroot');
    expect(h.versions).toHaveLength(1);
    expect(h.versions[0]['version']).toBe(1);
  });

  it('refuses docroots outside the account home', async () => {
    const h = harness();
    seedDomain(h);
    await expect(h.svc.update(uid(10), { document_root: '/var/www' }, SUPER)).rejects.toThrow(
      BadRequestException,
    );
    expect(h.agent.nginxApplyVhost).not.toHaveBeenCalled();
  });
});

describe('domain delete', () => {
  it('removes the vhost first, then soft-deletes domain and children', async () => {
    const h = harness();
    const d = seedDomain(h);
    h.subdomains.push({
      id: uid(20),
      domain_id: d['id'],
      name: 'blog',
      document_root: '/home/alice/subdomains/blog',
      php_version: null,
      created_at: new Date(),
      deleted_at: null,
    });
    h.aliases.push({ id: uid(21), domain_id: d['id'], alias_name: 'alias.com', created_at: new Date(), deleted_at: null });
    h.versions.push({ id: uid(22), target_type: 'nginx_vhost', target_id: d['id'], version: 1, content: 'x', is_active: true, created_at: new Date() });

    await h.svc.remove(uid(10), SUPER);
    expect(h.agent.nginxRemoveVhost).toHaveBeenCalledWith('example.com');
    expect(h.domains[0]['deleted_at']).not.toBeNull();
    expect(h.subdomains[0]['deleted_at']).not.toBeNull();
    expect(h.aliases[0]['deleted_at']).not.toBeNull();
    expect(h.versions[0]['is_active']).toBe(false);
  });
});

describe('subdomains', () => {
  it('validates the label, provisions agent-first and versions by subdomain id', async () => {
    const h = harness();
    const d = seedDomain(h);
    const dto = await h.svc.createSubdomain(d['id'], { name: 'Blog' }, SUPER);
    expect(dto.fqdn).toBe('blog.example.com');
    expect(dto.document_root).toBe('/home/alice/subdomains/blog');
    expect(h.agent.nginxApplyVhost).toHaveBeenCalledWith('blog.example.com', expect.any(String));
    expect(h.versions[0]['target_id']).toBe(dto.id);
  });

  it('rejects bad labels and duplicates', async () => {
    const h = harness();
    const d = seedDomain(h);
    await expect(h.svc.createSubdomain(d['id'], { name: 'not a label' }, SUPER)).rejects.toThrow(
      BadRequestException,
    );
    await h.svc.createSubdomain(d['id'], { name: 'blog' }, SUPER);
    await expect(h.svc.createSubdomain(d['id'], { name: 'blog' }, SUPER)).rejects.toThrow(
      ConflictException,
    );
  });
});

describe('aliases and redirects rewrite the parent vhost', () => {
  it('adding an alias re-applies the parent vhost and bumps its version', async () => {
    const h = harness();
    const d = seedDomain(h);
    await h.svc.createAlias(d['id'], { alias_name: 'Mirror.Example.org' }, SUPER);
    expect(h.agent.nginxApplyVhost).toHaveBeenCalledTimes(1);
    const content = h.agent.nginxApplyVhost.mock.calls[0][1] as string;
    expect(content).toContain('mirror.example.org');
    expect(h.versions[0]['version']).toBe(1);
    expect(h.aliases[0]['alias_name']).toBe('mirror.example.org');
  });

  it('rejects an alias another domain already uses', async () => {
    const h = harness();
    const d = seedDomain(h);
    h.aliases.push({
      id: uid(30),
      domain_id: uid(99),
      alias_name: 'taken.com',
      created_at: new Date(),
      deleted_at: null,
    });
    await expect(h.svc.createAlias(d['id'], { alias_name: 'taken.com' }, SUPER)).rejects.toThrow(
      ConflictException,
    );
  });

  it('validates redirect paths, urls and status codes', async () => {
    const h = harness();
    const d = seedDomain(h);
    await expect(
      h.svc.createRedirect(d['id'], { source_path: 'no-slash', destination_url: 'https://x.com' }, SUPER),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.createRedirect(d['id'], { source_path: '/a; return 302', destination_url: 'https://x.com' }, SUPER),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.createRedirect(d['id'], { source_path: '/a', destination_url: 'ftp://x.com' }, SUPER),
    ).rejects.toThrow(BadRequestException);
    await expect(
      h.svc.createRedirect(d['id'], { source_path: '/a', destination_url: 'https://x.com', status_code: 303 }, SUPER),
    ).rejects.toThrow(BadRequestException);
    expect(h.agent.nginxApplyVhost).not.toHaveBeenCalled();
  });

  it('creates a redirect and embeds it in the re-applied vhost', async () => {
    const h = harness();
    const d = seedDomain(h);
    const dto = await h.svc.createRedirect(
      d['id'],
      { source_path: '/old', destination_url: 'https://example.net/new', status_code: 308, is_wildcard: true },
      SUPER,
    );
    expect(dto.status_code).toBe(308);
    expect(dto.is_wildcard).toBe(true);
    const content = h.agent.nginxApplyVhost.mock.calls[0][1] as string;
    expect(content).toContain('location ^~ /old {');
    expect(content).toContain('return 308 https://example.net/new;');
  });
});

describe('serving status (live-VM finding #15)', () => {
  it('reports an nginx-less node as installed:false — a pre-install state, not an error', async () => {
    const h = harness();
    h.agent.nginxTest = jest.fn(async () => ({
      status: 'skipped',
      detail: 'nginx binary not found on this node',
    }));
    await expect(h.svc.servingStatus()).resolves.toEqual({
      installed: false,
      healthy: false,
      detail: 'nginx binary not found on this node',
    });
  });

  it('reports a passing nginx -t as installed and healthy', async () => {
    const h = harness();
    h.agent.nginxTest = jest.fn(async () => ({ status: 'passed', detail: 'syntax is ok' }));
    await expect(h.svc.servingStatus()).resolves.toEqual({
      installed: true,
      healthy: true,
      detail: 'syntax is ok',
    });
  });

  it('maps a failing nginx -t to unhealthy instead of hiding behind a 503', async () => {
    const h = harness();
    h.agent.nginxTest = jest.fn(async () => {
      throw new ServiceUnavailableException(
        'agent rejected nginx.test: nginx config test failed: emerg directive (-32001)',
      );
    });
    const s = await h.svc.servingStatus();
    expect(s.installed).toBe(true);
    expect(s.healthy).toBe(false);
    expect(s.detail).toContain('nginx config test failed');
  });

  it('rethrows agent-unreachable errors — the banner must not fake a status', async () => {
    const h = harness();
    h.agent.nginxTest = jest.fn(async () => {
      throw new ServiceUnavailableException('agent unreachable: no such file or directory');
    });
    await expect(h.svc.servingStatus()).rejects.toThrow(ServiceUnavailableException);
  });
});

describe('panel hostname reservation (live-VM finding #16, ADR-0024)', () => {
  // conf.d (agent site vhosts) loads before sites-enabled (panel origin), so a
  // site on the panel hostname would shadow the panel itself — refused, with
  // zero agent writes, on every path that can claim a hostname.
  const PANEL = 'server.example.com';
  const withPanelEnv = (run: () => Promise<unknown>): Promise<unknown> => {
    process.env.PANEL_PUBLIC_HOSTNAME = PANEL;
    return run().finally(() => {
      delete process.env.PANEL_PUBLIC_HOSTNAME;
    });
  };

  it('refuses a site on the panel hostname — 409, zero agent writes', async () => {
    await withPanelEnv(async () => {
      const h = harness();
      await expect(
        h.svc.create({ name: PANEL, hosting_account_id: ACCOUNT.id, php_version: '8.3' }, SUPER),
      ).rejects.toThrow(ConflictException);
      expect(h.agent.filesystemMkdir).not.toHaveBeenCalled();
      expect(h.agent.nginxApplyVhost).not.toHaveBeenCalled();
    });
  });

  it('refuses a subdomain that resolves to the panel hostname (apex site + label)', async () => {
    await withPanelEnv(async () => {
      const h = harness();
      const d = seedDomain(h); // example.com
      await expect(
        h.svc.createSubdomain(d['id'], { name: 'server' }, SUPER),
      ).rejects.toThrow(ConflictException);
      expect(h.agent.filesystemMkdir).not.toHaveBeenCalled();
      expect(h.agent.nginxApplyVhost).not.toHaveBeenCalled();
    });
  });

  it('refuses an alias on the panel hostname', async () => {
    await withPanelEnv(async () => {
      const h = harness();
      const d = seedDomain(h);
      await expect(
        h.svc.createAlias(d['id'], { alias_name: PANEL }, SUPER),
      ).rejects.toThrow(ConflictException);
      expect(h.agent.nginxApplyVhost).not.toHaveBeenCalled();
    });
  });

  it('reserves nothing when PANEL_PUBLIC_HOSTNAME is unset (loopback-only dev node)', async () => {
    delete process.env.PANEL_PUBLIC_HOSTNAME;
    const h = harness();
    const dto = await h.svc.create(
      { name: PANEL, hosting_account_id: ACCOUNT.id, php_version: '8.3' },
      SUPER,
    );
    expect(dto.name).toBe(PANEL);
    expect(h.agent.nginxApplyVhost).toHaveBeenCalledTimes(1);
  });
});
