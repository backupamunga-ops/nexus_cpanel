import { BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { ExtensionsService } from './extensions.service';
import { getSecretBox } from '../common/secretbox';
import { deriveExtToken } from './signature';

/**
 * Extension runtime tests (P7, ADR-0021). The exit criterion is the trust
 * ladder: an installed extension is INERT (no scopes, disabled) until the
 * scope review approves it; credentials are issued exactly once; heartbeats
 * fail the extension to `errored` and recover it.
 */

process.env.PANEL_SECRET_KEY =
  process.env.PANEL_SECRET_KEY || 'nexuspanel-test-secret-key-do-not-use-in-production';

const SUPER = { userId: 'u1', isSuperAdmin: true };

const VALID_MANIFEST = {
  name: 'Acme Backup Reporter',
  slug: 'acme-backup-reporter',
  version: '1.2.0',
  author: 'Acme Inc <support@acme.example>',
  nexuspanel_compat: { min: '1.0.0', max: '1.99.99' },
  types: ['integration', 'widget'],
  permissions: ['backup:read', 'account:read'],
  endpoints: {
    heartbeat: '/health',
    widgets: { 'backup-status': { slot: 'dashboard.main', entry: '/widgets/backup-status' } },
    hooks: { 'backup.completed': '/hooks/backup-completed' },
  },
};

function harness() {
  const audit = new InMemoryAuditService();
  const extensions: Array<Record<string, any>> = [];
  const registrations: Array<Record<string, any>> = [];
  const notifications: Array<Record<string, unknown>> = [];
  let extSeq = 1;

  const prisma: Record<string, any> = {
    extension: {
      create: jest.fn(async ({ data }: { data: any }) => {
        const row: Record<string, any> = {
          id: `ext-${extSeq++}`,
          installed_at: new Date(),
          last_error: null,
          ...data,
        };
        // the service queries extensions with
        // `include: { extension_registrations__extension_id: … }` — expose a
        // live view so later registration creates are visible to list/get/widgets
        Object.defineProperty(row, 'extension_registrations__extension_id', {
          get: () => registrations.filter((r) => r.extension_id === row.id && r.is_active),
        });
        extensions.push(row);
        return row;
      }),
      findUnique: jest.fn(async ({ where }: { where: { id?: string; slug?: string } }) =>
        extensions.find((e) => (where.id && e.id === where.id) || (where.slug && e.slug === where.slug)) ?? null,
      ),
      findMany: jest.fn(async ({ where }: { where?: { status?: string } } = {}) =>
        extensions.filter((e) => !where?.status || e.status === where.status),
      ),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: any }) => {
        const row = extensions.find((e) => e.id === where.id);
        if (!row) throw new Error('not found');
        return Object.assign(row, data);
      }),
      delete: jest.fn(async ({ where }: { where: { id: string } }) => {
        const i = extensions.findIndex((e) => e.id === where.id);
        if (i === -1) throw new Error('not found');
        const [row] = extensions.splice(i, 1);
        // cascade
        for (let r = registrations.length - 1; r >= 0; r--) {
          if (registrations[r].extension_id === where.id) registrations.splice(r, 1);
        }
        return row;
      }),
    },
    extensionRegistration: {
      create: jest.fn(async ({ data }: { data: any }) => {
        const row = {
          id: `reg-${registrations.length + 1}`,
          registered_at: new Date(),
          last_heartbeat_at: null,
          ...data,
          // the service queries registrations with `include: { extension: true }`
          extension: extensions.find((e) => e.id === data.extension_id),
        };
        registrations.push(row);
        return row;
      }),
      findFirst: jest.fn(async ({ where }: { where: { extension_id: string; is_active?: boolean } }) =>
        registrations.find((r) => r.extension_id === where.extension_id && r.is_active) ?? null,
      ),
      findMany: jest.fn(async () => registrations.filter((r) => r.is_active)),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: any }) => {
        const row = registrations.find((r) => r.id === where.id);
        if (!row) throw new Error('not found');
        return Object.assign(row, data);
      }),
    },
  };

  const notifier = {
    superAdminIds: jest.fn(async () => ['u-admin']),
    notify: jest.fn(async (input: Record<string, unknown>) => {
      notifications.push(input);
      return { id: 'n1' };
    }),
  };

  const service = new ExtensionsService(
    prisma as unknown as PrismaService,
    notifier as any,
    audit as any,
  );

  return { service, prisma, audit, extensions, registrations, notifications, notifier };
}

describe('extension manifest validation (install path)', () => {
  it('installs from a manifest URL as disabled with zero granted scopes', async () => {
    const h = harness();
    h.service.setFetchManifestFn(async () => VALID_MANIFEST);
    const res = await h.service.installFromUrl(SUPER, {
      manifest_url: 'https://acme.example/ext/nexuspanel-manifest.json',
    });
    expect(res.data.status).toBe('disabled');
    expect(res.data.granted_scopes).toEqual([]);
    expect(res.data.requested_scopes).toEqual(['backup:read', 'account:read']);
    expect(res.data.callback_url).toBe('https://acme.example');
    expect(h.audit.list().at(-1)?.operation).toBe('extension.install');
    expect(h.prisma.extension.create).toHaveBeenCalledTimes(1);
  });

  it('rejects a manifest with an unknown scope (closed list, fail-closed)', async () => {
    const h = harness();
    h.service.setFetchManifestFn(async () => ({
      ...VALID_MANIFEST,
      permissions: ['backup:read', 'password:read'],
    }));
    await expect(
      h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' }),
    ).rejects.toThrow(/password:read/);
    expect(h.prisma.extension.create).not.toHaveBeenCalled();
  });

  it('rejects a manifest whose compat window excludes this panel', async () => {
    const h = harness();
    h.service.setFetchManifestFn(async () => ({
      ...VALID_MANIFEST,
      nexuspanel_compat: { min: '2.0.0', max: '2.9.9' },
    }));
    await expect(
      h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' }),
    ).rejects.toThrow(/compat/);
  });

  it('rejects a bad slug and a non-semver version', async () => {
    const h = harness();
    h.service.setFetchManifestFn(async () => ({ ...VALID_MANIFEST, slug: 'Bad_Slug', version: '1.x' }));
    await expect(
      h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' }),
    ).rejects.toThrow(BadRequestException);
  });

  it('refuses a duplicate slug', async () => {
    const h = harness();
    h.service.setFetchManifestFn(async () => VALID_MANIFEST);
    await h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' });
    await expect(
      h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' }),
    ).rejects.toThrow(/already installed/);
  });
});

describe('scope review ladder', () => {
  async function installed(h: ReturnType<typeof harness>) {
    h.service.setFetchManifestFn(async () => VALID_MANIFEST);
    await h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' });
    return h.extensions[0];
  }

  it('approve grants the requested scopes, enables, and returns one-time credentials', async () => {
    const h = harness();
    const ext = await installed(h);
    const reg = h.registrations[0];
    const creds = await h.service.approve(SUPER, ext.id);
    expect(creds.extension_id).toBe(ext.id);
    expect(creds.shared_secret).toBeTruthy();
    // the shared secret round-trips: stored envelope decrypts to it
    const env = JSON.parse(
      getSecretBox().decrypt(Buffer.from(reg.shared_secret_enc).toString('utf8')),
    );
    expect(env.shared_secret).toBe(creds.shared_secret);
    // derived token is deterministic from the secret
    expect(creds.derived_token).toBe(deriveExtToken(creds.shared_secret));
    // scopes granted + enabled
    expect(ext.granted_scopes).toEqual(['backup:read', 'account:read']);
    expect(ext.status).toBe('enabled');
    expect(h.audit.list().at(-1)?.operation).toBe('extension.approve');
  });

  it('approve twice refuses to re-show credentials', async () => {
    const h = harness();
    const ext = await installed(h);
    await h.service.approve(SUPER, ext.id);
    await expect(h.service.approve(SUPER, ext.id)).rejects.toThrow(/cannot be re-shown/);
  });

  it('reject removes the extension entirely', async () => {
    const h = harness();
    const ext = await installed(h);
    await h.service.reject(SUPER, ext.id);
    expect(h.extensions).toHaveLength(0);
    expect(h.registrations).toHaveLength(0); // cascade
    expect(h.audit.list().at(-1)?.operation).toBe('extension.reject');
  });

  it('enable without approved scopes is refused (inert until review)', async () => {
    const h = harness();
    const ext = await installed(h);
    await expect(h.service.enable(SUPER, ext.id)).rejects.toThrow(/scope review/);
  });

  it('disable stops the extension; uninstall removes it', async () => {
    const h = harness();
    const ext = await installed(h);
    await h.service.approve(SUPER, ext.id);
    await h.service.disable(SUPER, ext.id);
    expect(ext.status).toBe('disabled');
    await h.service.uninstall(SUPER, ext.id);
    expect(h.extensions).toHaveLength(0);
    expect(h.audit.list().at(-1)?.operation).toBe('extension.uninstall');
  });

  it('non-admin callers get the anti-enumeration 404', async () => {
    const h = harness();
    await expect(h.service.list({ userId: 'u2', isSuperAdmin: false })).rejects.toThrow(NotFoundException);
    await expect(h.service.installFromUrl({ userId: 'u2', isSuperAdmin: false }, { manifest_url: 'https://x.example/m.json' })).rejects.toThrow(NotFoundException);
  });
});

describe('widget slots', () => {
  it('lists only enabled extensions with an active registration', async () => {
    const h = harness();
    h.service.setFetchManifestFn(async () => VALID_MANIFEST);
    const ext = await (async () => {
      await h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' });
      return h.extensions[0];
    })();
    // before approval: no widgets
    expect((await h.service.widgets()).data).toHaveLength(0);
    await h.service.approve(SUPER, ext.id);
    // registration needs a callback_url for the entry URL
    h.registrations[0].callback_url = 'https://acme.example';
    const w = (await h.service.widgets()).data;
    expect(w).toHaveLength(1);
    expect(w[0]).toMatchObject({
      slug: 'acme-backup-reporter',
      widget_id: 'backup-status',
      slot: 'dashboard.main',
      entry_url: 'https://acme.example/widgets/backup-status',
    });
  });
});

describe('heartbeats (spec §5.2: health every 60 s)', () => {
  async function enabledExt(h: ReturnType<typeof harness>) {
    h.service.setFetchManifestFn(async () => VALID_MANIFEST);
    await h.service.installFromUrl(SUPER, { manifest_url: 'https://acme.example/nexuspanel-manifest.json' });
    const ext = h.extensions[0];
    h.registrations[0].callback_url = 'https://acme.example';
    await h.service.approve(SUPER, ext.id);
    return ext;
  }

  it('a failing health check marks the extension errored and notifies admins once', async () => {
    const h = harness();
    const ext = await enabledExt(h);
    h.service.setHttpFn(async () => ({ ok: false, status: 503, body: 'down' }));
    await h.service.runHeartbeatsOnce();
    await h.service.runHeartbeatsOnce();
    expect(ext.status).toBe('errored');
    expect(ext.last_error).toContain('503');
    // notified ONCE despite two failures
    expect(h.notifications).toHaveLength(1);
    expect(h.audit.list().some((e) => e.operation === 'extension.heartbeat_failure')).toBe(true);
  });

  it('recovery flips the extension back to enabled', async () => {
    const h = harness();
    const ext = await enabledExt(h);
    h.service.setHttpFn(async () => ({ ok: false, status: 0, body: 'timeout' }));
    await h.service.runHeartbeatsOnce();
    expect(ext.status).toBe('errored');
    h.service.setHttpFn(async () => ({ ok: true, status: 200, body: '{"status":"ok"}' }));
    await h.service.runHeartbeatsOnce();
    expect(ext.status).toBe('enabled');
    expect(ext.last_error).toBeNull();
  });

  it('disabled extensions are not probed', async () => {
    const h = harness();
    const ext = await enabledExt(h);
    await h.service.disable(SUPER, ext.id);
    let probed = 0;
    h.service.setHttpFn(async () => {
      probed += 1;
      return { ok: true, status: 200, body: '{"status":"ok"}' };
    });
    await h.service.runHeartbeatsOnce();
    expect(probed).toBe(0);
  });
});
