import { BadRequestException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { SettingsService } from './settings.service';
import { SETTING_DEFINITIONS, validateSettingValue } from './settings.config';

/**
 * Server settings (P2): whitelist overlay on system_settings, fail-closed
 * validation, transactional audit. The prisma seam is a plain object with a
 * real key/value map; the audit seam is the real in-memory hash chain.
 */

function rowHarness(rows: Record<string, unknown>[] = []) {
  const audit = new InMemoryAuditService();
  const table = new Map<string, Record<string, unknown>>();
  for (const r of rows) table.set(r['key'] as string, { ...r });

  const prisma = {
    systemSetting: {
      findMany: jest.fn(async () => [...table.values()]),
      findUnique: jest.fn(async ({ where }: { where: { key: string } }) => table.get(where.key) ?? null),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>) =>
      fn({
        systemSetting: {
          upsert: jest.fn(
            async ({
              where,
              create,
              update,
            }: {
              where: { key: string };
              create: Record<string, unknown>;
              update: Record<string, unknown>;
            }) => {
              const existing = table.get(where.key);
              const row = existing
                ? Object.assign(existing, update)
                : Object.assign(
                    {
                      key: where.key,
                      updated_at: new Date(),
                    },
                    create,
                  );
              table.set(where.key, row);
              return row;
            },
          ),
        },
      }),
    ),
  };
  const svc = new SettingsService(prisma as unknown as PrismaService, audit);
  return { svc, prisma, audit, table };
}

const ADMIN = '01900000-0000-7000-8000-000000000001';

describe('setting value validation (settings.config)', () => {
  const def = (key: string) => {
    const d = SETTING_DEFINITIONS.find((x) => x.key === key);
    if (!d) throw new Error(`missing definition ${key}`);
    return d;
  };

  it('booleans are strict', () => {
    expect(validateSettingValue(def('security.totp_required'), true)).toBe(true);
    expect(() => validateSettingValue(def('security.totp_required'), 'yes')).toThrow(/boolean/);
    expect(() => validateSettingValue(def('security.totp_required'), 1)).toThrow(/boolean/);
  });

  it('integers respect bounds and reject non-integers', () => {
    expect(validateSettingValue(def('security.max_failed_logins'), 5)).toBe(5);
    expect(() => validateSettingValue(def('security.max_failed_logins'), 2)).toThrow(/at least 3/);
    expect(() => validateSettingValue(def('security.max_failed_logins'), 11)).toThrow(/at most 10/);
    expect(() => validateSettingValue(def('security.max_failed_logins'), 4.5)).toThrow(/integer/);
    expect(() => validateSettingValue(def('security.max_failed_logins'), '5')).toThrow(/integer/);
    expect(validateSettingValue(def('audit.retention_days'), 3650)).toBe(3650);
  });

  it('strings are trimmed and length-bounded', () => {
    expect(validateSettingValue(def('platform.instance_name'), '  Ops Panel ')).toBe('Ops Panel');
    expect(() => validateSettingValue(def('platform.instance_name'), '   ')).toThrow(/at least 1/);
    expect(() => validateSettingValue(def('platform.instance_name'), 'x'.repeat(65))).toThrow(/at most 64/);
    expect(() => validateSettingValue(def('platform.instance_name'), 42)).toThrow(/must be a string/);
    expect(validateSettingValue(def('platform.login_notice'), '')).toBe('');
  });
});

describe('SettingsService (server settings, P2)', () => {
  it('lists every catalog key with defaults when nothing is stored', async () => {
    const { svc } = rowHarness();
    const { data } = await svc.list();
    expect(data.map((s) => s.key)).toEqual(SETTING_DEFINITIONS.map((d) => d.key));
    for (const s of data) {
      expect(s.value).toBe(s.default);
      expect(s.updated_at).toBeNull();
    }
  });

  it('stored rows override defaults and carry updated_at', async () => {
    const { svc } = rowHarness([
      { key: 'security.lockout_minutes', value: 30, updated_by: ADMIN, updated_at: new Date('2026-01-01T00:00:00Z') },
    ]);
    const { data } = await svc.list();
    const lockout = data.find((s) => s.key === 'security.lockout_minutes');
    expect(lockout?.value).toBe(30);
    expect(lockout?.updated_at).toBe('2026-01-01T00:00:00.000Z');
    expect(lockout?.updated_by).toBe(ADMIN);
    const untouched = data.find((s) => s.key === 'security.session_ttl_days');
    expect(untouched?.value).toBe(7);
  });

  it('reads one key: default when absent, 404 when unknown', async () => {
    const { svc } = rowHarness();
    expect((await svc.get('security.password_min_length')).value).toBe(12);
    await expect(svc.get('security.nope')).rejects.toThrow(NotFoundException);
  });

  it('refuses writes to unknown keys (fail-closed, no row created)', async () => {
    const { svc, table } = rowHarness();
    await expect(
      svc.update('security.lockout_minuts', 30, ADMIN),
    ).rejects.toThrow(BadRequestException);
    expect(table.size).toBe(0);
  });

  it('requires a value and enforces type/bounds', async () => {
    const { svc } = rowHarness();
    await expect(svc.update('security.lockout_minutes', undefined, ADMIN)).rejects.toThrow(
      /value is required/,
    );
    await expect(svc.update('security.lockout_minutes', 3, ADMIN)).rejects.toThrow(/at least 5/);
    await expect(svc.update('security.lockout_minutes', '15', ADMIN)).rejects.toThrow(/integer/);
    await expect(svc.update('platform.instance_name', null, ADMIN)).rejects.toThrow(
      BadRequestException,
    );
  });

  it('stores a valid update and audits from → to inside the transaction', async () => {
    const { svc, audit, table } = rowHarness();
    const dto = await svc.update('security.lockout_minutes', 30, ADMIN);
    expect(dto.value).toBe(30);
    expect(dto.updated_by).toBe(ADMIN);
    expect(table.get('security.lockout_minutes')?.['value']).toBe(30);

    const entry = audit.list().at(-1);
    expect(entry?.operation).toBe('settings.update');
    expect(entry?.parameters).toMatchObject({ key: 'security.lockout_minutes', from: 15, to: 30 });
    expect(entry?.actorUserId).toBe(ADMIN);
  });

  it('audits the default as "from" on first override and normalizes strings', async () => {
    const { svc, audit } = rowHarness();
    await svc.update('platform.instance_name', '  Billu Host  ', ADMIN);
    const entry = audit.list().at(-1);
    expect(entry?.parameters).toMatchObject({
      key: 'platform.instance_name',
      from: 'NexusPanel',
      to: 'Billu Host',
    });
    const dto = await svc.get('platform.instance_name');
    expect(dto.value).toBe('Billu Host');
    expect(dto.enforced).toBe(false);
  });
});

describe('SettingsService.runtimeInt (D-11 runtime seam)', () => {
  it('stored override wins, absent row falls back to the catalog default', async () => {
    const { svc } = rowHarness([
      { key: 'security.max_failed_logins', value: 7, updated_by: ADMIN, updated_at: new Date() },
    ]);
    expect(await svc.runtimeInt('security.max_failed_logins')).toBe(7);
    expect(await svc.runtimeInt('security.lockout_minutes')).toBe(15); // default
  });

  it('any read failure falls back to the default (login path must not throw)', async () => {
    const { svc, prisma } = rowHarness();
    (prisma.systemSetting.findUnique as jest.Mock).mockRejectedValue(new Error('db down'));
    expect(await svc.runtimeInt('security.session_ttl_days')).toBe(7);
  });

  it('a malformed stored value falls back to the default instead of leaking junk', async () => {
    const { svc } = rowHarness([
      { key: 'security.password_min_length', value: '12', updated_by: ADMIN, updated_at: new Date() }, // wrong type
    ]);
    expect(await svc.runtimeInt('security.password_min_length')).toBe(12);
  });

  it('rejects non-integer keys loudly (programming error, not a silent no-op)', async () => {
    const { svc } = rowHarness();
    await expect(svc.runtimeInt('platform.instance_name')).rejects.toThrow(TypeError);
    await expect(svc.runtimeInt('security.nope')).rejects.toThrow(TypeError);
  });
});
