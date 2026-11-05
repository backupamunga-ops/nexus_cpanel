import { ConflictException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { PasswordService } from './auth.service';
import { SecretBox } from './secret-box';
import { TwoFactorService, normalizeBackupCode } from './two-factor.service';
import { generateTotpSecret, totpAt } from './totp';

/**
 * C2 lifecycle: setup → verify (enable + backup codes) → login consumption
 * (TOTP replay guard, backup-code burn) → disable / regenerate with password
 * re-entry. SecretBox round-trips keep plaintext out of the database.
 */

const USER_ID = '01900000-0000-7000-8000-000000000001';
const EMAIL = 'admin@nexuspanel.dev';

/** The harness row is a loose record; consumeLoginCode expects the row shape. */
function asUser(row: Record<string, unknown>): Parameters<TwoFactorService['consumeLoginCode']>[0] {
  return row as unknown as Parameters<TwoFactorService['consumeLoginCode']>[0];
}

function harness(opts: { key?: Buffer | null; user?: Record<string, unknown> } = {}) {
  const audit = new InMemoryAuditService();
  const hasher = new PasswordService();
  const userRow: Record<string, unknown> = {
    id: USER_ID,
    email: EMAIL,
    password_hash: '',
    totp_secret_enc: null,
    totp_enabled_at: null,
    backup_codes_enc: null,
    preferences: {},
    ...opts.user,
  };
  const prisma = {
    user: {
      findUnique: jest.fn(async () => userRow),
      update: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        Object.assign(userRow, data);
        return userRow;
      }),
      updateMany: jest.fn(),
      upsert: jest.fn(),
    },
    userSession: { create: jest.fn(), update: jest.fn(), findUnique: jest.fn(), updateMany: jest.fn() },
  };
  const key = opts.key === undefined ? crypto.randomBytes(32) : opts.key; // null ⇒ unconfigured
  const box = new SecretBox(key);
  const svc = new TwoFactorService(prisma as unknown as PrismaService, box, hasher, audit);
  return { svc, prisma, audit, box, hasher, userRow };
}

describe('SecretBox (C9 seam)', () => {
  it('round-trips and produces unique ciphertext (random IV)', () => {
    const box = new SecretBox(crypto.randomBytes(32));
    const msg = Buffer.from('totp-secret-JBSWY3DPEHPK3PXP');
    const a = box.encrypt(msg);
    const b = box.encrypt(msg);
    expect(a.equals(b)).toBe(false);
    expect(box.decrypt(a).equals(msg)).toBe(true);
    expect(box.decrypt(b).equals(msg)).toBe(true);
  });

  it('rejects tampered ciphertext and wrong keys', () => {
    const box = new SecretBox(crypto.randomBytes(32));
    const env = box.encrypt(Buffer.from('secret'));
    env[env.length - 1]! ^= 0xff;
    expect(() => box.decrypt(env)).toThrow();

    const other = new SecretBox(crypto.randomBytes(32));
    const intact = box.encrypt(Buffer.from('secret'));
    expect(() => other.decrypt(intact)).toThrow();
  });

  it('refuses to operate without a configured key (fail loudly, never plaintext)', () => {
    const box = new SecretBox(null);
    expect(box.configured).toBe(false);
    expect(() => box.encrypt(Buffer.from('x'))).toThrow(/secrets key not configured/);
    expect(() => box.decrypt(Buffer.alloc(40))).toThrow(/secrets key not configured/);
  });

  it('validates key material length from env (32 bytes base64)', async () => {
    const prev = { ...process.env };
    process.env.CP_SECRETS_KEY = Buffer.alloc(32).toString('base64');
    expect(new SecretBox().configured).toBe(true);
    process.env.CP_SECRETS_KEY = Buffer.alloc(16).toString('base64');
    expect(() => new SecretBox()).toThrow(/exactly 32 bytes/);
    process.env = prev;
  });
});

describe('TwoFactorService (C2)', () => {
  let passwordHash: string;
  beforeAll(async () => {
    passwordHash = await new PasswordService().hash('correct horse battery staple');
  });

  it('setup stores an ENCRYPTED secret and returns it + otpauth uri once', async () => {
    const { svc, prisma, audit } = harness();
    const res = await svc.setup(USER_ID);

    expect(res.secret).toMatch(/^[A-Z2-7]+$/);
    expect(res.otpauth_uri).toContain(`totp/NexusPanel:${encodeURIComponent(EMAIL)}`);
    const written = prisma.user.update.mock.calls[0][0].data.totp_secret_enc as Uint8Array;
    expect(Buffer.from(written).toString('utf8')).not.toContain(res.secret); // ciphertext
    expect(JSON.stringify(prisma.user.update.mock.calls)).not.toContain(res.secret);
    expect(audit.list().at(-1)?.operation).toBe('auth.2fa.setup');
  });

  it('verifyEnrollment enables 2FA, mints 10 hashed+encrypted backup codes', async () => {
    const { svc, prisma, audit, userRow } = harness();
    const { secret } = await svc.setup(USER_ID);
    const code = totpAt(secret, Math.floor(Date.now() / 1000))!;

    const { backup_codes } = await svc.verifyEnrollment(USER_ID, code);
    expect(backup_codes).toHaveLength(10);
    for (const c of backup_codes) {
      expect(normalizeBackupCode(c)).toMatch(/^[A-HJ-NP-Z2-9]{16}$/);
    }

    expect(userRow.totp_enabled_at).toBeInstanceOf(Date);
    const enc = userRow.backup_codes_enc as Buffer;
    expect(enc.length).toBeGreaterThan(32);
    expect(enc.toString('utf8')).not.toContain(backup_codes[0]!);
    // The enrollment step is persisted immediately (replay-proof).
    expect((userRow.preferences as Record<string, number>).totp_last_step).toBeGreaterThan(0);
    expect(audit.list().at(-1)?.operation).toBe('auth.2fa.enabled');
  });

  it('verifyEnrollment rejects a wrong code (audited) and never enables', async () => {
    const { svc, audit, userRow } = harness();
    await svc.setup(USER_ID);
    await expect(svc.verifyEnrollment(USER_ID, '000000')).rejects.toThrow(UnauthorizedException);
    expect(userRow.totp_enabled_at).toBeNull();
    expect(audit.list().some((e) => e.operation === 'auth.2fa.verify' && e.outcome === 'failure')).toBe(true);
  });

  it('setup/verify refuse when 2FA is already enabled (409)', async () => {
    const { svc } = harness({ user: { totp_enabled_at: new Date() } });
    await expect(svc.setup(USER_ID)).rejects.toThrow(ConflictException);
    await expect(svc.verifyEnrollment(USER_ID, '123456')).rejects.toThrow(ConflictException);
  });

  it('service is unavailable without a configured key (503, fail closed)', async () => {
    const { svc } = harness({ key: null });
    await expect(svc.setup(USER_ID)).rejects.toThrow(ServiceUnavailableException);
    await expect(svc.verifyEnrollment(USER_ID, '123456')).rejects.toThrow(ServiceUnavailableException);
  });

  it('login consumption: valid TOTP → method totp + step; replay of that step fails', async () => {
    const { svc, userRow } = harness();
    const { secret } = await svc.setup(USER_ID);
    await svc.verifyEnrollment(USER_ID, totpAt(secret, Math.floor(Date.now() / 1000))!);

    const nowUnix = Math.floor(Date.now() / 1000);
    // Enrollment consumed the current step (persisted as totp_last_step), so
    // a login IN THE SAME 30s window would correctly be refused — use the
    // next step, exactly like a real login after enrollment.
    const code = totpAt(secret, nowUnix + 30)!;
    const consumed = await svc.consumeLoginCode(asUser(userRow), code);
    expect(consumed).toMatchObject({ ok: true, method: 'totp' });
    if (consumed.ok) expect(consumed.totpStep).toBe(Math.floor(nowUnix / 30) + 1);

    // Replay through a user row that already recorded the consumed step
    // (exactly what the successful login persists).
    expect(consumed.ok).toBe(true);
    const replay = await svc.consumeLoginCode(
      asUser({ ...userRow, preferences: { totp_last_step: consumed.ok ? consumed.totpStep : 0 } }),
      code,
    );
    expect(replay).toMatchObject({ ok: false, reason: 'totp_invalid' });
  });

  it('login consumption: backup code verifies once and burns (replay fails)', async () => {
    const { svc, userRow, box } = harness();
    const { secret } = await svc.setup(USER_ID);
    await svc.verifyEnrollment(USER_ID, totpAt(secret, Math.floor(Date.now() / 1000))!);
    const encBackup = userRow.backup_codes_enc as Buffer;
    const rowWith = { ...userRow, backup_codes_enc: encBackup };

    // Recover one plaintext code by re-generating is impossible — instead
    // exercise the burn path with a code we plant ourselves.
    const planted = 'ABCD-EFGH-JKLM-NPQR';
    const hashes = [await new PasswordService().hash(normalizeBackupCode(planted)!), 'x', 'y'];
    rowWith.backup_codes_enc = box.encrypt(Buffer.from(JSON.stringify(hashes)));
    const svc2 = new TwoFactorService(
      { user: { findUnique: async () => rowWith, update: async ({ data }: { data: Record<string, unknown> }) => { Object.assign(rowWith, data); return rowWith; } } } as unknown as PrismaService,
      box,
      new PasswordService(),
      new InMemoryAuditService(),
    );

    const used = await svc2.consumeLoginCode(asUser(rowWith), planted);
    expect(used).toMatchObject({ ok: true, method: 'backup_code' });
    // Burned: the stored set no longer contains the hash.
    const remaining = JSON.parse(
      box.decrypt(Buffer.from(rowWith.backup_codes_enc as Uint8Array)).toString('utf8'),
    ) as string[];
    expect(remaining).toHaveLength(2);

    const replay = await svc2.consumeLoginCode(asUser(rowWith), planted);
    expect(replay).toMatchObject({ ok: false, reason: 'backup_code_invalid' });
  });

  it('disable and regenerate require the account password', async () => {
    const { svc, userRow, audit } = harness({
      user: { password_hash: passwordHash, totp_enabled_at: new Date() },
    });
    await expect(svc.disable(USER_ID, 'wrong-password-123')).rejects.toThrow(UnauthorizedException);
    expect(userRow.totp_enabled_at).toBeInstanceOf(Date); // unchanged
    const fail = audit.list().at(-1)!;
    expect(fail.operation).toBe('auth.2fa.disable');
    expect(fail.outcome).toBe('failure');

    await expect(svc.regenerateBackupCodes(USER_ID, 'wrong-password-123')).rejects.toThrow(
      UnauthorizedException,
    );

    await svc.disable(USER_ID, 'correct horse battery staple');
    expect(userRow.totp_enabled_at).toBeNull();
    expect(userRow.totp_secret_enc).toBeNull();
    expect(userRow.backup_codes_enc).toBeNull();
  });

  it('regenerate replaces the whole backup set (old codes die)', async () => {
    const { svc, userRow, box } = harness({
      user: { password_hash: passwordHash, totp_enabled_at: new Date() },
    });
    const first = await svc.regenerateBackupCodes(USER_ID, 'correct horse battery staple');
    const second = await svc.regenerateBackupCodes(USER_ID, 'correct horse battery staple');
    expect(first.backup_codes).toHaveLength(10);
    expect(second.backup_codes).toHaveLength(10);
    expect(first.backup_codes.filter((c) => second.backup_codes.includes(c))).toHaveLength(0);
    const hashes = JSON.parse(
      box.decrypt(Buffer.from(userRow.backup_codes_enc as Uint8Array)).toString('utf8'),
    ) as string[];
    expect(hashes).toHaveLength(10);
  });
});
