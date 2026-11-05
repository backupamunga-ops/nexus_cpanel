import { NotFoundException, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { ARGON2ID_PARAMS, AuthService, PasswordService } from './auth.service';
import { JwtService } from './jwt.service';
import { SecretBox } from './secret-box';
import { TwoFactorService } from './two-factor.service';
import { hashRefreshToken } from './refresh-token';
import { totpAt, generateTotpSecret } from './totp';

/* ─────────────────────────── C1 — password hashing ─────────────────────────── */

describe('PasswordService (C1 Argon2id)', () => {
  const hasher = new PasswordService();

  it('produces an Argon2id PHC hash with the C1 parameters', async () => {
    const h = await hasher.hash('correct horse battery staple');
    expect(h.startsWith('$argon2id$')).toBe(true);
    expect(h).toContain(`m=${ARGON2ID_PARAMS.memoryCost}`);
    expect(h).toContain(`t=${ARGON2ID_PARAMS.timeCost}`);
    expect(h).toContain(`p=${ARGON2ID_PARAMS.parallelism}`);
  });

  it('verifies the correct password and rejects a wrong one', async () => {
    const h = await hasher.hash('correct horse battery staple');
    await expect(hasher.verify('correct horse battery staple', h)).resolves.toBe(true);
    await expect(hasher.verify('wrong horse battery staple', h)).resolves.toBe(false);
  });

  it('salts: two hashes of the same password differ', async () => {
    const a = await hasher.hash('correct horse battery staple');
    const b = await hasher.hash('correct horse battery staple');
    expect(a).not.toBe(b);
  });

  it('enforces the 12-character policy (C1)', async () => {
    await expect(hasher.hash('short12passx')).resolves.toBeDefined();
    await expect(hasher.hash('short11pass')).rejects.toThrow('password policy');
  });

  it('still verifies legacy dev scrypt hashes (verify-only)', async () => {
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync('legacy-dev-password', salt, 32, {
      N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024,
    });
    const legacy = `scrypt$${2 ** 17}$8$1$${salt.toString('hex')}$${key.toString('hex')}`;
    await expect(hasher.verify('legacy-dev-password', legacy)).resolves.toBe(true);
    await expect(hasher.verify('not-the-password', legacy)).resolves.toBe(false);
  });

  it('returns false for unknown hash formats instead of throwing', async () => {
    await expect(hasher.verify('x', '$bcrypt$whatever')).resolves.toBe(false);
    await expect(hasher.verify('x', 'garbage')).resolves.toBe(false);
  });
});

/* ─────────────────────── C3 — login / refresh / lockout ─────────────────────── */

const USER_ID = '01900000-0000-7000-8000-000000000001';
const SESSION_ID = '01900000-0000-7000-8000-00000000ffff';
const EMAIL = 'admin@nexuspanel.dev';
const PASSWORD = 'correct horse battery staple';

function fakeUser(overrides: Record<string, unknown> = {}) {
  return {
    id: USER_ID,
    email: EMAIL,
    password_hash: '',
    display_name: 'Dev Admin',
    is_active: true,
    is_super_admin: true,
    email_verified_at: null,
    totp_secret_enc: null,
    totp_enabled_at: null,
    backup_codes_enc: null,
    failed_login_count: 0,
    locked_until: null,
    last_login_at: null,
    last_login_ip: null,
    preferences: {},
    created_at: new Date(),
    updated_at: new Date(),
    deleted_at: null,
    ...overrides,
  };
}

function fakeSession(refreshToken: string, user: object, overrides: Record<string, unknown> = {}) {
  return {
    id: SESSION_ID,
    user_id: USER_ID,
    refresh_token_hash: hashRefreshToken(refreshToken),
    device_fingerprint: 'fp-A',
    ip: null,
    user_agent: 'jest',
    created_at: new Date(),
    last_used_at: new Date(),
    expires_at: new Date(Date.now() + 7 * 24 * 3600 * 1000),
    revoked_at: null,
    user,
    ...overrides,
  };
}

interface PrismaMock {
  user: {
    findUnique: jest.Mock;
    update: jest.Mock;
    upsert: jest.Mock;
  };
  userSession: {
    create: jest.Mock;
    update: jest.Mock;
    findUnique: jest.Mock;
    findMany: jest.Mock;
    updateMany: jest.Mock;
  };
  reseller: {
    findMany: jest.Mock;
  };
}

async function makeAuth(user: object | null) {
  const prisma: PrismaMock = {
    user: { findUnique: jest.fn().mockResolvedValue(user), update: jest.fn(), upsert: jest.fn() },
    userSession: {
      create: jest.fn().mockImplementation(({ data }) => Promise.resolve({ id: SESSION_ID, ...data })),
      update: jest.fn(),
      findUnique: jest.fn(),
      findMany: jest.fn().mockResolvedValue([]),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    // C14: active reseller custom domains; empty by default = no branded
    // origins, every host is panel-kind (the C3 suites' behavior).
    reseller: { findMany: jest.fn().mockResolvedValue([]) },
  };
  const audit = new InMemoryAuditService();
  const jwt = new JwtService('unit-test-secret-0123456789abcdefghijklmnop');
  // 2FA with a test-key SecretBox + the same prisma mock (user rows flow
  // through consumeLoginCode for enrolled users).
  const box = new SecretBox(crypto.randomBytes(32));
  const hasher = new PasswordService();
  const twoFactor = new TwoFactorService(prisma as unknown as PrismaService, box, hasher, audit);
  const auth = new AuthService(prisma as unknown as PrismaService, jwt, audit, twoFactor);
  await auth.whenBootstrapSeeded();
  return { auth, prisma, audit, jwt, box, twoFactor };
}

describe('AuthService (C3 login + sessions)', () => {
  const ORIGINAL_ENV = { ...process.env };
  let passwordHash: string;

  beforeAll(async () => {
    passwordHash = await new PasswordService().hash(PASSWORD);
  });

  beforeEach(() => {
    delete process.env.DEV_ADMIN_EMAIL;
    delete process.env.DEV_ADMIN_PASSWORD;
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('logs in with valid credentials and returns a verifiable 15-minute JWT', async () => {
    const { auth, prisma, jwt } = await makeAuth(fakeUser({ password_hash: passwordHash }));

    const res = await auth.login(EMAIL, PASSWORD, { ip: '10.0.0.9', deviceFingerprint: 'fp-A' });

    expect(res.token_type).toBe('jwt');
    expect(res.expires_in).toBe(900);
    expect(res.user).toMatchObject({ id: USER_ID, email: EMAIL, is_super_admin: true });

    const claims = jwt.verify(res.access_token);
    expect(claims).not.toBeNull();
    expect(claims!.sub).toBe(USER_ID);
    const createdSessionId = prisma.userSession.create.mock.calls[0][0].data.id;
    expect(claims!.sid).toBe(createdSessionId);
    expect(claims!.fp).toBe('fp-A');
    expect(claims!.exp! - claims!.iat!).toBe(900);

    expect(prisma.user.update).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: USER_ID }, data: expect.objectContaining({ failed_login_count: 0, locked_until: null }) }),
    );
    expect(prisma.userSession.create).toHaveBeenCalledTimes(1);
  });

  it('normalizes the email and stores only a SHA-256 of the refresh token', async () => {
    const { auth, prisma } = await makeAuth(fakeUser({ password_hash: passwordHash }));

    const res = await auth.login(`  ${EMAIL.toUpperCase()} `, PASSWORD, {});
    expect(res.refresh_token).toMatch(/^nxf1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]+$/);
    const created = prisma.userSession.create.mock.calls[0][0].data;
    expect(created.refresh_token_hash).toBeInstanceOf(Uint8Array);
    expect(created.refresh_token_hash.byteLength).toBe(32);
    expect(JSON.stringify(created)).not.toContain(res.refresh_token);
  });

  it('rejects a wrong password, counts the failure, and audits it', async () => {
    const { auth, prisma, audit } = await makeAuth(fakeUser({ password_hash: passwordHash }));

    await expect(auth.login(EMAIL, 'wrong-password-123')).rejects.toThrow(UnauthorizedException);
    expect(prisma.user.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ failed_login_count: 1 }) }),
    );
    expect(audit.list().at(-1)?.operation).toBe('auth.login');
    expect(audit.list().at(-1)?.outcome).toBe('failure');
  });

  it('gives unknown users the same uniform error (no user-existence oracle)', async () => {
    const { auth, prisma } = await makeAuth(null);

    await expect(auth.login('ghost@nexuspanel.dev', 'whatever-pass-123')).rejects.toThrow('invalid credentials');
    expect(prisma.user.update).not.toHaveBeenCalled();
  });

  it('locks the account at the failure threshold and skips password work while locked', async () => {
    const lockedUser = fakeUser({ password_hash: passwordHash, failed_login_count: 4 });
    const { auth, prisma } = await makeAuth(lockedUser);

    await expect(auth.login(EMAIL, 'wrong-password-123')).rejects.toThrow(UnauthorizedException);
    const lockCall = prisma.user.update.mock.calls.find(
      (c) => c[0].data?.locked_until instanceof Date,
    );
    expect(lockCall).toBeDefined();
    expect(lockCall![0].data.failed_login_count).toBe(5);

    // While locked: even the CORRECT password is rejected and no verify runs.
    const stillLocked = fakeUser({ password_hash: passwordHash, locked_until: new Date(Date.now() + 15 * 60 * 1000) });
    const auth2 = (await makeAuth(stillLocked)).auth;
    await expect(auth2.login(EMAIL, PASSWORD, {})).rejects.toThrow(UnauthorizedException);
  });

  it('refuses TOTP-enrolled users without a code (distinct challenge reason, C2)', async () => {
    const { auth, audit } = await makeAuth(fakeUser({ password_hash: passwordHash, totp_enabled_at: new Date() }));
    await expect(auth.login(EMAIL, PASSWORD, {})).rejects.toThrow('totp code required');
    const entry = audit.list().at(-1);
    expect(entry?.parameters).toMatchObject({ reason: 'totp_missing' });
  });

  it('rejects a WRONG TOTP code as a failed attempt (lockout protects the second factor)', async () => {
    const { auth, prisma, audit } = await makeAuth(
      fakeUser({ password_hash: passwordHash, totp_enabled_at: new Date() }),
    );
    await expect(auth.login(EMAIL, PASSWORD, { totp: '000000' })).rejects.toThrow('invalid credentials');
    expect(prisma.user.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ failed_login_count: 1 }) }),
    );
    expect(audit.list().at(-1)?.parameters).toMatchObject({ reason: 'totp_invalid' });
  });

  it('accepts a valid TOTP code, tags the audit entry, and persists the consumed step', async () => {
    const secret = generateTotpSecret();
    const box = new SecretBox(crypto.randomBytes(32));
    const enc = box.encrypt(Buffer.from(secret, 'utf8'));
    const nowUnix = Math.floor(Date.now() / 1000);
    const code = totpAt(secret, nowUnix)!;
    const { auth, prisma, audit } = await makeAuth(
      fakeUser({
        password_hash: passwordHash,
        totp_enabled_at: new Date(),
        totp_secret_enc: enc,
      }),
    );
    // Wire the harness box into the service under test.
    (auth as unknown as { twoFactor: TwoFactorService }).twoFactor = new TwoFactorService(
      prisma as unknown as PrismaService,
      box,
      new PasswordService(),
      audit,
    );

    const res = await auth.login(EMAIL, PASSWORD, { totp: code });
    expect(res.access_token).toBeTruthy();
    const entry = audit.list().find((e) => e.outcome === 'success');
    expect(entry?.parameters).toMatchObject({ second_factor: 'totp' });
    // The consumed step rides the same update as the login bookkeeping.
    const updateData = prisma.user.update.mock.calls[0][0].data;
    expect(updateData.preferences.totp_last_step).toBe(Math.floor(nowUnix / 30));
  });

  it('refuses inactive and soft-deleted users', async () => {
    const a = await makeAuth(fakeUser({ password_hash: passwordHash, is_active: false }));
    await expect(a.auth.login(EMAIL, PASSWORD, {})).rejects.toThrow('invalid credentials');
    const b = await makeAuth(fakeUser({ password_hash: passwordHash, deleted_at: new Date() }));
    await expect(b.auth.login(EMAIL, PASSWORD, {})).rejects.toThrow('invalid credentials');
  });
});

describe('AuthService (C3 refresh rotation + reuse detection)', () => {
  const ORIGINAL_ENV = { ...process.env };
  let passwordHash: string;

  beforeAll(async () => {
    passwordHash = await new PasswordService().hash(PASSWORD);
  });

  beforeEach(() => {
    delete process.env.DEV_ADMIN_EMAIL;
    delete process.env.DEV_ADMIN_PASSWORD;
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('rotates the refresh token on use: new secret, hash updated in DB', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { deviceFingerprint: 'fp-A' });

    prisma.userSession.findUnique.mockResolvedValue(fakeSession(first.refresh_token, user));
    const second = await auth.refresh(first.refresh_token, { deviceFingerprint: 'fp-A' });

    expect(second.refresh_token).not.toBe(first.refresh_token);
    expect(second.access_token).not.toBe(first.access_token);
    const updated = prisma.userSession.update.mock.calls.at(-1)![0];
    expect(Buffer.compare(updated.data.refresh_token_hash, hashRefreshToken(first.refresh_token))).not.toBe(0);
    expect(updated.data.expires_at.getTime()).toBeGreaterThan(Date.now() + 6.9 * 24 * 3600 * 1000);
  });

  it('DETECTS REUSE of a rotated token and revokes every session of the user (C3)', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma, audit } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { deviceFingerprint: 'fp-A' });

    prisma.userSession.findUnique.mockResolvedValue(fakeSession(first.refresh_token, user));
    await auth.refresh(first.refresh_token, { deviceFingerprint: 'fp-A' });

    // The attacker replays the FIRST (already rotated) token.
    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession('nxf1.stale.replacement', user), // stored hash ≠ presented token
    );
    await expect(auth.refresh(first.refresh_token, { deviceFingerprint: 'fp-A' })).rejects.toThrow(
      UnauthorizedException,
    );
    expect(prisma.userSession.updateMany).toHaveBeenCalledWith({
      where: { user_id: USER_ID, revoked_at: null },
      data: { revoked_at: expect.any(Date) },
    });
    expect(audit.list().some((e) => e.operation === 'auth.session.reuse_detected')).toBe(true);
  });

  it('rejects unknown, revoked, expired and malformed refresh tokens uniformly', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma } = await makeAuth(user);

    await expect(auth.refresh('garbage', {})).rejects.toThrow('invalid refresh token');
    await expect(auth.refresh('nxf1.unknown-session.secret', {})).rejects.toThrow('invalid refresh token');
    expect(prisma.userSession.updateMany).not.toHaveBeenCalled();

    prisma.userSession.findUnique.mockResolvedValue(fakeSession('nxf1.x.y', user, { revoked_at: new Date() }));
    await expect(auth.refresh('nxf1.x.y', {})).rejects.toThrow('invalid refresh token');

    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession('nxf1.x.y', user, { expires_at: new Date(Date.now() - 1000) }),
    );
    await expect(auth.refresh('nxf1.x.y', {})).rejects.toThrow('invalid refresh token');
  });

  it('rejects a device-fingerprint mismatch and revokes only that session (C3 binding)', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { deviceFingerprint: 'fp-A' });

    prisma.userSession.findUnique.mockResolvedValue(fakeSession(first.refresh_token, user));
    await expect(auth.refresh(first.refresh_token, { deviceFingerprint: 'fp-EVIL' })).rejects.toThrow(
      UnauthorizedException,
    );
    expect(prisma.userSession.update).toHaveBeenCalledWith({
      where: { id: SESSION_ID },
      data: { revoked_at: expect.any(Date) },
    });
    expect(prisma.userSession.updateMany).not.toHaveBeenCalled();
  });

  it('logout revokes exactly the presenting session', async () => {
    const { auth, prisma, audit } = await makeAuth(fakeUser({ password_hash: passwordHash }));
    await auth.logout(USER_ID, SESSION_ID);
    expect(prisma.userSession.updateMany).toHaveBeenCalledWith({
      where: { id: SESSION_ID, user_id: USER_ID, revoked_at: null },
      data: { revoked_at: expect.any(Date) },
    });
    expect(audit.list().at(-1)?.operation).toBe('auth.logout');
  });
});

describe('AuthService (C3 session inventory)', () => {
  it('lists only live own sessions, flags the presenting one, and sorts newest-use first', async () => {
    const { auth, prisma } = await makeAuth(fakeUser());
    const now = Date.now();
    // What the DB returns for the where-clause below: live rows only,
    // newest-use first (revoked/expired rows are excluded server-side).
    const rows = [
      { id: SESSION_ID, ip: '10.0.0.1', user_agent: 'current', device_fingerprint: 'fp-A', created_at: new Date(now - 3000), last_used_at: new Date(now), expires_at: new Date(now + 60_000) },
      { id: 's-old', ip: '10.0.0.9', user_agent: 'old', device_fingerprint: 'fp-old', created_at: new Date(now - 9000), last_used_at: new Date(now - 5000), expires_at: new Date(now + 60_000) },
    ];
    prisma.userSession.findMany.mockResolvedValue(rows);

    const view = await auth.listSessions(USER_ID, SESSION_ID);
    // findMany's where clause excludes revoked + expired server-side (asserted);
    // the mock returns pre-filtered live rows.
    expect(prisma.userSession.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { user_id: USER_ID, revoked_at: null, expires_at: { gt: expect.any(Date) } },
      }),
    );
    expect(view.map((s) => s.id)).toEqual([SESSION_ID, 's-old']); // newest use first
    expect(view.find((s) => s.id === SESSION_ID)?.current).toBe(true);
    expect(view.find((s) => s.id === 's-old')?.current).toBe(false);
  });

  it('revokeSession revokes an own live session and audits it', async () => {
    const { auth, prisma, audit } = await makeAuth(fakeUser());
    await auth.revokeSession(USER_ID, 's-other');
    expect(prisma.userSession.updateMany).toHaveBeenCalledWith({
      where: { id: 's-other', user_id: USER_ID, revoked_at: null },
      data: { revoked_at: expect.any(Date) },
    });
    expect(audit.list().at(-1)?.operation).toBe('auth.session.revoke');
  });

  it('revokeSession is a uniform 404 for unknown, foreign or already-revoked ids', async () => {
    const { auth, prisma, audit } = await makeAuth(fakeUser());
    prisma.userSession.updateMany.mockResolvedValue({ count: 0 });
    await expect(auth.revokeSession(USER_ID, 'nope')).rejects.toThrow(NotFoundException);
    await expect(auth.revokeSession(USER_ID, 'nope')).rejects.toThrow(NotFoundException); // same shape every time
    // Nothing happened → nothing was audited (no enumeration breadcrumbs).
    expect(audit.list().some((e) => e.operation === 'auth.session.revoke')).toBe(false);
  });
});

/* ─────────────── C14 — cross-reseller session isolation ─────────────── */

describe('AuthService (C14 session host binding)', () => {
  const ORIGINAL_ENV = { ...process.env };
  let passwordHash: string;

  beforeAll(async () => {
    passwordHash = await new PasswordService().hash(PASSWORD);
  });

  beforeEach(() => {
    delete process.env.DEV_ADMIN_EMAIL;
    delete process.env.DEV_ADMIN_PASSWORD;
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('login binds the session to the normalized request Host (port stripped)', async () => {
    const { auth, prisma } = await makeAuth(fakeUser({ password_hash: passwordHash }));
    await auth.login(EMAIL, PASSWORD, { host: 'Panel.BrandCo.COM:8443' });
    expect(prisma.userSession.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ bound_host: 'panel.brandco.com' }),
    });
  });

  it('a session minted on reseller A\'s domain refreshes from A but NOT from reseller B\'s domain', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma, audit } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { host: 'panel.brand-a.com' });

    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession(first.refresh_token, user, { bound_host: 'panel.brand-a.com' }),
    );
    // Active custom domains: two resellers' branded origins.
    prisma.reseller.findMany.mockResolvedValue([
      { custom_domain: 'panel.brand-a.com' },
      { custom_domain: 'panel.brand-b.com' },
    ]);

    // Same branded origin → refresh succeeds and rotates.
    const second = await auth.refresh(first.refresh_token, { host: 'panel.brand-a.com' });
    expect(second.access_token).toBeDefined();

    // The rotated token presented from reseller B's domain → uniform 401,
    // session revoked, audited — the ADR-0003 C14 exit criterion.
    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession(second.refresh_token, user, { bound_host: 'panel.brand-a.com' }),
    );
    await expect(auth.refresh(second.refresh_token, { host: 'panel.brand-b.com' })).rejects.toThrow(
      UnauthorizedException,
    );
    expect(prisma.userSession.update).toHaveBeenCalledWith({
      where: { id: SESSION_ID },
      data: { revoked_at: expect.any(Date) },
    });
    expect(audit.list().some((e) => e.operation === 'auth.refresh' && (e.parameters as Record<string, unknown>)?.['reason'] === 'host_crossing')).toBe(true);
  });

  it('branded-origin sessions cannot float back to the canonical panel host', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { host: 'panel.brand-a.com' });

    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession(first.refresh_token, user, { bound_host: 'panel.brand-a.com' }),
    );
    prisma.reseller.findMany.mockResolvedValue([{ custom_domain: 'panel.brand-a.com' }]);

    await expect(auth.refresh(first.refresh_token, { host: 'panel.nexuspanel.dev' })).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('canonical sessions cannot be replayed onto a branded origin', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { host: 'panel.nexuspanel.dev' });

    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession(first.refresh_token, user, { bound_host: 'panel.nexuspanel.dev' }),
    );
    prisma.reseller.findMany.mockResolvedValue([{ custom_domain: 'panel.brand-a.com' }]);

    await expect(auth.refresh(first.refresh_token, { host: 'panel.brand-a.com' })).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('panel-kind hosts interoperate freely (ports and aliases stripped)', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { host: 'localhost:3000' });

    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession(first.refresh_token, user, { bound_host: 'localhost' }),
    );
    // No active custom domains at all → every host is panel-kind.
    const second = await auth.refresh(first.refresh_token, { host: '127.0.0.1:9200' });
    expect(second.refresh_token).not.toBe(first.refresh_token);
  });

  it('pending domains do not participate in enforcement (no lockout before activation)', async () => {
    const user = fakeUser({ password_hash: passwordHash });
    const { auth, prisma } = await makeAuth(user);
    const first = await auth.login(EMAIL, PASSWORD, { host: 'panel.brand-a.com' });

    prisma.userSession.findUnique.mockResolvedValue(
      fakeSession(first.refresh_token, user, { bound_host: 'panel.brand-a.com' }),
    );
    // The domain is registered but still 'pending' → the active-domain query
    // (custom_domain_status: 'active') returns nothing.
    prisma.reseller.findMany.mockResolvedValue([]);

    const second = await auth.refresh(first.refresh_token, { host: 'localhost:3000' });
    expect(second.access_token).toBeDefined();
  });
});
