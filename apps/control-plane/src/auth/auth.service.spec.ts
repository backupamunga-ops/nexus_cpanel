import { UnauthorizedException } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { ARGON2ID_PARAMS, AuthService, PasswordService } from './auth.service';

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

describe('AuthService dev bootstrap login', () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    process.env.DEV_ADMIN_EMAIL = 'admin@nexuspanel.dev';
    process.env.DEV_ADMIN_PASSWORD = 'bootstrap-password-123';
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  async function makeService(): Promise<AuthService> {
    const svc = new AuthService();
    await svc.whenBootstrapSeeded();
    return svc;
  }

  it('issues a dev token for valid credentials', async () => {
    const svc = await makeService();
    const res = await svc.login('admin@nexuspanel.dev', 'bootstrap-password-123');
    expect(res.token_type).toBe('jwt');
    expect(res.expires_in).toBe(900);
    expect(res.user).toEqual({ email: 'admin@nexuspanel.dev' });
    expect(res.access_token).toMatch(/^dev\./);
  });

  it('rejects wrong credentials with a uniform error (no user oracle)', async () => {
    const svc = await makeService();
    await expect(svc.login('admin@nexuspanel.dev', 'wrong-password-456')).rejects.toThrow(
      UnauthorizedException,
    );
    await expect(svc.login('nosuchuser@nexuspanel.dev', 'whatever-password')).rejects.toThrow(
      'invalid credentials',
    );
  });
});
