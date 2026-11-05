import { JwtService } from './jwt.service';

const SECRET = 'unit-test-secret-0123456789abcdefghijklmnopqrstuv';

describe('JwtService (HS256 access tokens)', () => {
  it('signs and verifies a round-trip with all fixed claims', () => {
    const jwt = new JwtService(SECRET);
    const token = jwt.sign({ sub: 'user-1', sid: 'sess-1', fp: 'fp-A' }, 900);
    const claims = jwt.verify(token);
    expect(claims).not.toBeNull();
    expect(claims!.sub).toBe('user-1');
    expect(claims!.sid).toBe('sess-1');
    expect(claims!.fp).toBe('fp-A');
    expect(claims!.typ).toBe('access');
    expect(claims!.iss).toBe('nexuspanel');
    expect(claims!.exp! - claims!.iat!).toBe(900);
  });

  it('rejects tampered payloads (signature mismatch)', () => {
    const jwt = new JwtService(SECRET);
    const token = jwt.sign({ sub: 'user-1', sid: 'sess-1' }, 900);
    const [h, , s] = token.split('.');
    const forgedBody = Buffer.from(
      JSON.stringify({ sub: 'admin-evil', sid: 'sess-1', typ: 'access', iss: 'nexuspanel', iat: 1, exp: 9999999999 }),
    ).toString('base64url');
    expect(jwt.verify(`${h}.${forgedBody}.${s}`)).toBeNull();
  });

  it('rejects expired tokens', () => {
    const jwt = new JwtService(SECRET);
    const token = jwt.sign({ sub: 'user-1', sid: 'sess-1' }, -1); // already expired
    expect(jwt.verify(token)).toBeNull();
  });

  it('rejects other algorithms (alg confusion) and garbage', () => {
    const jwt = new JwtService(SECRET);
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from('{}').toString('base64url');
    expect(jwt.verify(`${header}.${body}.`)).toBeNull();
    expect(jwt.verify('not-a-jwt')).toBeNull();
    expect(jwt.verify('a.b.c.d')).toBeNull();
  });

  it('rejects tokens signed with a different secret', () => {
    const a = new JwtService(SECRET);
    const b = new JwtService('another-secret-0123456789abcdefghijklmnopqrst');
    expect(b.verify(a.sign({ sub: 'user-1', sid: 'sess-1' }, 900))).toBeNull();
  });

  it('refuses secrets shorter than 32 characters', () => {
    expect(() => new JwtService('too-short')).toThrow('at least 32');
  });

  it('generates an ephemeral secret when none is configured (dev-safe default)', () => {
    // One instance = one boot secret: sign/verify work within the process;
    // a second ephemeral instance (restart) cannot read the first's tokens.
    const boot = new JwtService();
    expect(boot.verify(boot.sign({ sub: 'u', sid: 's' }, 60))).not.toBeNull();
    expect(new JwtService().verify(boot.sign({ sub: 'u', sid: 's' }, 60))).toBeNull();
  });
});
