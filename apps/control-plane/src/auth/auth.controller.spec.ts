import type { Response } from 'express';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TwoFactorService } from './two-factor.service';
import { SettingsService } from '../settings/settings.service';
import { REFRESH_COOKIE } from './refresh-cookie';

/**
 * Controller-level transport tests (C3): the service always returns the full
 * pair internally; the CONTROLLER decides what the client may observe.
 *
 *  - cookie mode (X-Auth-Transport: cookie): body OMITS the refresh token,
 *    Set-Cookie carries it httpOnly/Strict, scoped to /api/v1/auth.
 *  - body mode (no header): §4.1 contract unchanged — refresh_token in body,
 *    no cookie touched.
 *  - refresh prefers the cookie over a body token.
 *  - logout clears the cookie.
 */

const SESSION = { userId: 'u-1', sessionId: 's-1' };

function fakeRes(): Response {
  const jar: Record<string, { name: string; value: string; options: Record<string, unknown> }> = {};
  const res = {
    cookie: jest.fn((name: string, value: string, options: Record<string, unknown>) => {
      jar[name] = { name, value, options };
    }),
  } as unknown as Response;
  return res;
}

function cookieJar(res: Response): Record<string, string> {
  const jar: Record<string, string> = {};
  for (const call of (res.cookie as jest.Mock).mock.calls) {
    jar[call[0] as string] = call[1] as string;
  }
  return jar;
}

function makeController(): AuthController {
  const auth = {
    login: jest.fn().mockResolvedValue({
      access_token: 'jwt.a.b',
      refresh_token: 'nxf1.refresh-secret',
      token_type: 'jwt',
      expires_in: 900,
      user: { id: 'u-1', email: 'a@b.c', display_name: 'A', is_super_admin: true },
    }),
    refresh: jest.fn().mockResolvedValue({
      access_token: 'jwt.rotated',
      refresh_token: 'nxf1.rotated-secret',
      token_type: 'jwt',
      expires_in: 900,
      user: { id: 'u-1', email: 'a@b.c', display_name: 'A', is_super_admin: true },
    }),
    logout: jest.fn().mockResolvedValue(undefined),
  } as unknown as AuthService;
  const twoFactor = {} as TwoFactorService;
  // D-11: the cookie Max-Age mirrors the live security.session_ttl_days read.
  const settings = {
    runtimeInt: jest.fn().mockResolvedValue(7),
  } as unknown as SettingsService;
  return new AuthController(auth, twoFactor, settings);
}

function req(headers: Record<string, string | string[] | undefined>) {
  return { headers, remoteAddress: '127.0.0.1' } as Parameters<
    ReturnType<typeof makeController>['login']
  >[1];
}

describe('AuthController — refresh transport (C3)', () => {
  it('cookie mode: login sets httpOnly cookie and OMITS refresh_token from the body', async () => {
    const ctl = makeController();
    const res = fakeRes();
    const body = (await ctl.login(
      { email: 'a@b.c', password: 'p', device_fingerprint: 'fp-A' },
      req({ 'x-auth-transport': 'cookie' }),
      res,
    )) as Record<string, unknown>;

    expect(body.refresh_token).toBeUndefined(); // never observable to JS
    expect(body.access_token).toBe('jwt.a.b');

    const jar = cookieJar(res);
    expect(jar[REFRESH_COOKIE]).toBe('nxf1.refresh-secret');
    const options = (res.cookie as jest.Mock).mock.calls[0][2] as Record<string, unknown>;
    expect(options.httpOnly).toBe(true);
    expect(options.sameSite).toBe('strict');
    expect(options.path).toBe('/api/v1/auth');
    // D-11: Max-Age mirrors the live security.session_ttl_days read (7d here).
    expect(options.maxAge).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it('body mode (no transport header): §4.1 contract — refresh_token in body, no cookie', async () => {
    const ctl = makeController();
    const res = fakeRes();
    const body = (await ctl.login(
      { email: 'a@b.c', password: 'p' },
      req({}),
      res,
    )) as Record<string, unknown>;

    expect(body.refresh_token).toBe('nxf1.refresh-secret');
    expect(res.cookie as jest.Mock).not.toHaveBeenCalled();
  });

  it('refresh prefers the cookie over a stale body token and rotates the cookie', async () => {
    const ctl = makeController();
    const res = fakeRes();
    const r = req({
      cookie: `${REFRESH_COOKIE}=nxf1.cookie-secret`,
      'x-auth-transport': 'cookie',
    });

    const body = (await ctl.refresh(
      { refresh_token: 'nxf1.body-secret' },
      r,
      res,
    )) as Record<string, unknown>;

    expect((ctl['auth'].refresh as jest.Mock).mock.calls[0][0]).toBe('nxf1.cookie-secret');
    expect(body.refresh_token).toBeUndefined();
    expect(cookieJar(res)[REFRESH_COOKIE]).toBe('nxf1.rotated-secret');
  });

  it('refresh without a cookie keeps the body contract', async () => {
    const ctl = makeController();
    const res = fakeRes();
    const body = (await ctl.refresh(
      { refresh_token: 'nxf1.body-secret' },
      req({}),
      res,
    )) as Record<string, unknown>;

    expect((ctl['auth'].refresh as jest.Mock).mock.calls[0][0]).toBe('nxf1.body-secret');
    expect(body.refresh_token).toBe('nxf1.rotated-secret');
    expect(res.cookie as jest.Mock).not.toHaveBeenCalled();
  });

  it('logout clears the cookie', async () => {
    const ctl = makeController();
    const res = fakeRes();
    await ctl.logout(SESSION, res);
    expect(ctl['auth'].logout).toHaveBeenCalledWith('u-1', 's-1');
    const [name, value, options] = (res.cookie as jest.Mock).mock.calls[0];
    expect(name).toBe(REFRESH_COOKIE);
    expect(value).toBe('');
    expect(options.maxAge).toBe(0);
  });
});
