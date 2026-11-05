import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import { AuthService, LoginContext } from './auth.service';
import { Public } from './public.decorator';
import { RequirePermission } from '../common/permissions';
import { AuthContext, AuthenticatedRequest, CurrentUser } from './request-context';

/**
 * Auth endpoints (API spec §4.1).
 *
 *   POST /auth/login    email + password (+ TOTP in P2) → JWT + refresh
 *   POST /auth/refresh  rotating refresh token            → new pair (C3)
 *   POST /auth/logout   revoke the presenting session (authenticated)
 *
 * Request metadata (ip / user-agent / device fingerprint) is captured for
 * session binding — C3 binds refresh tokens to the device fingerprint.
 *
 * @Public() is METHOD-level here: login and refresh are unauthenticated by
 * design, but logout must authenticate (it revokes the presenting session).
 * A class-level @Public() previously leaked logout past the JWT gate.
 */
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(200)
  async login(
    @Body() body: { email?: string; password?: string; totp?: string; device_fingerprint?: string },
    @Req() req: AuthenticatedRequest,
  ): Promise<unknown> {
    return this.auth.login(body.email ?? '', body.password ?? '', this.context(req, body));
  }

  @Public()
  @Post('refresh')
  @HttpCode(200)
  async refresh(
    @Body() body: { refresh_token?: string; device_fingerprint?: string },
    @Req() req: AuthenticatedRequest,
  ): Promise<unknown> {
    return this.auth.refresh(body.refresh_token ?? '', this.context(req, body));
  }

  /** Logout is authenticated: it revokes exactly the presenting session. */
  @RequirePermission('auth:logout')
  @Post('logout')
  async logout(@CurrentUser() user: AuthContext): Promise<void> {
    await this.auth.logout(user.userId, user.sessionId);
  }

  private context(
    req: AuthenticatedRequest,
    body: { device_fingerprint?: string; totp?: string },
  ): LoginContext {
    const header = (name: string): string | undefined => {
      const v = req.headers[name];
      return Array.isArray(v) ? v[0] : v;
    };
    return {
      ip: header('x-forwarded-for') ?? req.remoteAddress,
      userAgent: header('user-agent'),
      deviceFingerprint: body.device_fingerprint ?? header('x-device-fingerprint'),
      totp: body.totp,
    };
  }
}
