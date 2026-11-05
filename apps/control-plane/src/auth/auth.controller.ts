import { Body, Controller, Get, HttpCode, Post, Req, UnauthorizedException } from '@nestjs/common';
import { AuthService, LoginContext } from './auth.service';
import { TwoFactorService } from './two-factor.service';
import { Public } from './public.decorator';
import { RequirePermission, SessionOnly } from '../common/permissions';
import { AuthContext, AuthenticatedRequest, CurrentUser } from './request-context';

/**
 * Auth endpoints (API spec §4.1).
 *
 *   POST /auth/login    email + password (+ TOTP in P2) → JWT + refresh
 *   POST /auth/refresh  rotating refresh token            → new pair (C3)
 *   POST /auth/logout   revoke the presenting session (authenticated)
 *   POST /auth/2fa/setup    begin TOTP enrollment (C2)
 *   POST /auth/2fa/verify   confirm a live code; enables 2FA + backup codes
 *   POST /auth/2fa/disable  disable 2FA (password re-entry)
 *   GET  /auth/2fa/backup-codes  regenerate (password via X-Confirm-Password)
 *
 * Request metadata (ip / user-agent / device fingerprint) is captured for
 * session binding — C3 binds refresh tokens to the device fingerprint.
 *
 * @Public() is METHOD-level here: login and refresh are unauthenticated by
 * design, but logout must authenticate (it revokes the presenting session).
 * A class-level @Public() previously leaked logout past the JWT gate.
 *
 * The 2FA routes are self-service (`auth:2fa`) AND @SessionOnly():
 * interactive sessions only — an API token can never touch second factors.
 * The spec's password re-entry on the GET backup-codes route travels in the
 * X-Confirm-Password header (GET bodies are semantically wrong and some
 * clients drop them); both are TLS-protected and never logged.
 */
@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly twoFactor: TwoFactorService,
  ) {}

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

  // ─────────────────────────── 2FA (C2) ───────────────────────────

  @RequirePermission('auth:2fa')
  @SessionOnly()
  @Post('2fa/setup')
  async setup2fa(@CurrentUser() user: AuthContext): Promise<unknown> {
    return this.twoFactor.setup(user.userId);
  }

  @RequirePermission('auth:2fa')
  @SessionOnly()
  @Post('2fa/verify')
  async verify2fa(
    @CurrentUser() user: AuthContext,
    @Body() body: { code?: string },
  ): Promise<{ backup_codes: string[] }> {
    return this.twoFactor.verifyEnrollment(user.userId, body.code ?? '');
  }

  @RequirePermission('auth:2fa')
  @SessionOnly()
  @Post('2fa/disable')
  async disable2fa(
    @CurrentUser() user: AuthContext,
    @Body() body: { password?: string },
  ): Promise<void> {
    await this.twoFactor.disable(user.userId, body.password ?? '');
  }

  @RequirePermission('auth:2fa')
  @SessionOnly()
  @Get('2fa/backup-codes')
  async regenerateBackupCodes(
    @CurrentUser() user: AuthContext,
    @Req() req: AuthenticatedRequest,
  ): Promise<{ backup_codes: string[] }> {
    const header = req.headers['x-confirm-password'];
    const password = Array.isArray(header) ? header[0] : header;
    if (!password) {
      throw new UnauthorizedException('password re-entry required (X-Confirm-Password)');
    }
    return this.twoFactor.regenerateBackupCodes(user.userId, password);
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
