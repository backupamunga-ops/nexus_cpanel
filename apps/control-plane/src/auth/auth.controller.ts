import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthService, AuthSessionTokens, LoginContext } from './auth.service';
import { TwoFactorService } from './two-factor.service';
import { SettingsService } from '../settings/settings.service';
import { Public } from './public.decorator';
import {
  clearRefreshCookie,
  readRefreshCookie,
  setRefreshCookie,
  TRANSPORT_COOKIE_HEADER,
  wantsCookieTransport,
} from './refresh-cookie';
import { RequirePermission, SessionOnly } from '../common/permissions';
import { AuthContext, AuthenticatedRequest, CurrentUser } from './request-context';

/**
 * Auth endpoints (API spec §4.1).
 *
 *   POST /auth/login    email + password (+ TOTP) → JWT + refresh
 *   POST /auth/refresh  rotating refresh token      → new pair (C3)
 *   POST /auth/logout   revoke the presenting session (authenticated)
 *   GET  /auth/sessions       list own active sessions
 *   DELETE /auth/sessions/{id} revoke one own session
 *   POST /auth/2fa/setup    begin TOTP enrollment (C2)
 *   POST /auth/2fa/verify   confirm a live code; enables 2FA + backup codes
 *   POST /auth/2fa/disable  disable 2FA (password re-entry)
 *   GET  /auth/2fa/backup-codes  regenerate (password via X-Confirm-Password)
 *
 * Refresh transport (C3, dual-mode):
 *   - Browser flow sends `X-Auth-Transport: cookie`. Login/refresh then set
 *     the httpOnly, SameSite=Strict `nexuspanel_rt` cookie scoped to
 *     /api/v1/auth and the response body OMITS the refresh token — the
 *     secret is never observable to page JavaScript, closing the XSS
 *     read path that localStorage had.
 *   - Without the header, the §4.1 body contract applies unchanged
 *     (programmatic clients until they adopt API tokens, C4).
 *   - Refresh prefers the cookie when both are presented; a body token that
 *     matches a cookie-era session is simply a stale client retry.
 *
 * Request metadata (ip / user-agent / device fingerprint) is captured for
 * session binding — C3 binds refresh tokens to the device fingerprint, and
 * C14 (session-host.ts) binds the session to the request Host so a session
 * minted on one reseller's branded domain cannot refresh from another.
 *
 * @Public() is METHOD-level here: login and refresh are unauthenticated by
 * design, but logout must authenticate (it revokes the presenting session).
 * A class-level @Public() previously leaked logout past the JWT gate.
 *
 * The 2FA and sessions routes are self-service AND @SessionOnly(): interactive
 * sessions only — an API token can never touch second factors or device
 * credentials. The spec's password re-entry on the GET backup-codes route
 * travels in the X-Confirm-Password header (GET bodies are semantically wrong
 * and some clients drop them); both are TLS-protected and never logged.
 */
@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly twoFactor: TwoFactorService,
    private readonly settings: SettingsService,
  ) {}

  @Public()
  @Post('login')
  @HttpCode(200)
  async login(
    @Body() body: { email?: string; password?: string; totp?: string; device_fingerprint?: string },
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    const ctx = this.context(req, body);
    const result = await this.auth.login(body.email ?? '', body.password ?? '', ctx);
    return this.deliver(result, req, res, ctx);
  }

  @Public()
  @Post('refresh')
  @HttpCode(200)
  async refresh(
    @Body() body: { refresh_token?: string; device_fingerprint?: string },
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    const ctx = this.context(req, body);
    // Cookie wins when presented: the browser flow must never fall back to a
    // body token it no longer stores. Body is the programmatic-client path.
    const presented = readRefreshCookie(req) ?? body.refresh_token ?? '';
    const viaCookie = readRefreshCookie(req) !== undefined || wantsCookieTransport(req);
    const result = await this.auth.refresh(presented, ctx);
    return this.deliver(result, req, res, ctx, viaCookie);
  }

  /** Logout is authenticated: it revokes exactly the presenting session. */
  @RequirePermission('auth:logout')
  @Post('logout')
  async logout(
    @CurrentUser() user: AuthContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.auth.logout(user.userId, user.sessionId);
    clearRefreshCookie(res);
  }

  // ──────────────────────── sessions (C3 device view) ────────────────────────

  @RequirePermission('auth:sessions')
  @SessionOnly()
  @Get('sessions')
  async listSessions(@CurrentUser() user: AuthContext): Promise<unknown> {
    return this.auth.listSessions(user.userId, user.sessionId);
  }

  @RequirePermission('auth:sessions')
  @SessionOnly()
  @Delete('sessions/:id')
  @HttpCode(204)
  async revokeSession(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.auth.revokeSession(user.userId, id);
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

  /**
   * Transport dispatch shared by login and refresh. Cookie mode strips the
   * refresh token from the response body and hands it to Set-Cookie instead;
   * body mode keeps the §4.1 contract for programmatic clients. The cookie
   * Max-Age reads the live security.session_ttl_days setting (D-11) so it
   * always mirrors the session's server-side sliding expiry.
   */
  private async deliver(
    result: AuthSessionTokens,
    req: AuthenticatedRequest,
    res: Response,
    ctx: LoginContext,
    forceCookie = false,
  ): Promise<unknown> {
    if (forceCookie || wantsCookieTransport(req)) {
      setRefreshCookie(
        res,
        result.refresh_token,
        await this.settings.runtimeInt('security.session_ttl_days'),
      );
      const { refresh_token: _omit, ...body } = result;
      void _omit;
      return body;
    }
    return result;
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
      host: header('host') ?? null,
    };
  }
}

// Re-exported for the permission CI's route inventory (and for callers that
// want the constant without importing express types).
export { TRANSPORT_COOKIE_HEADER };
