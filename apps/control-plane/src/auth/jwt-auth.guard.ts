import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from './jwt.service';
import { ApiTokensService, API_TOKEN_PREFIX } from './api-tokens.service';
import { IS_PUBLIC_KEY } from './public.decorator';
import { AuthenticatedRequest } from './request-context';

/**
 * Global bearer-token gate (C3/C4/C6 foundation).
 *
 * - `@Public()` endpoints pass through (health, login, refresh).
 * - `Authorization: Bearer npt_…` → API token path (C4): the credential is
 *   looked up by SHA-256 and, on success, the request authenticates as the
 *   owning user with the token's scopes attached for PermissionsGuard.
 * - Any other bearer credential is treated as a session JWT; the verified
 *   claims (sub, sid, fp) are attached for the permission layer (C6) and
 *   audit attribution.
 *
 * Failure responses are uniform (`invalid or expired token`) for both
 * credential kinds — responses never reveal which one was presented.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly reflector: Reflector,
    private readonly apiTokens: ApiTokensService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    const req = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const headerValue = req.headers['authorization'];
    const header = Array.isArray(headerValue) ? headerValue[0] : headerValue;
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException('missing bearer token');
    }
    const raw = header.slice('Bearer '.length).trim();

    if (raw.startsWith(API_TOKEN_PREFIX)) {
      const result = await this.apiTokens.authenticate(raw, req.remoteAddress ?? null);
      if (!result.ok) {
        throw new UnauthorizedException('invalid or expired token');
      }
      req.auth = {
        userId: result.userId,
        sessionId: `api-token:${result.tokenId}`,
        tokenId: result.tokenId,
        tokenScopes: result.scopes,
        viaApiToken: true,
      };
      return true;
    }

    const claims = this.jwt.verify(raw);
    if (!claims) {
      throw new UnauthorizedException('invalid or expired token');
    }
    req.auth = { userId: claims.sub, sessionId: claims.sid, fingerprint: claims.fp };
    return true;
  }
}
