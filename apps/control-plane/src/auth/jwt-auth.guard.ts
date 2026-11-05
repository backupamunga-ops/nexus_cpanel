import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from './jwt.service';
import { IS_PUBLIC_KEY } from './public.decorator';
import { AuthenticatedRequest } from './request-context';

/**
 * Global bearer-token gate (C3/C6 foundation).
 *
 * - `@Public()` endpoints pass through (health, login, refresh).
 * - Everything else requires `Authorization: Bearer <jwt>`; the verified
 *   claims (sub, sid, fp) are attached to the request for the permission
 *   layer (C6) and audit attribution.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly reflector: Reflector,
  ) {}

  canActivate(context: ExecutionContext): boolean {
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
    const claims = this.jwt.verify(header.slice('Bearer '.length).trim());
    if (!claims) {
      throw new UnauthorizedException('invalid or expired token');
    }
    req.auth = { userId: claims.sub, sessionId: claims.sid, fingerprint: claims.fp };
    return true;
  }
}
