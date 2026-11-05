import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/** Authenticated request context attached by JwtAuthGuard + PermissionsGuard. */
export interface AuthContext {
  userId: string;
  sessionId: string;
  fingerprint?: string;
  /** Set by PermissionsGuard after the user lookup (C6). */
  isSuperAdmin?: boolean;
  /** Per-account role resolved by PermissionsGuard for `account:*` routes. */
  accountRole?: string;
  /** True when the bearer credential is an API token (C4), not a session JWT. */
  viaApiToken?: boolean;
  /** ApiToken row id — audit attribution for token-authenticated requests. */
  tokenId?: string;
  /** Scopes granted to the presenting API token (C4) — enforced by PermissionsGuard. */
  tokenScopes?: string[];
}

export interface AuthenticatedRequest {
  headers: Record<string, string | string[] | undefined>;
  /** Route params, populated by Express; may be absent in unit tests. */
  params?: Record<string, string>;
  /** Request body (JSON), populated by Express; may be absent in unit tests. */
  body?: Record<string, unknown>;
  /** Parsed query string, populated by Express; may be absent in unit tests. */
  query?: Record<string, unknown>;
  /** Peer address, populated by Express; may be absent in unit tests. */
  remoteAddress?: string;
  auth?: AuthContext;
}

/** Parameter decorator: `@CurrentUser() user: AuthContext`. */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthContext => {
    const req = ctx.switchToHttp().getRequest<AuthenticatedRequest>();
    return req.auth ?? { userId: '', sessionId: '' };
  },
);
