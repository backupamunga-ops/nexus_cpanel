import { All, Body, Controller, HttpCode, Req } from '@nestjs/common';
import { Request } from 'express';
import { ExtProxyService } from './ext-proxy.service';
import { Public } from '../auth/public.decorator';

/**
 * `/api/v1/ext/*` catch-all (SDK spec §5.3, P7 / ADR-0021).
 *
 * This controller is deliberately @Public() to the JWT guard: extensions do
 * not hold user sessions — they authenticate with their own derived bearer
 * token, which ExtProxyService resolves, scope-checks, rate-limits and
 * audits. The route table is CLOSED (EXT_PROXY_ROUTES): an extension can
 * never reach `/api/v1/*` itself, only this namespace.
 */
@Controller('ext')
export class ExtProxyController {
  constructor(private readonly proxy: ExtProxyService) {}

  @Public()
  @All('*')
  @HttpCode(200)
  async handle(
    @Req() req: Request,
    @Body() body: Record<string, unknown> | undefined,
  ): Promise<unknown> {
    const method = req.method.toUpperCase();
    const path = extPathOf(req.originalUrl);
    const query = new URL(req.originalUrl, 'http://localhost').searchParams;
    const bearer = bearerOf(req.headers.authorization);

    const principal = await this.proxy.authenticate(bearer);
    try {
      this.proxy.authorize(principal, method, path);
      if (method === 'GET') {
        const data = await this.proxy.resolveGet(path, query);
        await this.proxy.auditCall(principal, method, path, 'success');
        return data;
      }
      const data = await this.proxy.resolvePost(principal, path, body ?? {});
      await this.proxy.auditCall(principal, method, path, 'success');
      return data;
    } catch (e) {
      await this.proxy
        .auditCall(principal, method, path, 'failure', { error: (e as Error).message })
        .catch(() => undefined);
      throw e;
    }
  }
}

/** `/api/v1/ext/backups/runs?limit=10` → `/backups/runs`. */
function extPathOf(originalUrl: string): string {
  const noQuery = originalUrl.split('?')[0];
  const idx = noQuery.indexOf('/ext/');
  if (idx === -1) return '/';
  return noQuery.slice(idx + 4) || '/';
}

function bearerOf(header: string | string[] | undefined): string | undefined {
  const h = Array.isArray(header) ? header[0] : header;
  if (!h) return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1].trim() : undefined;
}
