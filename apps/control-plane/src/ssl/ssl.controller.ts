import { Body, Controller, Delete, Get, HttpCode, Param, Post } from '@nestjs/common';
import { SslService, SslCertDto } from './ssl.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * SSL endpoints (API spec §4.7 ssl composite + §4.14). `ssl:read` sees
 * metadata; `ssl:issue` covers ACME issue/renew and manual install;
 * `ssl:revoke` removes. Responses never carry PEM material — metadata
 * only (ADR-0009).
 */
@Controller()
export class SslController {
  constructor(private readonly ssl: SslService) {}

  @Get('ssl/certificates')
  @RequirePermission('ssl:read')
  async list(@CurrentUser() user: AuthContext): Promise<{ data: SslCertDto[] }> {
    return this.ssl.list(actorOf(user));
  }

  @Post('ssl/certificates')
  @RequirePermission('ssl:issue')
  async installManual(
    @CurrentUser() user: AuthContext,
    @Body() body: { domain_id?: string; cert_pem?: string; key_pem?: string },
  ): Promise<SslCertDto> {
    return this.ssl.installManual(body, actorOf(user));
  }

  @Get('domains/:id/ssl')
  @RequirePermission('ssl:read')
  async getForDomain(@Param('id') id: string, @CurrentUser() user: AuthContext) {
    return this.ssl.getForDomain(id, actorOf(user));
  }

  @Post('domains/:id/ssl/issue')
  @RequirePermission('ssl:issue')
  async issue(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Body() body: { email?: string },
  ): Promise<SslCertDto> {
    return this.ssl.issue(id, body, actorOf(user));
  }

  @Post('domains/:id/ssl/renew')
  @RequirePermission('ssl:issue')
  async renew(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<SslCertDto> {
    return this.ssl.renew(id, actorOf(user));
  }

  @Delete('domains/:id/ssl')
  @HttpCode(204)
  @RequirePermission('ssl:revoke')
  async revoke(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<void> {
    await this.ssl.revoke(id, actorOf(user));
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
