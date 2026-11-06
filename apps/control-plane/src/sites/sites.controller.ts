import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Query } from '@nestjs/common';
import {
  SitesService,
  DomainDto,
  DomainLogDto,
  SubdomainDto,
  AliasDto,
  RedirectDto,
  CreateDomainInput,
  UpdateDomainInput,
  CreateRedirectInput,
  ServingStatusDto,
  Actor,
} from './sites.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';

/**
 * Sites & domains (API spec §4.7). The php/ssl/logs/staging/git composite
 * routes of §4.7 land with their own milestones (P3 php/ssl batches, P6).
 *
 * `site:*` permissions are hosting-account-scoped: the PermissionsGuard
 * resolves the owning account (route resource id or body) and authorizes
 * against the caller's access row — owner/admin manage, member/readonly
 * view. Super admins pass by role. Visibility failures are 404 (§3.2).
 */
@Controller('domains')
export class SitesController {
  constructor(private readonly sites: SitesService) {}

  @Get()
  @RequirePermission('site:list')
  async list(@CurrentUser() user: AuthContext): Promise<{ data: DomainDto[] }> {
    return this.sites.list(actorOf(user));
  }

  /** Node serving posture for the console banner — must precede @Get(':id'). */
  @Get('serving-status')
  @RequirePermission('site:list')
  async servingStatus(): Promise<ServingStatusDto> {
    return this.sites.servingStatus();
  }

  @Get(':id')
  @RequirePermission('site:read')
  async get(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<DomainDto> {
    return this.sites.get(id, actorOf(user));
  }

  @Post()
  @RequirePermission('site:create')
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: CreateDomainInput,
  ): Promise<DomainDto> {
    return this.sites.create(body, actorOf(user));
  }

  @Patch(':id')
  @RequirePermission('site:update')
  async update(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Body() body: UpdateDomainInput,
  ): Promise<DomainDto> {
    return this.sites.update(id, body, actorOf(user));
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('site:delete')
  async remove(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<void> {
    await this.sites.remove(id, actorOf(user));
  }

  // --------------------------------------------------------------- subdomains

  @Get(':id/subdomains')
  @RequirePermission('site:read')
  async listSubdomains(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
  ): Promise<{ data: SubdomainDto[] }> {
    return this.sites.listSubdomains(id, actorOf(user));
  }

  @Post(':id/subdomains')
  @RequirePermission('site:create')
  async createSubdomain(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Body() body: { name?: unknown; document_root?: unknown },
  ): Promise<SubdomainDto> {
    return this.sites.createSubdomain(id, body, actorOf(user));
  }

  @Delete(':id/subdomains/:subId')
  @HttpCode(204)
  @RequirePermission('site:delete')
  async deleteSubdomain(
    @Param('id') id: string,
    @Param('subId') subId: string,
    @CurrentUser() user: AuthContext,
  ): Promise<void> {
    await this.sites.deleteSubdomain(id, subId, actorOf(user));
  }

  // ------------------------------------------------------------------ aliases

  @Get(':id/aliases')
  @RequirePermission('site:read')
  async listAliases(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
  ): Promise<{ data: AliasDto[] }> {
    return this.sites.listAliases(id, actorOf(user));
  }

  @Post(':id/aliases')
  @RequirePermission('site:create')
  async createAlias(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Body() body: { alias_name?: unknown },
  ): Promise<AliasDto> {
    return this.sites.createAlias(id, body, actorOf(user));
  }

  @Delete(':id/aliases/:aliasId')
  @HttpCode(204)
  @RequirePermission('site:delete')
  async deleteAlias(
    @Param('id') id: string,
    @Param('aliasId') aliasId: string,
    @CurrentUser() user: AuthContext,
  ): Promise<void> {
    await this.sites.deleteAlias(id, aliasId, actorOf(user));
  }

  // ---------------------------------------------------------------- redirects

  @Get(':id/redirects')
  @RequirePermission('site:read')
  async listRedirects(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
  ): Promise<{ data: RedirectDto[] }> {
    return this.sites.listRedirects(id, actorOf(user));
  }

  /** Redirects mutate the vhost like any other serving change → site:update. */
  @Post(':id/redirects')
  @RequirePermission('site:update')
  async createRedirect(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Body() body: CreateRedirectInput,
  ): Promise<RedirectDto> {
    return this.sites.createRedirect(id, body, actorOf(user));
  }

  @Delete(':id/redirects/:redirectId')
  @HttpCode(204)
  @RequirePermission('site:update')
  async deleteRedirect(
    @Param('id') id: string,
    @Param('redirectId') redirectId: string,
    @CurrentUser() user: AuthContext,
  ): Promise<void> {
    await this.sites.deleteRedirect(id, redirectId, actorOf(user));
  }

  // ---------------------------------------------------------------- site logs

  /** Tail of the site's access/error log (query: ?type=access|error&lines=N). */
  @Get(':id/logs')
  @RequirePermission('site:read')
  async logs(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Query('type') type?: string,
    @Query('lines') lines?: string,
  ): Promise<DomainLogDto> {
    return this.sites.logs(id, type, lines, actorOf(user));
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
