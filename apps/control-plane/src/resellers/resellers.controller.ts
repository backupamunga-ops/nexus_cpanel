import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
import { ResellersService, CreateResellerInput, ResellerDto, UpdateResellerInput } from './resellers.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';

/**
 * Reseller lifecycle (API spec §4.6). `reseller:*` permissions are
 * Server-Admin-only for now (PermissionsGuard rejects non-super-admins);
 * per-reseller role scoping lands when reseller staff users arrive — the
 * decorators still name the exact permission so the C6 coverage check and
 * the API-token scope vocabulary stay exact.
 *
 * Routes follow the spec table verbatim: branding reads/writes reuse
 * `reseller:read`/`reseller:update`; the custom-domain pair is
 * `reseller:update` (C14 isolation is enforced at the auth layer, not here).
 */
@Controller('resellers')
export class ResellersController {
  constructor(private readonly resellers: ResellersService) {}

  @Get()
  @RequirePermission('reseller:list')
  async list(): Promise<{ data: ResellerDto[] }> {
    return this.resellers.list();
  }

  @Get(':id')
  @RequirePermission('reseller:read')
  async get(@Param('id') id: string): Promise<ResellerDto> {
    return this.resellers.get(id);
  }

  @Post()
  @RequirePermission('reseller:create')
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: CreateResellerInput,
  ): Promise<ResellerDto> {
    return this.resellers.create(body, user.userId);
  }

  @Patch(':id')
  @RequirePermission('reseller:update')
  async update(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: UpdateResellerInput,
  ): Promise<ResellerDto> {
    return this.resellers.update(id, body, user.userId);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('reseller:delete')
  async remove(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.resellers.remove(id, user.userId);
  }

  @Get(':id/branding')
  @RequirePermission('reseller:read')
  async getBranding(@Param('id') id: string): Promise<{ branding: Record<string, unknown> }> {
    return this.resellers.getBranding(id);
  }

  @Patch(':id/branding')
  @RequirePermission('reseller:update')
  async updateBranding(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { branding?: unknown },
  ): Promise<{ branding: Record<string, unknown> }> {
    return this.resellers.updateBranding(id, body, user.userId);
  }

  @Post(':id/custom-domain')
  @RequirePermission('reseller:update')
  async setCustomDomain(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { custom_domain?: unknown },
  ): Promise<ResellerDto> {
    return this.resellers.setCustomDomain(id, body, user.userId);
  }

  @Delete(':id/custom-domain')
  @HttpCode(204)
  @RequirePermission('reseller:update')
  async clearCustomDomain(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.resellers.clearCustomDomain(id, user.userId);
  }
}
