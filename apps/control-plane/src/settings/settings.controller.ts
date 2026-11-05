import { Body, Controller, Get, Param, Put } from '@nestjs/common';
import { SettingsService, SettingDto } from './settings.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';

/**
 * Server settings routes (P2). `settings:*` permissions are Server-Admin
 * only for now (PermissionsGuard rejects non-super-admins until reseller
 * roles land); the decorators still name the permission so the C6 coverage
 * check and the API-token scope vocabulary stay exact.
 *
 * Server-wide configuration is not a credential surface, so unlike token/2FA
 * routes these are NOT @SessionOnly(): an automation token scoped to
 * settings:write may legitimately manage config (that is the point of C4
 * scopes). Every write still lands in the hash-chained audit log with the
 * actor identity.
 */
@Controller('settings')
export class SettingsController {
  constructor(private readonly settings: SettingsService) {}

  @Get()
  @RequirePermission('settings:read')
  async list(): Promise<{ data: SettingDto[] }> {
    return this.settings.list();
  }

  @Get(':key')
  @RequirePermission('settings:read')
  async get(@Param('key') key: string): Promise<SettingDto> {
    return this.settings.get(key);
  }

  @Put(':key')
  @RequirePermission('settings:write')
  async update(
    @CurrentUser() user: AuthContext,
    @Param('key') key: string,
    @Body() body: { value?: unknown },
  ): Promise<SettingDto> {
    return this.settings.update(key, body?.value, user.userId);
  }
}
