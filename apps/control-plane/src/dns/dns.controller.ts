import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Query } from '@nestjs/common';
import { DnsService, DnsRecordDto, DnsZoneDto } from './dns.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * DNS endpoints (API spec §4.9). `dns:*` permissions are hosting-account
 * scoped (C7): the guard resolves the owning account via the zone / body /
 * query and the service mirrors the visibility check (404, §3.2).
 */
@Controller('dns')
export class DnsController {
  constructor(private readonly dns: DnsService) {}

  @Get('zones')
  @RequirePermission('dns:list')
  async listZones(
    @CurrentUser() user: AuthContext,
    @Query('account_id') accountId: string,
  ): Promise<{ data: DnsZoneDto[] }> {
    return this.dns.listZones(actorOf(user), accountId);
  }

  @Post('zones')
  @RequirePermission('dns:create')
  async createZone(
    @CurrentUser() user: AuthContext,
    @Body() body: { account_id?: string; name?: string; records?: unknown[] },
  ): Promise<DnsZoneDto> {
    return this.dns.createZone(actorOf(user), body);
  }

  @Get('zones/:id')
  @RequirePermission('dns:read')
  async getZone(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<DnsZoneDto> {
    return this.dns.getZone(actorOf(user), id);
  }

  @Delete('zones/:id')
  @HttpCode(204)
  @RequirePermission('dns:delete')
  async deleteZone(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.dns.deleteZone(actorOf(user), id);
  }

  @Get('zones/:id/records')
  @RequirePermission('dns:read')
  async listRecords(@CurrentUser() user: AuthContext, @Param('id') zoneId: string): Promise<{ data: DnsRecordDto[] }> {
    return this.dns.listRecords(actorOf(user), zoneId);
  }

  @Post('zones/:id/records')
  @RequirePermission('dns:create')
  async addRecord(
    @CurrentUser() user: AuthContext,
    @Param('id') zoneId: string,
    @Body() body: Record<string, unknown>,
  ): Promise<DnsRecordDto> {
    return this.dns.addRecord(actorOf(user), zoneId, body);
  }

  @Patch('zones/:id/records/:rid')
  @RequirePermission('dns:update')
  async updateRecord(
    @CurrentUser() user: AuthContext,
    @Param('id') zoneId: string,
    @Param('rid') recordId: string,
    @Body() body: Record<string, unknown>,
  ): Promise<DnsRecordDto> {
    return this.dns.updateRecord(actorOf(user), zoneId, recordId, body);
  }

  @Delete('zones/:id/records/:rid')
  @HttpCode(204)
  @RequirePermission('dns:delete')
  async deleteRecord(
    @CurrentUser() user: AuthContext,
    @Param('id') zoneId: string,
    @Param('rid') recordId: string,
  ): Promise<void> {
    await this.dns.deleteRecord(actorOf(user), zoneId, recordId);
  }

  @Get('zones/:id/export')
  @RequirePermission('dns:read')
  async exportZone(
    @CurrentUser() user: AuthContext,
    @Param('id') zoneId: string,
  ): Promise<{ zone: string; content: string }> {
    return this.dns.exportZone(actorOf(user), zoneId);
  }

  @Get('zones/:id/dnssec')
  @RequirePermission('dns:read')
  async getDnssec(@CurrentUser() user: AuthContext, @Param('id') zoneId: string) {
    return this.dns.getDnssec(actorOf(user), zoneId);
  }

  @Post('zones/:id/dnssec/enable')
  @RequirePermission('dns:manage')
  async enableDnssec(@CurrentUser() user: AuthContext, @Param('id') zoneId: string) {
    return this.dns.enableDnssec(actorOf(user), zoneId);
  }

  @Post('zones/:id/dnssec/disable')
  @HttpCode(204)
  @RequirePermission('dns:manage')
  async disableDnssec(@CurrentUser() user: AuthContext, @Param('id') zoneId: string): Promise<void> {
    await this.dns.disableDnssec(actorOf(user), zoneId);
  }

  @Post('zones/:id/zone-check')
  @RequirePermission('dns:read')
  async zoneCheck(@CurrentUser() user: AuthContext, @Param('id') zoneId: string) {
    return this.dns.zoneCheck(actorOf(user), zoneId);
  }

  @Post('zones/:id/check-propagation')
  @RequirePermission('dns:read')
  async checkPropagation(
    @CurrentUser() user: AuthContext,
    @Param('id') zoneId: string,
    @Body() body: { resolvers?: string[] },
  ) {
    return this.dns.checkPropagation(actorOf(user), zoneId, body?.resolvers);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
