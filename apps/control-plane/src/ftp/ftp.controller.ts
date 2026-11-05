import { Body, Controller, Delete, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { FtpService, FtpAccountDto } from './ftp.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * FTP endpoints (API spec §4.12). `ftp:*` permissions are
 * hosting-account-scoped (C7): the guard resolves the owning account and
 * the service mirrors the visibility check (404, §3.2).
 */
@Controller('ftp')
export class FtpController {
  constructor(private readonly ftp: FtpService) {}

  @Get()
  @RequirePermission('ftp:list')
  async list(@CurrentUser() user: AuthContext, @Query('account_id') accountId: string): Promise<{ data: FtpAccountDto[] }> {
    return this.ftp.list(actorOf(user), accountId);
  }

  @Post()
  @RequirePermission('ftp:create')
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: { account_id?: string; username?: string; password?: string; root_dir?: string; read_only?: boolean },
  ): Promise<FtpAccountDto> {
    return this.ftp.create(actorOf(user), body);
  }

  @Post(':id/password')
  @RequirePermission('ftp:update')
  @HttpCode(204)
  async setPassword(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { password?: string },
  ): Promise<void> {
    await this.ftp.setPassword(actorOf(user), id, body);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('ftp:delete')
  async remove(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.ftp.remove(actorOf(user), id);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
