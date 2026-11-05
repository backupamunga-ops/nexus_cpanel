import { Body, Controller, Delete, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { SshKeysService, SshKeyDto } from './sshkeys.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * SSH key endpoints (API spec §4.13). `ssh:read`/`ssh:manage` are
 * hosting-account-scoped: the guard resolves the account (query for the
 * collection, the key's FK chain for :id routes) and the service mirrors
 * the visibility check (404, §3.2).
 */
@Controller('ssh/keys')
export class SshKeysController {
  constructor(private readonly sshKeys: SshKeysService) {}

  @Get()
  @RequirePermission('ssh:read')
  async list(
    @CurrentUser() user: AuthContext,
    @Query('account_id') accountId: string,
  ): Promise<{ data: SshKeyDto[] }> {
    return this.sshKeys.list(actorOf(user), accountId);
  }

  @Post()
  @RequirePermission('ssh:manage')
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: { account_id?: string; name?: string; public_key?: string },
  ): Promise<SshKeyDto> {
    return this.sshKeys.create(actorOf(user), body);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('ssh:manage')
  async remove(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.sshKeys.remove(actorOf(user), id);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
