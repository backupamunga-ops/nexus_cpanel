import { Body, Controller, Delete, Get, HttpCode, Param, Post } from '@nestjs/common';
import { AccountsService } from './accounts.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';

/** Hosting account endpoints (API spec §4.4) — M0 slice. */
@Controller('accounts')
export class AccountsController {
  constructor(private readonly accounts: AccountsService) {}

  @Get()
  @RequirePermission('account:list')
  list(): unknown {
    return this.accounts.list();
  }

  @Post()
  @RequirePermission('account:create')
  async create(
    @Body() body: { username?: string; package_id?: string },
    @CurrentUser() user: AuthContext,
  ): Promise<unknown> {
    return this.accounts.create(String(body.username ?? ''), String(body.package_id ?? 'pkg-default'), user.userId);
  }

  @Get(':username/usage')
  @RequirePermission('account:read')
  async usage(@Param('username') username: string): Promise<unknown> {
    return this.accounts.usage(username);
  }

  @Post(':username/suspend')
  @RequirePermission('account:suspend')
  async suspend(@Param('username') username: string, @CurrentUser() user: AuthContext): Promise<unknown> {
    return this.accounts.suspend(username, user.userId);
  }

  @Delete(':username')
  @HttpCode(204)
  @RequirePermission('account:delete')
  async remove(@Param('username') username: string, @CurrentUser() user: AuthContext): Promise<void> {
    await this.accounts.remove(username, user.userId);
  }
}
