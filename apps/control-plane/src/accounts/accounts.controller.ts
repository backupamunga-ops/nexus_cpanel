import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { AccountsService } from './accounts.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';

/** Hosting account endpoints (API spec §4.4) — M0 slice. */
@Controller('accounts')
export class AccountsController {
  constructor(private readonly accounts: AccountsService) {}

  @Get()
  @RequirePermission('account:list')
  async list(@CurrentUser() user: AuthContext): Promise<unknown> {
    return this.accounts.list(user);
  }

  @Get(':id')
  @RequirePermission('account:read')
  async get(@Param('id') id: string): Promise<unknown> {
    return this.accounts.get(id);
  }

  @Post()
  @RequirePermission('account:create')
  async create(
    @Body() body: { username?: string; package_id?: string },
    @CurrentUser() user: AuthContext,
  ): Promise<unknown> {
    return this.accounts.create(
      String(body.username ?? ''),
      String(body.package_id ?? 'pkg-default'),
      user.userId,
    );
  }

  /**
   * PATCH /accounts/{id}: applies per-account quota overrides
   * (`{ quotas: {...} }`). Package/primary-domain changes follow when those
   * features land; quota overrides are the piece the agent can enforce now.
   */
  @Patch(':id')
  @RequirePermission('account:update')
  async update(
    @Param('id') id: string,
    @Body() body: { quotas?: unknown },
    @CurrentUser() user: AuthContext,
  ): Promise<unknown> {
    return this.accounts.updateQuotas(id, body.quotas, user.userId);
  }

  @Get(':id/usage')
  @RequirePermission('account:read')
  async usage(@Param('id') id: string): Promise<unknown> {
    return this.accounts.usage(id);
  }

  @Post(':id/suspend')
  @RequirePermission('account:suspend')
  async suspend(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<unknown> {
    return this.accounts.suspend(id, user.userId);
  }

  @Post(':id/resume')
  @RequirePermission('account:resume')
  async resume(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<unknown> {
    return this.accounts.resume(id, user.userId);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('account:delete')
  async remove(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<void> {
    await this.accounts.remove(id, user.userId);
  }
}
