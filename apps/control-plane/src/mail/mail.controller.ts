import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Query } from '@nestjs/common';
import { MailService } from './mail.service';
import { RequirePermission, SessionOnly } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Email endpoints (API spec §4.8). `mail:*` permissions are hosting-account
 * scoped (C7): the guard resolves the owning account via the domain id /
 * body account_id and the service mirrors the visibility check (404, §3.2).
 * Mailbox password rotation is additionally @SessionOnly(): a stolen
 * automation token must not be able to mint working mailbox credentials.
 */
@Controller('mail')
export class MailController {
  constructor(private readonly mail: MailService) {}

  @Get('domains')
  @RequirePermission('mail:list')
  async listDomains(
    @CurrentUser() user: AuthContext,
    @Query('account_id') accountId: string,
  ): Promise<{ data: unknown[] }> {
    return this.mail.listDomains(actorOf(user), accountId);
  }

  @Post('domains')
  @RequirePermission('mail:create')
  async createDomain(
    @CurrentUser() user: AuthContext,
    @Body() body: { account_id?: string; name?: string },
  ): Promise<unknown> {
    return this.mail.createDomain(actorOf(user), body);
  }

  @Delete('domains/:id')
  @HttpCode(204)
  @RequirePermission('mail:delete')
  async deleteDomain(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.mail.deleteDomain(actorOf(user), id);
  }

  @Get('domains/:id/mailboxes')
  @RequirePermission('mail:read')
  async listMailboxes(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<{ data: unknown[] }> {
    return this.mail.listMailboxes(actorOf(user), id);
  }

  @Post('domains/:id/mailboxes')
  @RequirePermission('mail:create')
  async createMailbox(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { local_part?: string; password?: string; quota_mb?: number },
  ): Promise<unknown> {
    return this.mail.createMailbox(actorOf(user), id, body);
  }

  @Patch('domains/:id/mailboxes/:mid')
  @RequirePermission('mail:update')
  async updateMailbox(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Param('mid') mailboxId: string,
    @Body() body: { quota_mb?: number },
  ): Promise<unknown> {
    return this.mail.updateMailbox(actorOf(user), id, mailboxId, body);
  }

  @Post('domains/:id/mailboxes/:mid/password')
  @HttpCode(204)
  @RequirePermission('mail:update')
  @SessionOnly()
  async setMailboxPassword(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Param('mid') mailboxId: string,
    @Body() body: { password?: string },
  ): Promise<void> {
    await this.mail.setMailboxPassword(actorOf(user), id, mailboxId, body);
  }

  @Delete('domains/:id/mailboxes/:mid')
  @HttpCode(200)
  @RequirePermission('mail:delete')
  async deleteMailbox(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Param('mid') mailboxId: string,
    @Body() body: { preserve_mail?: boolean },
  ): Promise<unknown> {
    return this.mail.deleteMailbox(actorOf(user), id, mailboxId, body);
  }

  @Get('domains/:id/aliases')
  @RequirePermission('mail:read')
  async listAliases(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<{ data: unknown[] }> {
    return this.mail.listAliases(actorOf(user), id);
  }

  @Post('domains/:id/aliases')
  @RequirePermission('mail:create')
  async createAlias(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { source?: string; destination?: string },
  ): Promise<unknown> {
    return this.mail.createAlias(actorOf(user), id, body);
  }

  @Delete('domains/:id/aliases/:aid')
  @HttpCode(204)
  @RequirePermission('mail:delete')
  async deleteAlias(@CurrentUser() user: AuthContext, @Param('id') id: string, @Param('aid') aliasId: string): Promise<void> {
    await this.mail.deleteAlias(actorOf(user), id, aliasId);
  }

  @Get('domains/:id/autoresponders')
  @RequirePermission('mail:read')
  async listAutoresponders(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<{ data: unknown[] }> {
    return this.mail.listAutoresponders(actorOf(user), id);
  }

  @Post('domains/:id/autoresponders')
  @RequirePermission('mail:create')
  async createAutoresponder(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { mailbox_id?: string; subject?: string; body?: string; starts_at?: string; ends_at?: string },
  ): Promise<unknown> {
    return this.mail.createAutoresponder(actorOf(user), id, body);
  }

  @Delete('domains/:id/autoresponders/:aid')
  @HttpCode(204)
  @RequirePermission('mail:delete')
  async deleteAutoresponder(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Param('aid') autoresponderId: string,
  ): Promise<void> {
    await this.mail.deleteAutoresponder(actorOf(user), id, autoresponderId);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
