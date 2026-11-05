import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Put, Query } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailDeliverabilityService } from './mail-deliverability.service';
import { RequirePermission, SessionOnly } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Email endpoints (API spec §4.8). `mail:*` permissions are hosting-account
 * scoped (C7): the guard resolves the owning account via the domain id /
 * body account_id and the service mirrors the visibility check (404, §3.2).
 * Mailbox password rotation is additionally @SessionOnly(): a stolen
 * automation token must not be able to mint working mailbox credentials.
 *
 * B08 deliverability additions (ADR-0014): DKIM enable/rotate (DNS record
 * auto-written through the DNS module), SPF/DMARC upserts, server-wide
 * relay profile (GET/PUT/DELETE /mail/relay — §4.8's per-domain routes
 * amended by ADR-0002/0014), and server-wide queue tooling.
 */
@Controller('mail')
export class MailController {
  constructor(
    private readonly mail: MailService,
    private readonly deliverability: MailDeliverabilityService,
  ) {}

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

  // ---- B08: deliverability (ADR-0014) ---------------------------------------

  @Get('domains/:id/dkim')
  @RequirePermission('mail:read')
  async getDkim(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.deliverability.getDkim(actorOf(user), id);
  }

  @Post('domains/:id/dkim')
  @RequirePermission('mail:manage')
  async enableDkim(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { selector?: string },
  ): Promise<unknown> {
    return this.deliverability.enableDkim(actorOf(user), id, body);
  }

  @Post('domains/:id/dkim/rotate')
  @RequirePermission('mail:manage')
  async rotateDkim(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { selector?: string },
  ): Promise<unknown> {
    return this.deliverability.rotateDkim(actorOf(user), id, body);
  }

  @Post('domains/:id/spf')
  @RequirePermission('mail:manage')
  async applySpf(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { record?: string },
  ): Promise<unknown> {
    return this.deliverability.applySpf(actorOf(user), id, body);
  }

  @Post('domains/:id/dmarc')
  @RequirePermission('mail:manage')
  async applyDmarc(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { policy?: string; rua?: string },
  ): Promise<unknown> {
    return this.deliverability.applyDmarc(actorOf(user), id, body);
  }

  // ---- B08: server-wide relay (ADR-0002/0014) ---------------------------------

  @Get('relay')
  @RequirePermission('mail:relay:manage')
  async getRelay(): Promise<unknown> {
    return this.deliverability.getRelay();
  }

  @Put('relay')
  @RequirePermission('mail:relay:manage')
  async putRelay(
    @CurrentUser() user: AuthContext,
    @Body() body: { provider?: string; smtp_host?: string; smtp_port?: number; username?: string; password?: string },
  ): Promise<unknown> {
    return this.deliverability.putRelay(actorOf(user), body);
  }

  @Delete('relay')
  @HttpCode(204)
  @RequirePermission('mail:relay:manage')
  async deleteRelay(@CurrentUser() user: AuthContext): Promise<void> {
    await this.deliverability.deleteRelay(actorOf(user));
  }

  // ---- B08: queue tools (server-wide, §4.8) ------------------------------------

  @Get('queue')
  @RequirePermission('mail:queue:read')
  async queueList(): Promise<unknown> {
    return this.deliverability.queueList();
  }

  @Post('queue/flush')
  @RequirePermission('mail:queue:manage')
  async queueFlush(@CurrentUser() user: AuthContext, @Body() body: { queue_id?: string }): Promise<unknown> {
    return this.deliverability.queueFlush(actorOf(user), body?.queue_id);
  }

  @Post('queue/:id/retry')
  @RequirePermission('mail:queue:manage')
  async queueRetry(@CurrentUser() user: AuthContext, @Param('id') messageId: string): Promise<unknown> {
    return this.deliverability.queueRetry(actorOf(user), messageId);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
