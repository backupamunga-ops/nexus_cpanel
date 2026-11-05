import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
import { WebhooksService } from './webhooks.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Webhook endpoints (API spec §4.22, extended at B13 with redrive + test).
 * Server-wide surface — super admins hold `webhook:*` via C6; the service
 * re-checks (defense in depth, anti-enumeration 404s).
 */
@Controller('webhooks')
export class WebhooksController {
  constructor(private readonly webhooks: WebhooksService) {}

  @Get()
  @RequirePermission('webhook:list')
  list(@CurrentUser() user: AuthContext) {
    return this.webhooks.list(actorOf(user));
  }

  @Post()
  @RequirePermission('webhook:create')
  create(@CurrentUser() user: AuthContext, @Body() body: Record<string, unknown>) {
    return this.webhooks.create(actorOf(user), body);
  }

  @Patch(':id')
  @RequirePermission('webhook:update')
  update(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: Record<string, unknown>,
  ) {
    return this.webhooks.update(actorOf(user), id, body);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('webhook:delete')
  delete(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    return this.webhooks.delete(actorOf(user), id);
  }

  @Get(':id/deliveries')
  @RequirePermission('webhook:read')
  deliveries(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.webhooks.deliveries(actorOf(user), id);
  }

  @Post(':id/test')
  @RequirePermission('webhook:update')
  test(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.webhooks.test(actorOf(user), id);
  }

  @Post(':id/deliveries/:did/redrive')
  @RequirePermission('webhook:update')
  redrive(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Param('did') deliveryId: string,
  ) {
    return this.webhooks.redrive(actorOf(user), id, deliveryId);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
