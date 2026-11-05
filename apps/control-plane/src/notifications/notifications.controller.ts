import { Controller, Get, HttpCode, Param, Post } from '@nestjs/common';
import { NotificationsService } from './notifications.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';

/**
 * Notification endpoints (API spec §4.23) — own-scope only: every route
 * filters by the session user; there is no cross-user read.
 */
@Controller('notifications')
export class NotificationsController {
  constructor(private readonly notifications: NotificationsService) {}

  @Get()
  @RequirePermission('notification:read')
  list(@CurrentUser() user: AuthContext) {
    return this.notifications.listMine(user.userId);
  }

  @Post(':id/read')
  @HttpCode(204)
  @RequirePermission('notification:manage')
  async markRead(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.notifications.markRead(user.userId, id);
  }

  @Post('read-all')
  @HttpCode(204)
  @RequirePermission('notification:manage')
  async markAllRead(@CurrentUser() user: AuthContext): Promise<void> {
    await this.notifications.markAllRead(user.userId);
  }
}
