import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
import { FirewallService } from './firewall.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Firewall & fail2ban endpoints (API spec §4.17). Server-scoped surface:
 * `firewall:*` is NOT hosting-account scoped — the PermissionsGuard grants
 * it to server admins (C6), and the service re-checks (defense in depth).
 */
@Controller('firewall')
export class FirewallController {
  constructor(private readonly firewall: FirewallService) {}

  @Get('rules')
  @RequirePermission('firewall:read')
  listRules(@CurrentUser() user: AuthContext) {
    return this.firewall.listRules(actorOf(user));
  }

  @Post('rules')
  @RequirePermission('firewall:manage')
  createRule(@CurrentUser() user: AuthContext, @Body() body: Record<string, unknown>) {
    return this.firewall.createRule(actorOf(user), body);
  }

  @Patch('rules/:id')
  @RequirePermission('firewall:manage')
  updateRule(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: Record<string, unknown>,
  ) {
    return this.firewall.updateRule(actorOf(user), id, body);
  }

  @Delete('rules/:id')
  @HttpCode(204)
  @RequirePermission('firewall:manage')
  deleteRule(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    return this.firewall.deleteRule(actorOf(user), id);
  }

  @Get('status')
  @RequirePermission('firewall:read')
  status(@CurrentUser() user: AuthContext) {
    return this.firewall.status(actorOf(user));
  }

  @Get('fail2ban/jails')
  @RequirePermission('firewall:read')
  jails(@CurrentUser() user: AuthContext) {
    return this.firewall.jails(actorOf(user));
  }

  @Post('fail2ban/unban')
  @RequirePermission('firewall:manage')
  unban(
    @CurrentUser() user: AuthContext,
    @Body() body: { jail?: string; ip?: string },
  ) {
    return this.firewall.unban(actorOf(user), String(body.jail ?? ''), String(body.ip ?? ''));
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
