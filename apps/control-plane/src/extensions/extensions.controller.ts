import { Body, Controller, Delete, Get, Param, Patch, Post } from '@nestjs/common';
import { ExtensionsService } from './extensions.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Extension admin + lifecycle endpoints (API spec §4.24, P7 / ADR-0021).
 *
 * Server-wide surface — super admins hold `extension:*` via C6; the service
 * re-checks with anti-enumeration 404s (same posture as webhooks). The
 * scope-review ladder lives in the service: install → review → approve
 * (one-time credentials) → operate → disable/uninstall.
 */
@Controller('extensions')
export class ExtensionsController {
  constructor(private readonly extensions: ExtensionsService) {}

  @Get()
  @RequirePermission('extension:list')
  list(@CurrentUser() user: AuthContext) {
    return this.extensions.list(actorOf(user));
  }

  @Get('widgets')
  @RequirePermission('extension:widgets')
  widgets() {
    return this.extensions.widgets();
  }

  @Post('register')
  @RequirePermission('extension:install')
  register(@CurrentUser() user: AuthContext, @Body() body: Record<string, unknown>) {
    return this.extensions.register(actorOf(user), body);
  }

  @Post()
  @RequirePermission('extension:install')
  install(@CurrentUser() user: AuthContext, @Body() body: Record<string, unknown>) {
    return this.extensions.installFromUrl(actorOf(user), body);
  }

  @Get(':id')
  @RequirePermission('extension:list')
  get(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.extensions.get(actorOf(user), id);
  }

  /**
   * Scope review + lifecycle switch (one route per API spec §4.24 PATCH):
   * body {action: "approve" | "reject" | "enable" | "disable"}. approve
   * returns the ONE-TIME credentials — they are never shown again.
   */
  @Patch(':id')
  @RequirePermission('extension:manage')
  manage(@CurrentUser() user: AuthContext, @Param('id') id: string, @Body() body: Record<string, unknown>) {
    const action = typeof body.action === 'string' ? body.action : '';
    switch (action) {
      case 'approve':
        return this.extensions.approve(actorOf(user), id);
      case 'reject':
        return this.extensions.reject(actorOf(user), id).then(() => ({ data: { rejected: true } }));
      case 'enable':
        return this.extensions.enable(actorOf(user), id).then(() => ({ data: { enabled: true } }));
      case 'disable':
        return this.extensions.disable(actorOf(user), id).then(() => ({ data: { disabled: true } }));
      default:
        return Promise.reject(new Error('action must be one of approve|reject|enable|disable'));
    }
  }

  @Delete(':id')
  @RequirePermission('extension:uninstall')
  uninstall(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.extensions.uninstall(actorOf(user), id).then(() => ({ data: { uninstalled: true } }));
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
