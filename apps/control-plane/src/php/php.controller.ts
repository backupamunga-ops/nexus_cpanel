import { Body, Controller, Get, Param, Patch } from '@nestjs/common';
import { PhpService, PhpViewDto } from './php.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Per-site PHP endpoints (API spec §4.7): GET uses site:read (viewing the
 * PHP settings is part of viewing the site); PATCH uses php:manage (the
 * permission the spec names for pool management).
 */
@Controller()
export class PhpController {
  constructor(private readonly php: PhpService) {}

  @Get('domains/:id/php')
  @RequirePermission('site:read')
  async getForDomain(@Param('id') id: string, @CurrentUser() user: AuthContext): Promise<PhpViewDto> {
    return this.php.getForDomain(id, actorOf(user));
  }

  @Patch('domains/:id/php')
  @RequirePermission('php:manage')
  async update(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Body() body: { php_version?: string | null; pool?: unknown },
  ): Promise<PhpViewDto> {
    return this.php.update(id, body, actorOf(user));
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
