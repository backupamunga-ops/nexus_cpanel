import { Body, Controller, Delete, Get, Param, Patch, Post } from '@nestjs/common';
import { WafService } from './waf.service';
import { MalwareService } from './malware.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * WAF & anti-malware endpoints (API spec §4.15a, B12). The `security:*`
 * permissions are server-scoped (C6); account-scoped visibility is
 * re-checked in the services (404, §3.2 anti-enumeration).
 */
@Controller('security')
export class SecurityController {
  constructor(
    private readonly waf: WafService,
    private readonly malware: MalwareService,
  ) {}

  // ---- per-site WAF -------------------------------------------------------

  @Get('modsecurity')
  @RequirePermission('security:read')
  listPolicies(@CurrentUser() user: AuthContext) {
    return this.waf.listPolicies(actorOf(user));
  }

  @Get('modsecurity/:domain_id')
  @RequirePermission('security:read')
  getPolicy(@CurrentUser() user: AuthContext, @Param('domain_id') domainId: string) {
    return this.waf.getPolicy(actorOf(user), domainId);
  }

  @Patch('modsecurity/:domain_id')
  @RequirePermission('security:manage')
  updatePolicy(
    @CurrentUser() user: AuthContext,
    @Param('domain_id') domainId: string,
    @Body() body: { mode?: string; paranoia_level?: number; exclusions?: string[] },
  ) {
    return this.waf.updatePolicy(actorOf(user), domainId, body as Record<string, unknown>);
  }

  // ---- anti-malware -------------------------------------------------------

  @Post('malware/scan')
  @RequirePermission('security:manage')
  scan(
    @CurrentUser() user: AuthContext,
    @Body() body: { scope?: string; account_id?: string; path?: string; move_infected?: boolean },
  ) {
    return this.malware.startScan(actorOf(user), body as Record<string, unknown>);
  }

  @Get('malware/scans')
  @RequirePermission('security:read')
  scans(@CurrentUser() user: AuthContext) {
    return this.malware.listScans(actorOf(user));
  }

  @Get('malware/quarantine')
  @RequirePermission('security:read')
  quarantine(@CurrentUser() user: AuthContext) {
    return this.malware.listQuarantine(actorOf(user));
  }

  @Post('malware/quarantine/:id/restore')
  @RequirePermission('security:manage')
  restoreQuarantine(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { username?: string; rel_path?: string },
  ) {
    return this.malware.restoreFinding(actorOf(user), id, body as Record<string, unknown>);
  }

  @Delete('malware/quarantine/:id')
  @RequirePermission('security:manage')
  deleteQuarantine(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    return this.malware.deleteFinding(actorOf(user), id);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
