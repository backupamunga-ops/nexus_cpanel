import { Body, Controller, Get, Param, Post, RawBody, Req } from '@nestjs/common';
import type { Request } from 'express';
import { AppsService } from './apps.service';
import { GitService } from './git.service';
import { RequirePermission } from '../common/permissions';
import { Public } from '../auth/public.decorator';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Apps & Git deploy endpoints (API spec §4.7a, ADR-0019, B14).
 *
 * `apps:*` / `git:*` are account-scoped resources behind the C6 guard:
 * the route permission is the coarse gate, the services re-check
 * account-level visibility with 404 anti-enumeration (§3.2). The webhook
 * receiver is @Public and authenticates by HMAC signature only.
 */
@Controller()
export class AppsController {
  constructor(
    private readonly apps: AppsService,
    private readonly git: GitService,
  ) {}

  // ---- apps ----------------------------------------------------------------

  @Get('apps')
  @RequirePermission('apps:read')
  listApps(@CurrentUser() user: AuthContext) {
    return this.apps.listApps(actorOf(user));
  }

  @Post('apps/install')
  @RequirePermission('apps:manage')
  install(@CurrentUser() user: AuthContext, @Body() body: Record<string, unknown>) {
    return this.apps.installWordPress(actorOf(user), body);
  }

  @Post('apps/:id/update')
  @RequirePermission('apps:manage')
  update(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.apps.updateApp(actorOf(user), id);
  }

  @Post('apps/:id/wp-cli')
  @RequirePermission('apps:manage')
  wpCli(@CurrentUser() user: AuthContext, @Param('id') id: string, @Body() body: { args?: string[] }) {
    return this.apps.runWpCli(actorOf(user), id, body as Record<string, unknown>);
  }

  @Post('apps/:id/staging')
  @RequirePermission('apps:manage')
  staging(@CurrentUser() user: AuthContext, @Param('id') id: string, @Body() body: { label?: string }) {
    return this.apps.createStaging(actorOf(user), id, body as Record<string, unknown>);
  }

  // ---- git push-to-deploy ----------------------------------------------------

  @Get('git')
  @RequirePermission('git:read')
  listGit(@CurrentUser() user: AuthContext) {
    return this.git.listDeployments(actorOf(user));
  }

  @Post('git')
  @RequirePermission('git:manage')
  createGit(@CurrentUser() user: AuthContext, @Body() body: Record<string, unknown>) {
    return this.git.createDeployment(actorOf(user), body);
  }

  @Post('git/:id/deploy')
  @RequirePermission('git:deploy')
  deploy(@CurrentUser() user: AuthContext, @Param('id') id: string, @Body() body: { sha?: string }) {
    return this.git.deployNow(actorOf(user), id, body as Record<string, unknown>);
  }

  @Get('git/:id/history')
  @RequirePermission('git:read')
  history(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.git.history(actorOf(user), id);
  }

  @Post('git/:id/rollback')
  @RequirePermission('git:deploy')
  rollback(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { release_id?: string },
  ) {
    return this.git.rollback(actorOf(user), id, body as Record<string, unknown>);
  }

  /** Push receiver — signature-authenticated (GitHub/GitLab/Bitbucket). */
  @Public()
  @Post('git/webhook/:id')
  webhook(
    @Param('id') id: string,
    @Req() req: Request,
    @RawBody() rawBody: Buffer,
  ) {
    return this.git.handleWebhook(id, req.headers as Record<string, string | string[] | undefined>, rawBody);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
