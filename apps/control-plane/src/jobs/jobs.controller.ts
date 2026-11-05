import { Controller, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { JobsService } from './jobs.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Job center endpoints (B13). Server-scoped visibility (`job:*` via C6);
 * retrigger is a confirmed action in the UI and audited server-side.
 */
@Controller('jobs')
export class JobsController {
  constructor(private readonly jobs: JobsService) {}

  @Get()
  @RequirePermission('job:list')
  list(@CurrentUser() user: AuthContext, @Query('status') status?: string) {
    return this.jobs.list(status || undefined);
  }

  @Get(':id')
  @RequirePermission('job:list')
  get(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.jobs.get(id);
  }

  @Post(':id/retry')
  @RequirePermission('job:manage')
  retry(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.jobs.retry(actorOf(user), id);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
