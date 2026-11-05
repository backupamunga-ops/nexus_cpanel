import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Query } from '@nestjs/common';
import { BackupsService } from './backups.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Backup endpoints (API spec §4.16). `backup:*` is a server-wide (admin)
 * family — destinations and jobs are platform resources, not per-account
 * ones — so it stays out of HOSTING_SCOPED_PREFIXES and the guard admits
 * server admins (and tokens explicitly scoped for backup:*, C4).
 *
 * Nothing here returns destination config material: the envelope is
 * decrypted only at the point of an agent call, and every test/restore/
 * verify action is audited with a fingerprint instead (ADR-0015).
 */
@Controller('backups')
export class BackupsController {
  constructor(private readonly backups: BackupsService) {}

  // ---- destinations ----

  @Get('destinations')
  @RequirePermission('backup:list')
  async listDestinations(): Promise<{ data: unknown[] }> {
    return this.backups.listDestinations();
  }

  @Post('destinations')
  @RequirePermission('backup:create')
  async createDestination(
    @CurrentUser() user: AuthContext,
    @Body() body: { name?: string; type?: string; is_default?: boolean; config?: Record<string, unknown> },
  ): Promise<unknown> {
    return this.backups.createDestination(actorOf(user), body);
  }

  @Delete('destinations/:id')
  @HttpCode(204)
  @RequirePermission('backup:delete')
  async deleteDestination(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.backups.deleteDestination(actorOf(user), id);
  }

  @Post('destinations/:id/test')
  @RequirePermission('backup:create')
  async testDestination(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.backups.testDestination(actorOf(user), id);
  }

  // ---- jobs ----

  @Get('jobs')
  @RequirePermission('backup:list')
  async listJobs(): Promise<{ data: unknown[] }> {
    return this.backups.listJobs();
  }

  @Post('jobs')
  @RequirePermission('backup:create')
  async createJob(
    @CurrentUser() user: AuthContext,
    @Body() body: {
      name?: string; scope?: string; scope_id?: string; destination_id?: string;
      schedule?: string; retention_days?: number; keep_daily?: number;
      keep_weekly?: number; keep_monthly?: number; is_enabled?: boolean;
    },
  ): Promise<unknown> {
    return this.backups.createJob(actorOf(user), body);
  }

  @Patch('jobs/:id')
  @RequirePermission('backup:update')
  async updateJob(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { schedule?: string; is_enabled?: boolean; retention_days?: number; keep_daily?: number; keep_weekly?: number; keep_monthly?: number; destination_id?: string },
  ): Promise<unknown> {
    return this.backups.updateJob(actorOf(user), id, body);
  }

  @Delete('jobs/:id')
  @HttpCode(204)
  @RequirePermission('backup:delete')
  async deleteJob(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.backups.deleteJob(actorOf(user), id);
  }

  @Post('jobs/:id/run')
  @RequirePermission('backup:create')
  async runJob(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.backups.runJob(actorOf(user), id);
  }

  @Post('jobs/:id/retention')
  @RequirePermission('backup:update')
  async applyRetention(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    // Increment over §4.16 (B10): manual retention pass — same GFS logic
    // that runs automatically after each successful backup.
    return this.backups.applyRetention(actorOf(user), id);
  }

  // ---- runs ----

  @Get('runs')
  @RequirePermission('backup:list')
  async listRuns(@CurrentUser() user: AuthContext, @Query('job_id') jobId?: string): Promise<{ data: unknown[] }> {
    return this.backups.listRuns(actorOf(user), jobId || undefined);
  }

  @Get('runs/:id')
  @RequirePermission('backup:read')
  async getRun(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.backups.getRun(actorOf(user), id);
  }

  @Post('runs/:id/restore-preview')
  @RequirePermission('backup:restore')
  async restorePreview(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.backups.restorePreview(actorOf(user), id);
  }

  @Post('runs/:id/restore')
  @RequirePermission('backup:restore')
  async restore(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { dry_run?: boolean; target_path?: string },
  ): Promise<unknown> {
    return this.backups.restoreRun(actorOf(user), id, body);
  }

  @Post('runs/:id/verify')
  @RequirePermission('backup:verify')
  async verify(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.backups.verifyRun(actorOf(user), id);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
