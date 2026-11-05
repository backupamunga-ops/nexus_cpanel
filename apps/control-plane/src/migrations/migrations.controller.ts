import { Body, Controller, Delete, Get, HttpCode, Param, Post } from '@nestjs/common';
import { MigrationsService } from './migrations.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Migration endpoints (API spec §4.21, migration spec M15). `migration:*`
 * is a server-wide (admin) family — migrations move accounts onto the
 * node, they are not per-account resources — so it stays out of
 * HOSTING_SCOPED_PREFIXES and the guard admits server admins (and tokens
 * explicitly scoped for migration:*, C4). Every state transition is
 * audited; the report (the acceptance artifact) is audited too and can be
 * re-generated any time.
 */
@Controller('migrations')
export class MigrationsController {
  constructor(private readonly migrations: MigrationsService) {}

  @Get()
  @RequirePermission('migration:list')
  async list(): Promise<{ data: unknown[] }> {
    return this.migrations.list();
  }

  /** The agent's migration shelf — cpmove files staged for import (B15 addition to §4.21). */
  @Get('artifacts')
  @RequirePermission('migration:list')
  async artifacts(): Promise<{ root: string; artifacts: unknown[] }> {
    return this.migrations.listArtifacts();
  }

  @Post()
  @RequirePermission('migration:create')
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: { artifact?: string; target_account_id?: string },
  ): Promise<unknown> {
    return this.migrations.create(actorOf(user), body);
  }

  @Get(':id')
  @RequirePermission('migration:read')
  async get(@Param('id') id: string): Promise<unknown> {
    return this.migrations.get(id);
  }

  @Post(':id/analyze')
  @HttpCode(200)
  @RequirePermission('migration:analyze')
  async analyze(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.migrations.analyze(actorOf(user), id);
  }

  @Post(':id/dry-run')
  @HttpCode(200)
  @RequirePermission('migration:execute')
  async dryRun(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.migrations.dryRun(actorOf(user), id);
  }

  @Post(':id/execute')
  @HttpCode(200)
  @RequirePermission('migration:execute')
  async execute(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.migrations.execute(actorOf(user), id);
  }

  @Get(':id/report')
  @RequirePermission('migration:read')
  async report(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.migrations.report(actorOf(user), id);
  }

  @Post(':id/cancel')
  @HttpCode(200)
  @RequirePermission('migration:execute')
  async cancel(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.migrations.cancel(actorOf(user), id);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('migration:delete')
  async remove(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.migrations.remove(actorOf(user), id);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
