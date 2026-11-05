import { Body, Controller, Delete, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { DatabasesService } from './databases.service';
import { RequirePermission, SessionOnly } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Database endpoints (API spec §4.10). `db:*` permissions are hosting-account
 * scoped (C7): the guard resolves the owning account via the database id /
 * body account_id and the service mirrors the visibility check (404, §3.2).
 *
 * Credential surfaces (connection string, reveal, phpMyAdmin SSO) are
 * @SessionOnly(): a stolen automation token must not be able to harvest
 * working database credentials (ADR-0015).
 */
@Controller('databases')
export class DatabasesController {
  constructor(private readonly databases: DatabasesService) {}

  @Get()
  @RequirePermission('db:list')
  async list(@CurrentUser() user: AuthContext, @Query('account_id') accountId: string): Promise<{ data: unknown[] }> {
    return this.databases.list(actorOf(user), accountId);
  }

  @Post()
  @RequirePermission('db:create')
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: { account_id?: string; engine?: string; name?: string; db_user?: string; password?: string; host?: string },
  ): Promise<unknown> {
    return this.databases.create(actorOf(user), body);
  }

  @Get(':id')
  @RequirePermission('db:read')
  async get(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    // §4.10 get: reuse the size read (row + cached size) — one honest lookup.
    return this.databases.refreshSize(actorOf(user), id);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('db:delete')
  async remove(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { drop_user?: boolean },
  ): Promise<void> {
    await this.databases.remove(actorOf(user), id, body);
  }

  @Get(':id/users')
  @RequirePermission('db:read')
  async listUsers(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<{ data: unknown[] }> {
    return this.databases.listUsers(actorOf(user), id);
  }

  @Post(':id/users')
  @RequirePermission('db:manage')
  async createUser(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Body() body: { user?: string; password?: string; host?: string },
  ): Promise<unknown> {
    return this.databases.createUser(actorOf(user), id, body);
  }

  @Delete(':id/users/:uid')
  @HttpCode(204)
  @RequirePermission('db:manage')
  async deleteUser(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
    @Param('uid') dbUser: string,
    @Query('host') host?: string,
  ): Promise<void> {
    await this.databases.deleteUser(actorOf(user), id, dbUser, host || 'localhost');
  }

  @Post(':id/size')
  @RequirePermission('db:read')
  async refreshSize(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.databases.refreshSize(actorOf(user), id);
  }

  @Post(':id/dump')
  @RequirePermission('db:backup')
  async dump(@CurrentUser() user: AuthContext, @Param('id') id: string, @Body() body: { output_path?: string }): Promise<unknown> {
    return this.databases.dump(actorOf(user), id, body);
  }

  @Post(':id/restore')
  @RequirePermission('db:restore')
  async restore(@CurrentUser() user: AuthContext, @Param('id') id: string, @Body() body: { input_path?: string }): Promise<unknown> {
    return this.databases.restore(actorOf(user), id, body);
  }

  @Post(':id/connection-string')
  @RequirePermission('db:read')
  @SessionOnly()
  async connectionString(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.databases.connectionString(actorOf(user), id);
  }

  @Post(':id/reveal')
  @RequirePermission('db:read')
  @SessionOnly()
  async reveal(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.databases.revealPassword(actorOf(user), id);
  }

  @Post(':id/phpmyadmin-sso')
  @RequirePermission('db:read')
  @SessionOnly()
  async phpmyadminSso(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<unknown> {
    return this.databases.phpmyadminSso(actorOf(user), id);
  }
}


function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
