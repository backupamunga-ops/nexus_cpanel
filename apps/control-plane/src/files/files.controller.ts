import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Query,
} from '@nestjs/common';
import { FilesService, FileEntryDto, TrashEntryDto } from './files.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * File manager endpoints (API spec §4.11). `file:*` permissions are
 * hosting-account-scoped (guard resolves the account from query/body) and
 * the service re-verifies visibility — an account you cannot see does not
 * exist (404, §3.2). Every mutation is audited; deletes go through the
 * 30-day trash, never straight to the void.
 *
 * The composite /files endpoints of the spec that move whole trees
 * (archive/extract/search) and FTP land with later amendments; the core
 * browse/read/write/mkdir/delete/chmod/trash surface is complete here.
 */
@Controller('files')
export class FilesController {
  constructor(private readonly files: FilesService) {}

  @Get()
  @RequirePermission('file:read')
  async list(
    @CurrentUser() user: AuthContext,
    @Query('account_id') accountId: string,
    @Query('path') path: string,
  ): Promise<{ path: string; entries: FileEntryDto[]; total: number }> {
    return this.files.list(actorOf(user), accountId, path);
  }

  @Get('usage')
  @RequirePermission('file:read')
  async usage(
    @CurrentUser() user: AuthContext,
    @Query('account_id') accountId: string,
  ): Promise<{ bytes: number; inodes: number; partial: boolean }> {
    return this.files.usage(actorOf(user), accountId);
  }

  @Get('trash')
  @RequirePermission('file:read')
  async listTrash(
    @CurrentUser() user: AuthContext,
    @Query('account_id') accountId: string,
  ): Promise<{ data: TrashEntryDto[] }> {
    return this.files.listTrash(actorOf(user), accountId);
  }

  @Post('trash/purge')
  @HttpCode(200)
  @RequirePermission('file:delete')
  async purgeTrash(
    @CurrentUser() user: AuthContext,
    @Body() body: { account_id?: string },
  ): Promise<{ removed: number }> {
    return this.files.purgeTrash(actorOf(user), body?.account_id);
  }

  @Post('trash/:id/restore')
  @RequirePermission('file:write')
  async restoreTrash(@CurrentUser() user: AuthContext, @Param('id') id: string) {
    return this.files.restoreTrash(actorOf(user), id);
  }

  @Delete('trash/:id')
  @HttpCode(204)
  @RequirePermission('file:delete')
  async deleteTrashEntry(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.files.deleteTrashEntry(actorOf(user), id);
  }

  @Get('download')
  @RequirePermission('file:read')
  async download(
    @CurrentUser() user: AuthContext,
    @Query('account_id') accountId: string,
    @Query('path') path: string,
  ) {
    return this.files.read(actorOf(user), accountId, path);
  }

  @Post('mkdir')
  @RequirePermission('file:write')
  async mkdir(@CurrentUser() user: AuthContext, @Body() body: { account_id?: string; path?: string; mode?: number }) {
    return this.files.mkdir(actorOf(user), body);
  }

  @Post('upload')
  @RequirePermission('file:write')
  async upload(
    @CurrentUser() user: AuthContext,
    @Body() body: { account_id?: string; path?: string; content_b64?: string; overwrite?: boolean; mode?: number },
  ) {
    return this.files.write(actorOf(user), body);
  }

  @Post('chmod')
  @RequirePermission('file:write')
  async chmod(@CurrentUser() user: AuthContext, @Body() body: { account_id?: string; path?: string; mode?: number }) {
    return this.files.chmod(actorOf(user), body);
  }

  @Post('delete')
  @RequirePermission('file:delete')
  async delete(@CurrentUser() user: AuthContext, @Body() body: { account_id?: string; path?: string }) {
    return this.files.deleteToTrash(actorOf(user), body);
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
