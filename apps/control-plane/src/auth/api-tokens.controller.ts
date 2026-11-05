import { Body, Controller, Delete, Get, HttpCode, Param, Post } from '@nestjs/common';
import { ApiTokensService, ApiTokenDto, CreateApiTokenInput } from './api-tokens.service';
import { RequirePermission, SessionOnly } from '../common/permissions';
import { AuthContext, AuthenticatedRequest, CurrentUser } from './request-context';

/**
 * API token lifecycle (C4, API spec §4.3). Every route is the caller's OWN
 * token surface — ownership is scoped to the authenticated user id in the
 * service, never from request data.
 *
 * All routes are @SessionOnly(): an API token must never be able to mint,
 * list, rotate or revoke credentials (stolen-token blast radius). The spec's
 * auth column marks these routes `jwt` — the decorator enforces exactly that.
 */
@Controller('tokens')
@RequirePermission('auth:tokens')
@SessionOnly()
export class TokensController {
  constructor(private readonly tokens: ApiTokensService) {}

  @Get()
  async list(@CurrentUser() user: AuthContext): Promise<{ data: ApiTokenDto[] }> {
    return this.tokens.list(user.userId);
  }

  @Post()
  async create(
    @CurrentUser() user: AuthContext,
    @Body() body: CreateApiTokenInput,
  ): Promise<{ token: string; record: ApiTokenDto }> {
    return this.tokens.create(user.userId, body);
  }

  @Delete(':id')
  @HttpCode(204)
  async revoke(@CurrentUser() user: AuthContext, @Param('id') id: string): Promise<void> {
    await this.tokens.revoke(user.userId, id);
  }

  @Post(':id/rotate')
  async rotate(
    @CurrentUser() user: AuthContext,
    @Param('id') id: string,
  ): Promise<{ token: string; record: ApiTokenDto }> {
    return this.tokens.rotate(user.userId, id);
  }
}
