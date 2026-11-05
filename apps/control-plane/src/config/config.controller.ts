import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
} from '@nestjs/common';
import {
  ConfigService,
  ConfigVersionDto,
  ConfigTransactionDto,
  DriftEventDto,
} from './config.service';
import { RequirePermission } from '../common/permissions';
import { AuthContext, CurrentUser } from '../auth/request-context';
import { Actor } from '../sites/sites.service';

/**
 * Config-engine endpoints (§4.5 behaviors behind a control-plane API —
 * amendment noted in the module docs; the API design doc predates the
 * engine's inspection surface). config:read inspects; config:manage rolls
 * back, runs drift checks and resolves events.
 */
@Controller('config')
export class ConfigController {
  constructor(private readonly config: ConfigService) {}

  @Get(':targetType/:targetId/versions')
  @RequirePermission('config:read')
  async versions(
    @Param('targetType') targetType: string,
    @Param('targetId') targetId: string,
    @CurrentUser() user: AuthContext,
  ): Promise<{ data: ConfigVersionDto[] }> {
    return this.config.versions(targetType, targetId, actorOf(user));
  }

  @Get(':targetType/:targetId/versions/:versionId')
  @RequirePermission('config:read')
  async versionContent(
    @Param('targetType') targetType: string,
    @Param('targetId') targetId: string,
    @Param('versionId') versionId: string,
    @CurrentUser() user: AuthContext,
  ) {
    return this.config.versionContent(targetType, targetId, versionId, actorOf(user));
  }

  @Get(':targetType/:targetId/transactions')
  @RequirePermission('config:read')
  async transactions(
    @Param('targetType') targetType: string,
    @Param('targetId') targetId: string,
    @CurrentUser() user: AuthContext,
  ): Promise<{ data: ConfigTransactionDto[] }> {
    return this.config.transactions(targetType, targetId, actorOf(user));
  }

  @Post(':targetType/:targetId/rollback/:versionId')
  @HttpCode(200)
  @RequirePermission('config:manage')
  async rollback(
    @Param('targetType') targetType: string,
    @Param('targetId') targetId: string,
    @Param('versionId') versionId: string,
    @CurrentUser() user: AuthContext,
  ): Promise<ConfigVersionDto> {
    return this.config.rollback(targetType, targetId, versionId, actorOf(user));
  }

  @Post(':targetType/:targetId/drift-check')
  @HttpCode(200)
  @RequirePermission('config:manage')
  async driftCheck(
    @Param('targetType') targetType: string,
    @Param('targetId') targetId: string,
    @CurrentUser() user: AuthContext,
  ): Promise<{ matches: boolean; exists: boolean; drift_event_id: string | null }> {
    return this.config.driftCheck(targetType, targetId, actorOf(user));
  }

  @Get('drift')
  @RequirePermission('config:read')
  async driftEvents(@CurrentUser() user: AuthContext): Promise<{ data: DriftEventDto[] }> {
    return this.config.driftEvents(actorOf(user));
  }

  @Post('drift/:id/resolve')
  @RequirePermission('config:manage')
  async resolveDrift(
    @Param('id') id: string,
    @CurrentUser() user: AuthContext,
    @Body() body: { resolution?: string },
  ): Promise<DriftEventDto> {
    return this.config.resolveDrift(id, body?.resolution, actorOf(user));
  }
}

function actorOf(user: AuthContext): Actor {
  return { userId: user.userId, isSuperAdmin: user.isSuperAdmin };
}
