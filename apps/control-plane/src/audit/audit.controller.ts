import { Controller, Get, Param, Post, Query } from '@nestjs/common';
import { DatabaseAuditService } from './audit.service';
import { RequirePermission } from '../common/permissions';

/** Audit endpoints (API spec §4.20) — persisted hash-chain store (C11). */
@Controller('audit')
export class AuditController {
  constructor(private readonly audit: DatabaseAuditService) {}

  @Get('entries')
  @RequirePermission('audit:list')
  async entries(
    @Query('limit') limit?: string,
    @Query('before_id') beforeId?: string,
  ): Promise<unknown> {
    const n = Math.min(Math.max(Number(limit) || 50, 1), 200);
    const { data, hasMore } = await this.audit.list(n, beforeId);
    return {
      data: data.map((e) => ({
        id: e.id,
        occurred_at: e.occurredAt.toISOString(),
        actor_user_id: e.actorUserId,
        operation: e.operation,
        parameters: e.parameters,
        outcome: e.outcome,
        prior_hash: e.priorHash.toString('hex'),
        this_hash: e.thisHash.toString('hex'),
      })),
      pagination: { has_more: hasMore, limit: n, next_cursor: hasMore ? data[data.length - 1]!.id : null },
    };
  }

  @Get('entries/:id')
  @RequirePermission('audit:read')
  async entry(@Param('id') id: string): Promise<unknown> {
    return this.audit.get(id);
  }

  /** Chain verification (security model §4): POST /api/v1/audit/verify */
  @Post('verify')
  @RequirePermission('audit:verify')
  verify(): Promise<unknown> {
    return this.audit.verify();
  }

  @Get('head')
  @RequirePermission('audit:list')
  async head(): Promise<unknown> {
    return { head: await this.audit.headHex() };
  }
}
