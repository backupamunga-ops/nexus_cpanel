import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { AuditService } from './audit.service';
import { RequirePermission } from '../common/permissions';

/** Audit endpoints (API spec §4.20). */
@Controller('audit')
export class AuditController {
  constructor(private readonly audit: AuditService) {}

  @Get('entries')
  @RequirePermission('audit:list')
  entries(@Query('limit') limit?: string): unknown {
    const n = Math.min(Number(limit) || 50, 200);
    return {
      data: this.audit.list().slice(-n).map(serialized),
      pagination: { has_more: false, limit: n },
    };
  }

  /** Chain verification (security model §4): POST /api/v1/audit/verify */
  @Post('verify')
  @RequirePermission('audit:verify')
  verify(@Body() body: { from_id?: string; to_id?: string }): unknown {
    // M0 verifies the in-memory chain; P1 adds the persisted-range variant.
    void body;
    return this.audit.verify();
  }

  @Get('head')
  @RequirePermission('audit:list')
  head(): unknown {
    return { head: this.audit.headHex() };
  }
}

function serialized(e: ReturnType<AuditService['list']>[number]): unknown {
  return {
    id: e.id,
    occurred_at: e.occurredAt.toISOString(),
    actor_user_id: e.actorUserId,
    operation: e.operation,
    parameters: e.parameters,
    outcome: e.outcome,
    prior_hash: e.priorHash.toString('hex'),
    this_hash: e.thisHash.toString('hex'),
  };
}
