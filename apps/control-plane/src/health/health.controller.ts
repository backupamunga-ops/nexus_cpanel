import { Controller, Get } from '@nestjs/common';

/** Platform meta endpoints (API spec §4.25). */
@Controller()
export class HealthController {
  private readonly startedAt = Date.now();

  /** Liveness: no DB, no agent. */
  @Get('health')
  health(): Record<string, string> {
    return { status: 'ok' };
  }

  /** Readiness: DB + agent reachability (enforced from P1 when Prisma lands). */
  @Get('ready')
  ready(): Record<string, string | boolean> {
    return { status: 'ok', database: 'pending-p1', agent: 'on-demand' };
  }

  /** Panel version, agent protocol version, schema version. */
  @Get('version')
  version(): Record<string, string> {
    return {
      panel: '0.1.0-m0',
      agent_protocol: '1.0',
      schema: '2.0',
      api: 'v1',
    };
  }

  @Get('uptime')
  uptime(): Record<string, number> {
    return { uptime_seconds: Math.floor((Date.now() - this.startedAt) / 1000) };
  }
}
