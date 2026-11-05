import { Controller, Get } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Public } from '../auth/public.decorator';

/** Platform meta endpoints (API spec §4.25) — unauthenticated. */
@Public()
@Controller()
export class HealthController {
  private readonly startedAt = Date.now();

  constructor(private readonly prisma: PrismaService) {}

  /** Liveness: no DB, no agent. */
  @Get('health')
  health(): Record<string, string> {
    return { status: 'ok' };
  }

  /** Readiness: DB reachability (agent checks are on-demand, not gated). */
  @Get('ready')
  async ready(): Promise<Record<string, string | boolean | number>> {
    let database = 'ok';
    try {
      await this.prisma.$queryRaw`SELECT 1`;
    } catch {
      database = 'error';
    }
    return {
      status: database === 'ok' ? 'ok' : 'degraded',
      database,
      agent: 'on-demand',
      uptime_s: Math.floor((Date.now() - this.startedAt) / 1000),
    };
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
