import { Module } from '@nestjs/common';
import { DatabasesController } from './databases.controller';
import { DatabasesService } from './databases.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

/**
 * Databases (B09, ADR-0001/0015) — §4.10, MariaDB-only via the agent's
 * DatabaseEngineAdapter seam; SecretBox credentials at rest (ADR-0009).
 */
@Module({
  imports: [AgentModule, AuditModule],
  controllers: [DatabasesController],
  providers: [DatabasesService],
})
export class DatabasesModule {}
