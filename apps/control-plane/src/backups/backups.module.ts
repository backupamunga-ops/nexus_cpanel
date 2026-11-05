import { Module } from '@nestjs/common';
import { BackupsController } from './backups.controller';
import { BackupsService } from './backups.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

/**
 * Backups module (B10, API spec §4.16): destinations, jobs, runs,
 * restore-with-preview and GFS retention. The agent does the node-side
 * work (tar/age/upload); this module owns the registry and the journal.
 */
@Module({
  imports: [AgentModule, AuditModule],
  controllers: [BackupsController],
  providers: [BackupsService],
  exports: [BackupsService],
})
export class BackupsModule {}
