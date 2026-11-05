import { Module } from '@nestjs/common';
import { SitesController } from './sites.controller';
import { SitesService } from './sites.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  controllers: [SitesController],
  imports: [AgentModule, AuditModule],
  providers: [SitesService],
  exports: [SitesService],
})
export class SitesModule {}
