import { Module } from '@nestjs/common';
import { SecurityController } from './security.controller';
import { WafService } from './waf.service';
import { MalwareService } from './malware.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

/**
 * Security module (B12, ADR-0017): per-site ModSecurity policies +
 * ClamAV scan/quarantine flows.
 */
@Module({
  imports: [AgentModule, AuditModule],
  controllers: [SecurityController],
  providers: [WafService, MalwareService],
  exports: [WafService, MalwareService],
})
export class SecurityModule {}
