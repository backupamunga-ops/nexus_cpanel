import { Module } from '@nestjs/common';
import { DnsController } from './dns.controller';
import { DnsService } from './dns.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

/**
 * DNS zones & records (API spec §4.9, ADR-0012). PowerDNS on the node is
 * authoritative; this module owns the mirror registry + the API surface.
 */
@Module({
  imports: [AgentModule, AuditModule],
  controllers: [DnsController],
  providers: [DnsService],
  exports: [DnsService],
})
export class DnsModule {}
