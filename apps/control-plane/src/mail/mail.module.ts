import { Module } from '@nestjs/common';
import { MailController } from './mail.controller';
import { MailService } from './mail.service';
import { MailDeliverabilityService } from './mail-deliverability.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';
import { DnsModule } from '../dns/dns.module';

/**
 * Email core + deliverability (B07/B08, ADR-0013/0014) — §4.8.
 * DnsModule provides the record auto-write path (ADR-0014: one writer).
 */
@Module({
  imports: [AgentModule, AuditModule, DnsModule],
  controllers: [MailController],
  providers: [MailService, MailDeliverabilityService],
})
export class MailModule {}
