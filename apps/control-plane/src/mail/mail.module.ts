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
 * MailService is exported for the B15 migration center (mailbox import
 * with fresh secrets, spec §6 — never the artifact's hashes).
 */
@Module({
  imports: [AgentModule, AuditModule, DnsModule],
  controllers: [MailController],
  providers: [MailService, MailDeliverabilityService],
  exports: [MailService],
})
export class MailModule {}
