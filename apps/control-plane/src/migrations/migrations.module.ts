import { Module } from '@nestjs/common';
import { MigrationsController } from './migrations.controller';
import { MigrationsService } from './migrations.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';
import { DnsModule } from '../dns/dns.module';
import { MailModule } from '../mail/mail.module';

/**
 * Migration Center (B15, API spec §4.21, migration spec M15): cPanel
 * cpmove import with per-entity verification. The agent reads/extracts
 * the artifact; this module owns the ledger (migration_jobs /
 * migration_entity_mappings) and the phase machine. DnsModule and
 * MailModule provide the real provisioning paths — zones and mailboxes
 * are created through the same services the panels use, never side
 * doors.
 */
@Module({
  imports: [AgentModule, AuditModule, DnsModule, MailModule],
  controllers: [MigrationsController],
  providers: [MigrationsService],
  exports: [MigrationsService],
})
export class MigrationsModule {}
