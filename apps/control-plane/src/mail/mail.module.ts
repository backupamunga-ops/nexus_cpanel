import { Module } from '@nestjs/common';
import { MailController } from './mail.controller';
import { MailService } from './mail.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

/** Email core (B07, ADR-0013) — §4.8 domain/mailbox/alias/autoresponder slice. */
@Module({
  imports: [AgentModule, AuditModule],
  controllers: [MailController],
  providers: [MailService],
})
export class MailModule {}
