import { Module } from '@nestjs/common';
import { TerminalGateway } from './terminal.gateway';
import { AgentModule } from '../agent/agent.module';
import { AuthModule } from '../auth/auth.module';
import { AuditModule } from '../audit/audit.module';

/**
 * Web-terminal relay (ADR-0023): browser ws ↔ signed agent stream.
 * No controller — the capability is intentionally not reachable over REST.
 */
@Module({
  imports: [AgentModule, AuthModule, AuditModule],
  providers: [TerminalGateway],
})
export class TerminalModule {}
