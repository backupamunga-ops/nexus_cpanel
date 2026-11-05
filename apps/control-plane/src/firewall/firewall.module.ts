import { Module } from '@nestjs/common';
import { FirewallController } from './firewall.controller';
import { FirewallService } from './firewall.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

/**
 * Firewall & fail2ban module (B11, ADR-0016). The agent client lives in
 * AgentModule (signed-command transport is shared infrastructure); audit
 * appends go through the hash-chained AuditModule.
 */
@Module({
  imports: [AgentModule, AuditModule],
  controllers: [FirewallController],
  providers: [FirewallService],
  exports: [FirewallService],
})
export class FirewallModule {}
