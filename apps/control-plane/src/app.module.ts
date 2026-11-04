import { Module } from '@nestjs/common';
import { HealthModule } from './health/health.module';
import { AuthModule } from './auth/auth.module';
import { AccountsModule } from './accounts/accounts.module';
import { AgentModule } from './agent/agent.module';
import { AuditModule } from './audit/audit.module';

/** Root application module — M0 slice. */
@Module({
  imports: [HealthModule, AuthModule, AccountsModule, AgentModule, AuditModule],
})
export class AppModule {}
