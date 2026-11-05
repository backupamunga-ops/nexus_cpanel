import { Module } from '@nestjs/common';
import { HealthModule } from './health/health.module';
import { AuthModule } from './auth/auth.module';
import { AccountsModule } from './accounts/accounts.module';
import { PackagesModule } from './packages/packages.module';
import { AgentModule } from './agent/agent.module';
import { AuditModule } from './audit/audit.module';
import { EventsModule } from './events/events.module';
import { PrismaModule } from './prisma/prisma.module';

/** Root application module — M0 slice with P1 auth persistence. */
@Module({
  imports: [
    PrismaModule,
    HealthModule,
    AuthModule,
    AccountsModule,
    PackagesModule,
    AgentModule,
    AuditModule,
    EventsModule,
  ],
})
export class AppModule {}
