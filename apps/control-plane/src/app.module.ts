import { Module } from '@nestjs/common';
import { HealthModule } from './health/health.module';
import { AuthModule } from './auth/auth.module';
import { AccountsModule } from './accounts/accounts.module';
import { PackagesModule } from './packages/packages.module';
import { ResellersModule } from './resellers/resellers.module';
import { SettingsModule } from './settings/settings.module';
import { SitesModule } from './sites/sites.module';
import { FilesModule } from './files/files.module';
import { SshKeysModule } from './sshkeys/sshkeys.module';
import { SslModule } from './ssl/ssl.module';
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
    ResellersModule,
    SettingsModule,
    SitesModule,
    FilesModule,
    SshKeysModule,
    SslModule,
    AgentModule,
    AuditModule,
    EventsModule,
  ],
})
export class AppModule {}
