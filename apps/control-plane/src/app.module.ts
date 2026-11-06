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
import { FtpModule } from './ftp/ftp.module';
import { DnsModule } from './dns/dns.module';
import { MailModule } from './mail/mail.module';
import { DatabasesModule } from './databases/databases.module';
import { BackupsModule } from './backups/backups.module';
import { FirewallModule } from './firewall/firewall.module';
import { SecurityModule } from './security/security.module';
import { JobsModule } from './jobs/jobs.module';
import { WebhooksModule } from './webhooks/webhooks.module';
import { NotificationsModule } from './notifications/notifications.module';
import { AppsModule } from './apps/apps.module';
import { MigrationsModule } from './migrations/migrations.module';
import { ExtensionsModule } from './extensions/extensions.module';
import { SslModule } from './ssl/ssl.module';
import { PhpModule } from './php/php.module';
import { ConfigModule } from './config/config.module';
import { AgentModule } from './agent/agent.module';
import { AuditModule } from './audit/audit.module';
import { EventsModule } from './events/events.module';
import { TerminalModule } from './terminal/terminal.module';
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
    FtpModule,
    DnsModule,
    MailModule,
    DatabasesModule,
    BackupsModule,
    FirewallModule,
    SecurityModule,
    JobsModule,
    WebhooksModule,
    NotificationsModule,
    AppsModule,
    MigrationsModule,
    ExtensionsModule,
    SslModule,
    PhpModule,
    ConfigModule,
    AgentModule,
    AuditModule,
    EventsModule,
    TerminalModule,
  ],
})
export class AppModule {}
