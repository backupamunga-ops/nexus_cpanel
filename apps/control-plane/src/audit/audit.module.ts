import { Module } from '@nestjs/common';
import { AuditController } from './audit.controller';
import { AUDIT_APPENDER, DatabaseAuditService, InMemoryAuditService } from './audit.service';
import { AuditVerifyCronService } from './verify-cron.service';
import { NotificationsModule } from '../notifications/notifications.module';

/**
 * Provides the audit store (C11). Production/default: PostgreSQL hash chain.
 * AUDIT_STORE=memory selects the in-memory store (unit tests, ephemeral dev).
 */
@Module({
  imports: [NotificationsModule],
  controllers: [AuditController],
  providers: [
    {
      provide: AUDIT_APPENDER,
      useClass: process.env.AUDIT_STORE === 'memory' ? InMemoryAuditService : DatabaseAuditService,
    },
    DatabaseAuditService,
    AuditVerifyCronService,
  ],
  exports: [AUDIT_APPENDER, DatabaseAuditService],
})
export class AuditModule {}
