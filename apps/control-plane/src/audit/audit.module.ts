import { Module } from '@nestjs/common';
import { AuditController } from './audit.controller';
import { AUDIT_APPENDER, DatabaseAuditService, InMemoryAuditService } from './audit.service';

/**
 * Provides the audit store (C11). Production/default: PostgreSQL hash chain.
 * AUDIT_STORE=memory selects the in-memory store (unit tests, ephemeral dev).
 */
@Module({
  controllers: [AuditController],
  providers: [
    {
      provide: AUDIT_APPENDER,
      useClass: process.env.AUDIT_STORE === 'memory' ? InMemoryAuditService : DatabaseAuditService,
    },
    DatabaseAuditService,
  ],
  exports: [AUDIT_APPENDER, DatabaseAuditService],
})
export class AuditModule {}
