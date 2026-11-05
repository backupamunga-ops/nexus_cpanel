import { Module, forwardRef } from '@nestjs/common';
import { JobsController } from './jobs.controller';
import { JobsService } from './jobs.service';
import { AuditModule } from '../audit/audit.module';
import { SecurityModule } from '../security/security.module';
import { BackupsModule } from '../backups/backups.module';

/**
 * Job center (B13, ADR-0018): the visible state of long-running work.
 * Handlers are wired explicitly (malware.scan, backup.run).
 */
@Module({
  imports: [AuditModule, forwardRef(() => SecurityModule), forwardRef(() => BackupsModule)],
  controllers: [JobsController],
  providers: [JobsService],
  exports: [JobsService],
})
export class JobsModule {}
