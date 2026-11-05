import { Module, forwardRef } from '@nestjs/common';
import { AppsController } from './apps.controller';
import { AppsService } from './apps.service';
import { GitService } from './git.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';
import { DatabasesModule } from '../databases/databases.module';
import { SitesModule } from '../sites/sites.module';
import { JobsModule } from '../jobs/jobs.module';

/**
 * Apps & Git deploy (B14, ADR-0019): WordPress installer (WP-CLI as the
 * account user, one-click staging clone) and push-to-deploy (HMAC
 * webhook receivers, release-symlink deploys with history + rollback).
 * JobsModule is forward-referenced: the job center registers git.deploy
 * retries through GitService (the mirror of B13's malware/backup wiring).
 */
@Module({
  imports: [
    AgentModule,
    AuditModule,
    DatabasesModule,
    SitesModule,
    forwardRef(() => JobsModule),
  ],
  controllers: [AppsController],
  providers: [AppsService, GitService],
  exports: [AppsService, GitService],
})
export class AppsModule {}
