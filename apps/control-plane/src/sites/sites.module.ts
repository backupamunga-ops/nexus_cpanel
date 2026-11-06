import { Module } from '@nestjs/common';
import { SitesController } from './sites.controller';
import { SitesService } from './sites.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';
import { PhpModule } from '../php/php.module';

@Module({
  controllers: [SitesController],
  // PhpModule: sites create/update/delete delegate the pool lifecycle (and
  // the fastcgi vhost refresh) to PhpService — one code path owns PHP.
  imports: [AgentModule, AuditModule, PhpModule],
  providers: [SitesService],
  exports: [SitesService],
})
export class SitesModule {}
