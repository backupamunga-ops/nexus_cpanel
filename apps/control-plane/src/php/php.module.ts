import { Module } from '@nestjs/common';
import { PhpController } from './php.controller';
import { PhpService } from './php.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  controllers: [PhpController],
  imports: [AgentModule, AuditModule],
  providers: [PhpService],
  exports: [PhpService],
})
export class PhpModule {}
