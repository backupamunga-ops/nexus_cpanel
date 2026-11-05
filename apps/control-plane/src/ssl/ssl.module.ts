import { Module } from '@nestjs/common';
import { SslController } from './ssl.controller';
import { SslService } from './ssl.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  controllers: [SslController],
  imports: [AgentModule, AuditModule],
  providers: [SslService],
  exports: [SslService],
})
export class SslModule {}
