import { Module } from '@nestjs/common';
import { ConfigController } from './config.controller';
import { ConfigService } from './config.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  controllers: [ConfigController],
  imports: [AgentModule, AuditModule],
  providers: [ConfigService],
  exports: [ConfigService],
})
export class ConfigModule {}
