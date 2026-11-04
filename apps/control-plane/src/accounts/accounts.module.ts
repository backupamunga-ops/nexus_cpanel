import { Module } from '@nestjs/common';
import { AccountsController } from './accounts.controller';
import { AccountsService } from './accounts.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [AgentModule, AuditModule],
  controllers: [AccountsController],
  providers: [AccountsService],
})
export class AccountsModule {}
