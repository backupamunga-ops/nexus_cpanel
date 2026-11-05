import { Module } from '@nestjs/common';
import { SshKeysController } from './sshkeys.controller';
import { SshKeysService } from './sshkeys.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  controllers: [SshKeysController],
  imports: [AgentModule, AuditModule],
  providers: [SshKeysService],
  exports: [SshKeysService],
})
export class SshKeysModule {}
