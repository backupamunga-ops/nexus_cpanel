import { Module } from '@nestjs/common';
import { AgentClientService } from './agent-client.service';

@Module({
  providers: [AgentClientService],
  exports: [AgentClientService],
})
export class AgentModule {}
