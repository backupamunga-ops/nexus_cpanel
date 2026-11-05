import { Module } from '@nestjs/common';
import { EventsGateway } from './events.gateway';
import { AgentModule } from '../agent/agent.module';
import { AuthModule } from '../auth/auth.module';

/** WebSocket event stream (M0: live account usage; P2: full taxonomy). */
@Module({
  imports: [AgentModule, AuthModule],
  providers: [EventsGateway],
})
export class EventsModule {}
