import { Module } from '@nestjs/common';
import { FilesController } from './files.controller';
import { FilesService } from './files.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  controllers: [FilesController],
  imports: [AgentModule, AuditModule],
  providers: [FilesService],
  exports: [FilesService],
})
export class FilesModule {}
