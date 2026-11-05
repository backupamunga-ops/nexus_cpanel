import { Module } from '@nestjs/common';
import { FtpController } from './ftp.controller';
import { FtpService } from './ftp.service';
import { AgentModule } from '../agent/agent.module';
import { AuditModule } from '../audit/audit.module';

/** FTP accounts (API spec §4.12) — vsftpd virtual users (ADR-0011). */
@Module({
  controllers: [FtpController],
  imports: [AgentModule, AuditModule],
  providers: [FtpService],
  exports: [FtpService],
})
export class FtpModule {}
