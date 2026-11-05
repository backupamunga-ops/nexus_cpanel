import { Module } from '@nestjs/common';
import { ResellersController } from './resellers.controller';
import { ResellersService } from './resellers.service';
import { AuditModule } from '../audit/audit.module';

/** Reseller lifecycle (API spec §4.6) — nesting, branding, custom domains. */
@Module({
  controllers: [ResellersController],
  imports: [AuditModule],
  providers: [ResellersService],
})
export class ResellersModule {}
