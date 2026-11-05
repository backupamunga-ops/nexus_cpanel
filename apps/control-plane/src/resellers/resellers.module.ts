import { Module } from '@nestjs/common';
import { ResellersController } from './resellers.controller';
import { ResellersService } from './resellers.service';

/** Reseller lifecycle (API spec §4.6) — nesting, branding, custom domains. */
@Module({
  controllers: [ResellersController],
  providers: [ResellersService],
})
export class ResellersModule {}
