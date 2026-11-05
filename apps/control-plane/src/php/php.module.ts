import { Module } from '@nestjs/common';
import { PhpController } from './php.controller';
import { PhpService } from './php.service';

@Module({
  controllers: [PhpController],
  providers: [PhpService],
  exports: [PhpService],
})
export class PhpModule {}
