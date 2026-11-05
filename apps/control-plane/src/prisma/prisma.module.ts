import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

/** Prisma is a process-wide singleton shared by every feature module. */
@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
