import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { AuditModule } from '../audit/audit.module';
import { ExtensionsController } from './extensions.controller';
import { ExtProxyController } from './ext-proxy.controller';
import { ExtensionsService } from './extensions.service';
import { ExtProxyService } from './ext-proxy.service';
import { ExtDispatchService } from './ext-dispatch.service';

/**
 * Extension SDK runtime (P7, ADR-0021): registration + scope review +
 * one-time credentials, the closed `/api/v1/ext/*` proxy (scoped, rate
 * limited, audited), signed hook dispatch and heartbeats.
 */
@Module({
  imports: [PrismaModule, NotificationsModule, AuditModule],
  controllers: [ExtensionsController, ExtProxyController],
  providers: [ExtensionsService, ExtProxyService, ExtDispatchService],
  exports: [ExtensionsService],
})
export class ExtensionsModule {}
