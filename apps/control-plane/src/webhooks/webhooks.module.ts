import { Module } from '@nestjs/common';
import { WebhooksController } from './webhooks.controller';
import { WebhooksService } from './webhooks.service';
import { NotificationsModule } from '../notifications/notifications.module';

/**
 * Outbound webhooks (B13, API spec §4.22, ADR-0018): HMAC-signed delivery,
 * exponential backoff, dead-letter + redrive. Dispatch tails the audit
 * chain in-process for v1.0 single-node deployments.
 */
@Module({
  imports: [NotificationsModule],
  controllers: [WebhooksController],
  providers: [WebhooksService],
  exports: [WebhooksService],
})
export class WebhooksModule {}
