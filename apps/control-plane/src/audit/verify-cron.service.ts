import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { AuditAppender, DatabaseAuditService, InjectAudit } from './audit.service';
import { NotificationsService } from '../notifications/notifications.service';

/**
 * Daily audit-chain verification (security control C11) — B13.
 *
 * Runs once at boot and then every VERIFY_INTERVAL_MS (24h): walks the
 * hash chain via DatabaseAuditService.verify() and, on ANY break, alerts
 * every super admin in the notification center AND writes a `failure`
 * audit entry — the tamper evidence becomes part of the chain itself.
 * A clean run is logged, not noisily notified (the panel shows the live
 * verification state on the Audit page).
 *
 * Exit evidence (batch plan): a mid-chain tamper is detected by this cron —
 * covered in the spec by tampering an entry and verifying (A5) plus the
 * unit test that drives verifyChainNow() against a broken chain.
 */

const VERIFY_INTERVAL_MS = 24 * 60 * 60 * 1000;

@Injectable()
export class AuditVerifyCronService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AuditVerifyCronService.name);
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly dbAudit: DatabaseAuditService,
    private readonly notifications: NotificationsService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  onModuleInit(): void {
    // Defer the first run so boot is not blocked by a long chain walk.
    setTimeout(() => void this.verifyChainNow(), 30_000)
      .unref?.();
    this.timer = setInterval(() => void this.verifyChainNow(), VERIFY_INTERVAL_MS);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /** One verification pass; returns the result (test seam + cron body). */
  async verifyChainNow(): Promise<{ verified: boolean; brokenAt: string | null; checked: number }> {
    try {
      const res = await this.dbAudit.verify();
      if (res.verified) {
        this.logger.log(`audit chain verified (${res.checked} entries)`);
        return res;
      }
      this.logger.error(`AUDIT CHAIN BREAK at entry ${res.brokenAt} (${res.checked} checked)`);
      const admins = await this.notifications.superAdminIds();
      await this.notifications.notify({
        userIds: admins,
        category: 'audit',
        title: 'Audit chain verification FAILED',
        body: `The tamper-evident audit log failed verification at entry ${res.brokenAt ?? '?'}. This may indicate direct database tampering. Investigate immediately.`,
        actionUrl: '/audit',
        severity: 'error',
      });
      await this.audit.append({
        operation: 'audit.chain.verify',
        parameters: { verified: false, broken_at: res.brokenAt, checked: res.checked },
        outcome: 'failure',
      });
      return res;
    } catch (e) {
      this.logger.error(`audit verify cron error: ${(e as Error).message}`);
      return { verified: false, brokenAt: null, checked: 0 };
    }
  }
}
