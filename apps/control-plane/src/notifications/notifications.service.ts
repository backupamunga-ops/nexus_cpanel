import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/**
 * In-app notification center (API spec §4.23) — B13.
 *
 * Notifications are strictly per-user and readable only by their owner
 * (no permission gate needed — the route scopes by the session user).
 * Producers today: the audit-chain verification cron (failures), webhook
 * dead-letters (server admins), and module flows that want to surface a
 * result without shouting over the audit chain.
 */

export interface NotificationDto {
  id: string;
  category: string;
  title: string;
  body: string;
  action_url: string | null;
  severity: string;
  read_at: string | null;
  created_at: string;
}

@Injectable()
export class NotificationsService {
  constructor(private readonly prisma: PrismaService) {}

  /** Fire-and-forget producer; never throws into the caller's flow. */
  async notify(input: {
    userId?: string | null;
    userIds?: string[];
    category: string;
    title: string;
    body: string;
    actionUrl?: string;
    severity?: 'info' | 'warning' | 'error';
  }): Promise<void> {
    const targets = input.userIds ?? (input.userId ? [input.userId] : []);
    if (targets.length === 0) return;
    await this.prisma.notification.createMany({
      data: targets.map((userId) => ({
        user_id: userId,
        category: input.category,
        title: input.title,
        body: input.body,
        action_url: input.actionUrl ?? null,
        severity: input.severity ?? 'info',
      })),
    });
  }

  /** All super admins — the recipient set for server-wide alerts. */
  async superAdminIds(): Promise<string[]> {
    const rows = await this.prisma.user.findMany({
      where: { is_super_admin: true },
      select: { id: true },
    });
    return rows.map((r) => r.id);
  }

  async listMine(userId: string): Promise<{ data: NotificationDto[]; unread: number }> {
    const rows = await this.prisma.notification.findMany({
      where: { user_id: userId },
      orderBy: { created_at: 'desc' },
      take: 100,
    });
    const unread = rows.filter((r) => r.read_at === null).length;
    return {
      data: rows.map((r) => ({
        id: r.id,
        category: r.category,
        title: r.title,
        body: r.body,
        action_url: r.action_url,
        severity: r.severity,
        read_at: r.read_at?.toISOString() ?? null,
        created_at: r.created_at.toISOString(),
      })),
      unread,
    };
  }

  async markRead(userId: string, id: string): Promise<void> {
    const row = await this.prisma.notification.findFirst({
      where: { id, user_id: userId },
      select: { id: true },
    });
    if (!row) throw new NotFoundException('notification not found');
    await this.prisma.notification.update({ where: { id }, data: { read_at: new Date() } });
  }

  async markAllRead(userId: string): Promise<void> {
    await this.prisma.notification.updateMany({
      where: { user_id: userId, read_at: null },
      data: { read_at: new Date() },
    });
  }
}
