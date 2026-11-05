import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import * as os from 'node:os';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { Actor } from '../sites/sites.service';

/**
 * Configuration engine v1 — the control-plane half (API surface: an
 * amendment documented in the ADR; the agent half is §4.5 validate /
 * drift_check / list_active, with apply already living in the nginx and
 * php command families).
 *
 * The version history IS config_versions (written by the sites and php
 * flows since their first apply). On top of it this module adds:
 *
 *   - inspection: version list + content for a target;
 *   - rollback: re-apply an old version's stored bytes as a NEW version
 *     (history is append-only — rolling back writes forward), recorded as
 *     a config_transactions row (applied | failed);
 *   - drift: hash the node's file vs the active version's bytes. The agent
 *     reports; the control plane records drift_events and humans decide
 *     (§P.7 — the agent never silently reconciles).
 *
 * Single-node reality: drift_events.node_id requires a node row, so the
 * service lazily maintains the 'local' node.
 */

const TARGET_TYPES = new Set(['nginx_vhost', 'php_pool']);
const DRIFT_RESOLUTIONS = new Set(['reconciled', 'investigated', 'ignored']);

export interface ConfigVersionDto {
  id: string;
  version: number;
  is_active: boolean;
  size_bytes: number;
  rendered_by: string | null;
  created_at: string;
}

export interface ConfigTransactionDto {
  id: string;
  from_version_id: string | null;
  to_version_id: string | null;
  status: string;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
}

export interface DriftEventDto {
  id: string;
  target_type: string;
  target_id: string;
  detected_at: string;
  resolved_at: string | null;
  resolution: string | null;
}

@Injectable()
export class ConfigService {
  private readonly logger = new Logger(ConfigService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  private assertTarget(targetType: string): void {
    if (!TARGET_TYPES.has(targetType)) {
      throw new BadRequestException(
        `target_type must be one of ${[...TARGET_TYPES].join(' | ')}`,
      );
    }
  }

  private async requireVisibleDomain(domainId: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(domainId)) {
      throw new NotFoundException('target not found');
    }
    const row = await this.prisma.domain.findFirst({ where: { id: domainId, deleted_at: null } });
    if (!row) {
      throw new NotFoundException('target not found');
    }
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) {
        throw new NotFoundException('target not found');
      }
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: row.hosting_account_id, revoked_at: null },
        select: { id: true },
      });
      if (!access) {
        throw new NotFoundException('target not found');
      }
    }
    return row;
  }

  /** Lazily maintains the single-node 'local' row for drift attribution. */
  private async ensureLocalNode(): Promise<string> {
    const existing = await this.prisma.node.findFirst({ where: { name: 'local' }, select: { id: true } });
    if (existing) {
      return existing.id;
    }
    const created = await this.prisma.node.create({
      data: { name: 'local', type: 'hosting', hostname: os.hostname(), is_active: true },
    });
    return created.id;
  }

  async versions(
    targetType: string,
    targetId: string,
    actor?: Actor,
  ): Promise<{ data: ConfigVersionDto[] }> {
    this.assertTarget(targetType);
    await this.requireVisibleDomain(targetId, actor);
    const rows = await this.prisma.configVersion.findMany({
      where: { target_type: targetType, target_id: targetId },
      orderBy: { version: 'desc' },
      take: 100,
    });
    return {
      data: rows.map((r) => ({
        id: r.id,
        version: r.version,
        is_active: r.is_active,
        size_bytes: Buffer.byteLength(r.content, 'utf8'),
        rendered_by: r.rendered_by,
        created_at: r.created_at.toISOString(),
      })),
    };
  }

  async versionContent(
    targetType: string,
    targetId: string,
    versionId: string,
    actor?: Actor,
  ): Promise<{ id: string; version: number; is_active: boolean; content: string }> {
    this.assertTarget(targetType);
    await this.requireVisibleDomain(targetId, actor);
    const row = await this.prisma.configVersion.findFirst({
      where: { id: versionId, target_type: targetType, target_id: targetId },
    });
    if (!row) {
      throw new NotFoundException('config version not found');
    }
    return { id: row.id, version: row.version, is_active: row.is_active, content: row.content };
  }

  /** Transactions for a target, newest first (applies + rollbacks). */
  async transactions(
    targetType: string,
    targetId: string,
    actor?: Actor,
  ): Promise<{ data: ConfigTransactionDto[] }> {
    this.assertTarget(targetType);
    await this.requireVisibleDomain(targetId, actor);
    const rows = await this.prisma.configTransaction.findMany({
      where: { target_type: targetType, target_id: targetId },
      orderBy: { started_at: 'desc' },
      take: 50,
    });
    return {
      data: rows.map((r) => ({
        id: r.id,
        from_version_id: r.from_version_id,
        to_version_id: r.to_version_id,
        status: r.status,
        started_at: r.started_at.toISOString(),
        completed_at: r.completed_at ? r.completed_at.toISOString() : null,
        error_message: r.error_message,
      })),
    };
  }

  /**
   * Rollback = re-apply an old version's stored bytes as a NEW version.
   * vhost targets apply through the agent's health-gated pipeline; pool
   * targets refuse honestly until the pool-target apply path exists.
   */
  async rollback(
    targetType: string,
    targetId: string,
    versionId: string,
    actor?: Actor,
  ): Promise<ConfigVersionDto> {
    this.assertTarget(targetType);
    const domain = await this.requireVisibleDomain(targetId, actor);
    if (targetType === 'php_pool') {
      // Refuse the capability gap up front — the honest message beats a
      // misleading "version not found" for a target type that exists.
      throw new BadRequestException(
        'php_pool rollback lands with the pool-target apply path (the agent addresses pools by version today)',
      );
    }
    const target = await this.prisma.configVersion.findFirst({
      where: { id: versionId, target_type: targetType, target_id: targetId },
    });
    if (!target) {
      throw new NotFoundException('config version not found');
    }

    const active = await this.prisma.configVersion.findFirst({
      where: { target_type: targetType, target_id: targetId, is_active: true },
      select: { id: true, version: true },
    });
    if (active?.id === target.id) {
      throw new BadRequestException('that version is already the active one');
    }

    // Transaction row first (pending), then the apply, then the outcome —
    // the transaction record exists even if the node dies mid-apply.
    const tx = await this.prisma.configTransaction.create({
      data: {
        target_type: targetType,
        target_id: targetId,
        from_version_id: active?.id ?? null,
        to_version_id: target.id,
        status: 'pending',
      },
    });

    try {
      await this.agent.nginxApplyVhost(domain.name, target.content);
      await this.agent.nginxReload();
    } catch (e) {
      await this.prisma.configTransaction.update({
        where: { id: tx.id },
        data: { status: 'failed', completed_at: new Date(), error_message: (e as Error).message },
      });
      await this.audit.append({
        operation: 'config.rollback',
        parameters: {
          target_type: targetType,
          target_id: targetId,
          version_id: versionId,
          error: (e as Error).message,
        },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }

    const newVersion = await this.prisma.$transaction(async (db) => {
      const prev = await db.configVersion.findFirst({
        where: { target_type: targetType, target_id: targetId },
        orderBy: { version: 'desc' },
        select: { version: true },
      });
      await db.configVersion.updateMany({
        where: { target_type: targetType, target_id: targetId, is_active: true },
        data: { is_active: false },
      });
      const created = await db.configVersion.create({
        data: {
          target_type: targetType,
          target_id: targetId,
          version: (prev?.version ?? 0) + 1,
          content: target.content,
          rendered_by: actor?.userId ?? null,
          is_active: true,
        },
      });
      await db.configTransaction.update({
        where: { id: tx.id },
        data: { status: 'applied', completed_at: new Date(), to_version_id: created.id },
      });
      await this.audit.appendWithClient(db, {
        operation: 'config.rollback',
        parameters: {
          target_type: targetType,
          target_id: targetId,
          from_version: active?.version ?? null,
          to_version_content_of: target.version,
          new_version: created.version,
          transaction_id: tx.id,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      return created;
    });
    this.logger.log(
      `rolled back ${targetType} for domain ${domain.name}: v${target.content ? target.version : '?'} content re-applied as v${newVersion.version}`,
    );
    return {
      id: newVersion.id,
      version: newVersion.version,
      is_active: true,
      size_bytes: Buffer.byteLength(newVersion.content, 'utf8'),
      rendered_by: newVersion.rendered_by,
      created_at: newVersion.created_at.toISOString(),
    };
  }

  /** On-demand drift check: node bytes vs the active version's bytes. */
  async driftCheck(
    targetType: string,
    targetId: string,
    actor?: Actor,
  ): Promise<{ matches: boolean; exists: boolean; drift_event_id: string | null }> {
    this.assertTarget(targetType);
    if (targetType !== 'nginx_vhost') {
      throw new BadRequestException('drift checks cover nginx_vhost in this build (pool targets land with their amendment)');
    }
    const domain = await this.requireVisibleDomain(targetId, actor);
    const active = await this.prisma.configVersion.findFirst({
      where: { target_type: targetType, target_id: targetId, is_active: true },
    });
    if (!active) {
      throw new NotFoundException('no active config version for this target');
    }

    const res = await this.agent.configDriftCheck(domain.name, active.content);
    if (res.matches) {
      return { matches: true, exists: res.exists, drift_event_id: null };
    }

    // Record the drift — reporting, never reconciling (§P.7). The event
    // stores the HASHES (the agent's contract), not the content.
    const nodeId = await this.ensureLocalNode();
    const event = await this.prisma.driftEvent.create({
      data: {
        node_id: nodeId,
        target_type: targetType,
        target_id: targetId,
        expected_hash: Buffer.from(res.expected_hash, 'hex'),
        actual_hash: Buffer.from(res.actual_hash, 'hex'),
      },
    });
    await this.audit.append({
      operation: 'config.drift_detected',
      parameters: {
        target_type: targetType,
        target_id: targetId,
        domain: domain.name,
        drift_event_id: event.id,
      },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: domain.hosting_account_id,
    });
    this.logger.warn(`drift detected on ${domain.name} vhost (${event.id})`);
    return { matches: false, exists: res.exists, drift_event_id: event.id };
  }

  async driftEvents(actor?: Actor): Promise<{ data: DriftEventDto[] }> {
    const events = await this.prisma.driftEvent.findMany({
      where: { resolved_at: null },
      orderBy: { detected_at: 'desc' },
      take: 100,
    });
    // Visibility: only events on targets the caller can see.
    const visible: DriftEventDto[] = [];
    for (const e of events) {
      try {
        await this.requireVisibleDomain(e.target_id, actor);
        visible.push({
          id: e.id,
          target_type: e.target_type,
          target_id: e.target_id,
          detected_at: e.detected_at.toISOString(),
          resolved_at: e.resolved_at ? e.resolved_at.toISOString() : null,
          resolution: e.resolution,
        });
      } catch {
        // not visible → skipped
      }
    }
    return { data: visible };
  }

  async resolveDrift(id: string, resolution: unknown, actor?: Actor): Promise<DriftEventDto> {
    if (typeof resolution !== 'string' || !DRIFT_RESOLUTIONS.has(resolution)) {
      throw new BadRequestException('resolution must be reconciled | investigated | ignored');
    }
    const event = await this.prisma.driftEvent.findFirst({ where: { id } });
    if (!event || event.resolved_at) {
      throw new NotFoundException('drift event not found (or already resolved)');
    }
    await this.requireVisibleDomain(event.target_id, actor);
    const updated = await this.prisma.driftEvent.update({
      where: { id: event.id },
      data: { resolved_at: new Date(), resolution },
    });
    await this.audit.append({
      operation: 'config.drift_resolved',
      parameters: { drift_event_id: event.id, resolution },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
    });
    return {
      id: updated.id,
      target_type: updated.target_type,
      target_id: updated.target_id,
      detected_at: updated.detected_at.toISOString(),
      resolved_at: updated.resolved_at ? updated.resolved_at.toISOString() : null,
      resolution: updated.resolution,
    };
  }
}
