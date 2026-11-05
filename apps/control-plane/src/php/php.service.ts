import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { Actor } from '../sites/sites.service';

/**
 * Per-site PHP-FPM pools (API spec §4.7: GET/PATCH /domains/{id}/php).
 *
 * The agent renders and owns the pool file (PhpRoot/<version>/pools/<fqdn>.conf);
 * the control plane stores the exact rendered bytes as a config_version
 * (target_type 'php_pool') plus the config JSON that produced them — the
 * config engine's timeline covers PHP pools the same way it covers vhosts.
 *
 * Pool config is fail-closed on BOTH sides: unknown keys are a protocol
 * violation (the agent must understand everything it enforces), values are
 * range-checked, and the version must actually be installed on the node —
 * an uninstalled version is a precondition, not a silent no-pool.
 */

const PHP_VERSION_RE = /^8\.[1-4]$/;

const PM_MODES = new Set(['dynamic', 'static', 'ondemand']);
const POOL_INT_KEYS = [
  'pm.max_children',
  'pm.start_servers',
  'pm.min_spare_servers',
  'pm.max_spare_servers',
] as const;
const POOL_SIZE_KEYS = ['memory_limit', 'upload_max_filesize'] as const;

export interface PoolConfig extends Record<string, unknown> {
  pm?: string;
  'pm.max_children'?: number;
  'pm.start_servers'?: number;
  'pm.min_spare_servers'?: number;
  'pm.max_spare_servers'?: number;
  memory_limit?: string;
  upload_max_filesize?: string;
  max_execution_time?: number;
}

export const DEFAULT_POOL: PoolConfig = {
  pm: 'dynamic',
  'pm.max_children': 10,
  'pm.start_servers': 2,
  'pm.min_spare_servers': 2,
  'pm.max_spare_servers': 4,
  memory_limit: '128M',
};

export interface PhpViewDto {
  domain_id: string;
  php_version: string | null;
  pool: { version: string; config: PoolConfig; conf_content: string } | null;
  offered_by_package: string[];
}

/** Validates a pool config against the agent's exact policy (mirror). */
export function validatePoolConfig(input: unknown): PoolConfig {
  if (input === undefined || input === null) {
    return {};
  }
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new BadRequestException('pool must be an object');
  }
  const out: PoolConfig = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (key === 'pm') {
      if (typeof value !== 'string' || !PM_MODES.has(value)) {
        throw new BadRequestException('pool.pm must be dynamic | static | ondemand');
      }
      out.pm = value;
      continue;
    }
    if ((POOL_INT_KEYS as readonly string[]).includes(key) || key === 'max_execution_time') {
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 500) {
        throw new BadRequestException(`pool.${key} must be an integer in 1..500`);
      }
      if (key === 'max_execution_time' && value > 300) {
        throw new BadRequestException('pool.max_execution_time must be 1..300 seconds');
      }
      out[key as keyof PoolConfig] = value as never;
      continue;
    }
    if ((POOL_SIZE_KEYS as readonly string[]).includes(key)) {
      if (typeof value !== 'string' || !/^\d{1,5}[MG]$/.test(value)) {
        throw new BadRequestException(`pool.${key} must look like '128M' or '1G'`);
      }
      out[key as keyof PoolConfig] = value as never;
      continue;
    }
    throw new BadRequestException(`pool: unknown key '${key}' (the agent enforces a known set)`);
  }
  return out;
}

interface StoredPool {
  version: string;
  config: PoolConfig;
}

function parseStoredPool(content: string): StoredPool | null {
  try {
    const parsed = JSON.parse(content) as StoredPool;
    if (typeof parsed?.version === 'string' && typeof parsed?.config === 'object') {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

@Injectable()
export class PhpService {
  private readonly logger = new Logger(PhpService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  private async requireVisibleDomain(id: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('domain not found');
    }
    const row = await this.prisma.domain.findFirst({ where: { id, deleted_at: null } });
    if (!row) {
      throw new NotFoundException('domain not found');
    }
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) {
        throw new NotFoundException('domain not found');
      }
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: row.hosting_account_id, revoked_at: null },
        select: { id: true },
      });
      if (!access) {
        throw new NotFoundException('domain not found');
      }
    }
    return row;
  }

  private async activePool(domainId: string): Promise<{ row: { id: string; version: number; content: string } | null; stored: StoredPool | null }> {
    const row = await this.prisma.configVersion.findFirst({
      where: { target_type: 'php_pool', target_id: domainId, is_active: true },
      orderBy: { version: 'desc' },
    });
    return { row, stored: row ? parseStoredPool(row.content) : null };
  }

  async getForDomain(domainId: string, actor?: Actor): Promise<PhpViewDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: domain.hosting_account_id },
      select: { package: { select: { php_versions: true } } },
    });
    const { row, stored } = await this.activePool(domain.id);
    return {
      domain_id: domain.id,
      php_version: domain.php_version,
      pool:
        row && stored
          ? { version: stored.version, config: stored.config, conf_content: row.content }
          : null,
      offered_by_package: account?.package?.php_versions ?? [],
    };
  }

  /**
   * PATCH /domains/{id}/php — sets the version and pool config. A null
   * version removes the pool; a version change recreates the pool under the
   * new version; a config change modifies in place. The agent is authoritative
   * (agent-first): a failed call leaves the previous state fully intact.
   */
  async update(
    domainId: string,
    input: { php_version?: unknown; pool?: unknown },
    actor?: Actor,
  ): Promise<PhpViewDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: domain.hosting_account_id },
      select: { id: true, username: true, package: { select: { php_versions: true } } },
    });
    if (!account) {
      throw new NotFoundException('hosting account not found');
    }

    const wantsRemoval =
      input.php_version === null || input.php_version === '' || (input.php_version === undefined && input.pool === undefined);
    const { row: currentRow, stored: current } = await this.activePool(domain.id);

    if (wantsRemoval) {
      if (!current) {
        throw new BadRequestException('no PHP pool to remove for this domain');
      }
      await this.agent.phpDeletePool(account.username, domain.name, current.version);
      await this.prisma.$transaction(async (tx) => {
        await tx.domain.update({
          where: { id: domain.id },
          data: { php_version: null, updated_at: new Date() },
        });
        await tx.configVersion.updateMany({
          where: { target_type: 'php_pool', target_id: domain.id, is_active: true },
          data: { is_active: false },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'php.remove',
          parameters: { domain_id: domain.id, domain: domain.name, previous_version: current.version },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: domain.hosting_account_id,
        });
      });
      return this.getForDomain(domainId, actor);
    }

    // Setting / changing the version and/or the pool config.
    const version = String(input.php_version ?? current?.version ?? '');
    if (!PHP_VERSION_RE.test(version)) {
      throw new BadRequestException('php_version must be one of 8.1 | 8.2 | 8.3 | 8.4');
    }
    const offered = account.package?.php_versions ?? [];
    if (offered.length > 0 && !offered.includes(version)) {
      throw new BadRequestException(`php_version ${version} is not offered by the account's package`);
    }

    let config: PoolConfig;
    if (input.pool !== undefined) {
      config = validatePoolConfig(input.pool);
    } else if (current && current.version === version) {
      config = current.config;
    } else {
      config = { ...DEFAULT_POOL };
    }

    const content = JSON.stringify({ version, config });
    let confContent: string;
    if (current && current.version === version) {
      const res = await this.agent.phpModifyPool(account.username, domain.name, version, config);
      confContent = res.conf_content;
    } else if (current) {
      // Version change: remove the old pool, create under the new version.
      await this.agent.phpDeletePool(account.username, domain.name, current.version);
      const res = await this.agent.phpCreatePool(account.username, domain.name, version, config);
      confContent = res.conf_content;
    } else {
      const res = await this.agent.phpCreatePool(account.username, domain.name, version, config);
      confContent = res.conf_content;
    }

    await this.prisma.$transaction(async (tx) => {
      const prev = await tx.configVersion.findFirst({
        where: { target_type: 'php_pool', target_id: domain.id },
        orderBy: { version: 'desc' },
        select: { version: true },
      });
      await tx.configVersion.updateMany({
        where: { target_type: 'php_pool', target_id: domain.id, is_active: true },
        data: { is_active: false },
      });
      await tx.configVersion.create({
        data: {
          target_type: 'php_pool',
          target_id: domain.id,
          version: (prev?.version ?? 0) + 1,
          // Store BOTH the agent-rendered bytes and the config JSON that
          // produced them: the rendered conf is truth on disk, the JSON is
          // what the UI edits back.
          content: JSON.stringify({ ...JSON.parse(content), conf_content: confContent }),
          rendered_by: actor?.userId ?? null,
          is_active: true,
        },
      });
      await tx.domain.update({
        where: { id: domain.id },
        data: { php_version: version, updated_at: new Date() },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'php.update',
        parameters: { domain_id: domain.id, domain: domain.name, version },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
    this.logger.log(`php pool applied for ${domain.name} (php ${version})`);
    return this.getForDomain(domainId, actor);
  }
}
