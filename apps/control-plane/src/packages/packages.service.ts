import { BadRequestException, ConflictException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';

/**
 * Packages (API spec §4.5) — the quota/feature bundles hosting accounts are
 * built from. Replaces the M0 "Default" bootstrap seam: `account.create`
 * now requires a real, active package.
 *
 * Authorization: `package:*` permissions currently require a Server Admin
 * (enforced in PermissionsGuard) — reseller-owned packages arrive with the
 * reseller feature. Validation is fail-closed:
 *
 *   - quotas: ONLY the canonical keys the schema and the agent know —
 *     cpu (cores, 0.1 granularity, ≤ 64), mem_mb / disk_mb (≤ 1 TiB / 10 TiB),
 *     inodes, processes (≤ 4096) — all strictly positive numbers. Unknown
 *     keys are rejected (the agent enforces a known set; a typo'd key would
 *     silently enforce nothing).
 *   - features: object of boolean values (key-open — the schema marks the
 *     set extensible; enforcement points read the flags they know).
 *   - over_quota_policy ∈ alert | throttle | suspend.
 *   - isolation_profile: 'standard' only (the agent's M0 constraint).
 *
 * Deletion is a SOFT delete (schema deleted_at) and is refused while any
 * live hosting account references the package (409) — the FK is NOT NULL, so
 * deleting an in-use package would strand its accounts.
 */

export const QUOTA_KEYS = ['cpu', 'mem_mb', 'disk_mb', 'inodes', 'processes', 'mailbox_count', 'mailbox_quota_mb'] as const;
export type QuotaKey = (typeof QUOTA_KEYS)[number];
export type QuotaSet = Partial<Record<QuotaKey, number>>;

const QUOTA_LIMITS: Record<QuotaKey, { max: number }> = {
  cpu: { max: 64 },
  mem_mb: { max: 1 << 20 }, // 1 TiB
  disk_mb: { max: 10 * (1 << 20) }, // 10 TiB
  inodes: { max: 100_000_000 },
  processes: { max: 4096 },
  mailbox_count: { max: 10_000 }, // B07: mailboxes per account
  mailbox_quota_mb: { max: 1 << 20 }, // B07: per-mailbox cap, 1 TiB (agent cap too)
};

const OVER_QUOTA_POLICIES = new Set(['alert', 'throttle', 'suspend']);

export interface PackageDto {
  id: string;
  name: string;
  description: string | null;
  quotas: QuotaSet;
  features: Record<string, boolean>;
  php_versions: string[];
  isolation_profile: string;
  over_quota_policy: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreatePackageInput {
  name?: unknown;
  description?: unknown;
  quotas?: unknown;
  features?: unknown;
  php_versions?: unknown;
  isolation_profile?: unknown;
  over_quota_policy?: unknown;
  is_active?: unknown;
}

/** Validates a quotas object against the canonical key set (fail-closed). */
export function validateQuotaSet(input: unknown, what: string): QuotaSet {
  if (input === null || input === undefined) {
    return {};
  }
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new BadRequestException(`${what} must be an object`);
  }
  const out: QuotaSet = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (!(QUOTA_KEYS as readonly string[]).includes(key)) {
      throw new BadRequestException(`${what}: unknown quota key '${key}' (known: ${QUOTA_KEYS.join(', ')})`);
    }
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
      throw new BadRequestException(`${what}: '${key}' must be a positive number`);
    }
    if (key === 'cpu') {
      const scaled = value * 10;
      if (Math.abs(scaled - Math.round(scaled)) > 1e-6 || value > QUOTA_LIMITS.cpu.max) {
        throw new BadRequestException(`${what}: 'cpu' must be a multiple of 0.1, at most ${QUOTA_LIMITS.cpu.max}`);
      }
      out.cpu = Math.round(scaled) / 10;
      continue;
    }
    if (!Number.isInteger(value)) {
      throw new BadRequestException(`${what}: '${key}' must be an integer`);
    }
    if (value > QUOTA_LIMITS[key as QuotaKey].max) {
      throw new BadRequestException(`${what}: '${key}' exceeds the ceiling of ${QUOTA_LIMITS[key as QuotaKey].max}`);
    }
    out[key as QuotaKey] = value;
  }
  return out;
}

/** Validates a features object: any keys, boolean values only. */
export function validateFeatureSet(input: unknown, what: string): Record<string, boolean> {
  if (input === null || input === undefined) {
    return {};
  }
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new BadRequestException(`${what} must be an object`);
  }
  const out: Record<string, boolean> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (typeof key !== 'string' || key.length > 64 || !/^[a-z0-9_]+$/.test(key)) {
      throw new BadRequestException(`${what}: feature key '${key}' must be [a-z0-9_], ≤ 64 chars`);
    }
    if (typeof value !== 'boolean') {
      throw new BadRequestException(`${what}: feature '${key}' must be a boolean`);
    }
    out[key] = value;
  }
  return out;
}

/** Merges package quotas with per-account overrides (override wins). */
export function mergeQuotas(base: QuotaSet, override: QuotaSet): QuotaSet {
  return { ...base, ...override };
}

@Injectable()
export class PackagesService {
  private readonly logger = new Logger(PackagesService.name);

  constructor(
    private readonly prisma: PrismaService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  async list(): Promise<{ data: PackageDto[] }> {
    const rows = await this.prisma.package.findMany({
      where: { deleted_at: null },
      orderBy: { created_at: 'asc' },
      take: 200,
    });
    return { data: rows.map((r) => toDto(r)) };
  }

  async get(id: string): Promise<PackageDto> {
    const row = await this.findLive(id);
    return toDto(row);
  }

  async create(input: CreatePackageInput, actorUserId?: string): Promise<PackageDto> {
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (name.length < 1 || name.length > 100) {
      throw new BadRequestException('name is required (1–100 characters)');
    }
    const quotas = validateQuotaSet(input.quotas, 'quotas');
    const features = validateFeatureSet(input.features, 'features');
    const phpVersions = this.validatePhpVersions(input.php_versions);
    const isolationProfile = this.validateProfile(input.isolation_profile);
    const overQuotaPolicy = this.validateOverQuotaPolicy(input.over_quota_policy);
    const description =
      input.description === undefined || input.description === null
        ? null
        : String(input.description).slice(0, 500);

    const row = await this.prisma.package.create({
      data: {
        name,
        description,
        quotas: quotas as object,
        features: features as object,
        php_versions: phpVersions,
        isolation_profile: isolationProfile,
        over_quota_policy: overQuotaPolicy,
      },
    });
    await this.audit.append({
      operation: 'package.create',
      parameters: { package_id: row.id, name },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    return toDto(row);
  }

  /**
   * Updates the package. `quotas` and `features` are FULL replacements when
   * present (partial quota updates would make the effective set ambiguous);
   * pass the complete object you want stored.
   */
  async update(id: string, input: CreatePackageInput, actorUserId?: string): Promise<PackageDto> {
    const row = await this.findLive(id);
    const data: Record<string, unknown> = { updated_at: new Date() };
    if (input.name !== undefined) {
      const name = typeof input.name === 'string' ? input.name.trim() : '';
      if (name.length < 1 || name.length > 100) {
        throw new BadRequestException('name must be 1–100 characters');
      }
      data['name'] = name;
    }
    if (input.description !== undefined) {
      data['description'] =
        input.description === null ? null : String(input.description).slice(0, 500);
    }
    if (input.quotas !== undefined) {
      data['quotas'] = validateQuotaSet(input.quotas, 'quotas') as object;
    }
    if (input.features !== undefined) {
      data['features'] = validateFeatureSet(input.features, 'features') as object;
    }
    if (input.php_versions !== undefined) {
      data['php_versions'] = this.validatePhpVersions(input.php_versions);
    }
    if (input.isolation_profile !== undefined) {
      data['isolation_profile'] = this.validateProfile(input.isolation_profile);
    }
    if (input.over_quota_policy !== undefined) {
      data['over_quota_policy'] = this.validateOverQuotaPolicy(input.over_quota_policy);
    }
    if (input.is_active !== undefined) {
      data['is_active'] = input.is_active === true;
    }

    const updated = await this.prisma.package.update({ where: { id: row.id }, data });
    await this.audit.append({
      operation: 'package.update',
      parameters: { package_id: row.id, fields: Object.keys(data).filter((k) => k !== 'updated_at') },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    return toDto(updated);
  }

  /** Soft-deletes; refused while live hosting accounts reference the package. */
  async remove(id: string, actorUserId?: string): Promise<void> {
    const row = await this.findLive(id);
    const inUse = await this.prisma.hostingAccount.count({
      where: { package_id: row.id, deleted_at: null },
    });
    if (inUse > 0) {
      throw new ConflictException(`package is in use by ${inUse} hosting account(s)`);
    }
    await this.prisma.package.update({
      where: { id: row.id },
      data: { deleted_at: new Date(), is_active: false },
    });
    await this.audit.append({
      operation: 'package.delete',
      parameters: { package_id: row.id, name: row.name },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    this.logger.log(`deleted package ${row.name} (${row.id})`);
  }

  private async findLive(id: string) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('package not found');
    }
    const row = await this.prisma.package.findFirst({ where: { id, deleted_at: null } });
    if (!row) {
      throw new NotFoundException('package not found');
    }
    return row;
  }

  private validatePhpVersions(raw: unknown): string[] {
    if (raw === undefined || raw === null) {
      return [];
    }
    if (!Array.isArray(raw)) {
      throw new BadRequestException('php_versions must be an array of version strings');
    }
    const out: string[] = [];
    for (const v of raw) {
      if (typeof v !== 'string' || !/^\d+\.\d+(\.\d+)?$/.test(v)) {
        throw new BadRequestException(`php_versions entry is not a version string: ${JSON.stringify(v ?? null)}`);
      }
      out.push(v);
    }
    return out;
  }

  private validateProfile(raw: unknown): string {
    if (raw === undefined || raw === null) {
      return 'standard';
    }
    if (raw !== 'standard') {
      // Mirrors the agent's M0 constraint (isolation.go).
      throw new BadRequestException("isolation_profile must be 'standard' (more profiles land later)");
    }
    return raw;
  }

  private validateOverQuotaPolicy(raw: unknown): string {
    if (raw === undefined || raw === null) {
      return 'alert';
    }
    if (typeof raw !== 'string' || !OVER_QUOTA_POLICIES.has(raw)) {
      throw new BadRequestException('over_quota_policy must be alert | throttle | suspend');
    }
    return raw;
  }
}

type PackageRow = {
  id: string;
  name: string;
  description: string | null;
  quotas: unknown;
  features: unknown;
  php_versions: string[];
  isolation_profile: string;
  over_quota_policy: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
};

function toDto(row: PackageRow): PackageDto {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    quotas: (row.quotas ?? {}) as QuotaSet,
    features: (row.features ?? {}) as Record<string, boolean>,
    php_versions: row.php_versions ?? [],
    isolation_profile: row.isolation_profile,
    over_quota_policy: row.over_quota_policy,
    is_active: row.is_active,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
  };
}
