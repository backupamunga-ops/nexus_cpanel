import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import {
  BadRequestLike,
  findSettingDefinition,
  SETTING_DEFINITIONS,
  SettingDefinition,
  validateSettingValue,
} from './settings.config';

/**
 * Server settings (P2) — admin-editable, non-secret platform configuration.
 *
 * Model: a whitelist of typed definitions (settings.config.ts) overlays a
 * single `system_settings` key/value table. Stored rows OVERRIDE defaults;
 * anything not stored yet reads as its default, so the table only ever
 * carries deltas.
 *
 * Fail-closed rules:
 *   - unknown key on READ   → 404 (the vocabulary is public, but a missing
 *     key is still a missing resource);
 *   - unknown key on WRITE  → 400 (a typo must bounce, not create a row the
 *     enforcement seams would silently ignore);
 *   - value out of type/bounds → 400 naming the exact rule;
 *   - every successful write is hash-chained into the audit log (C11) with
 *     the previous and new value — server-wide config changes must never be
 *     deniable.
 */

export interface SettingDto {
  key: string;
  category: string;
  label: string;
  description: string;
  type: string;
  /** Current effective value (stored override, else the definition default). */
  value: string | number | boolean;
  default: string | number | boolean;
  min: number | null;
  max: number | null;
  min_length: number | null;
  max_length: number | null;
  /** Honesty flag: runtime actually reads this value when true. */
  enforced: boolean;
  /** null = never changed from the default (no stored row). */
  updated_at: string | null;
  updated_by: string | null;
}

interface SettingRow {
  key: string;
  value: unknown;
  updated_by: string | null;
  updated_at: Date;
}

@Injectable()
export class SettingsService {
  private readonly logger = new Logger(SettingsService.name);

  constructor(
    private readonly prisma: PrismaService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  /** All settings with effective values, in catalog order. */
  async list(): Promise<{ data: SettingDto[] }> {
    const rows = await this.prisma.systemSetting.findMany();
    const stored = new Map<string, SettingRow>(
      (rows as SettingRow[]).map((r) => [r.key, r]),
    );
    return {
      data: SETTING_DEFINITIONS.map((def) => toDto(def, stored.get(def.key))),
    };
  }

  /** One setting by key; unknown keys are 404 (nothing secret to probe). */
  async get(key: string): Promise<SettingDto> {
    const def = this.definition(key, NotFoundException);
    const row = (await this.prisma.systemSetting.findUnique({
      where: { key },
    })) as SettingRow | null;
    return toDto(def, row);
  }

  /**
   * Stores a new value for a whitelisted key. The write and its audit entry
   * share one transaction, matching the packages/accounts pattern — a config
   * change without its audit entry must be impossible.
   */
  async update(
    key: string,
    value: unknown,
    actorUserId?: string,
  ): Promise<SettingDto> {
    const def = this.definition(key, BadRequestException);
    if (value === undefined) {
      throw new BadRequestException('value is required');
    }
    let normalized: string | number | boolean;
    try {
      normalized = validateSettingValue(def, value);
    } catch (err) {
      if (err instanceof BadRequestLike) {
        throw new BadRequestException(err.message);
      }
      throw err;
    }

    const previous = (await this.prisma.systemSetting.findUnique({
      where: { key },
    })) as SettingRow | null;

    const row = await this.prisma.$transaction(async (tx) => {
      const upserted = (await tx.systemSetting.upsert({
        where: { key },
        create: {
          key,
          value: normalized,
          updated_by: actorUserId ?? null,
          updated_at: new Date(),
        },
        update: {
          value: normalized,
          updated_by: actorUserId ?? null,
          updated_at: new Date(),
        },
      })) as SettingRow;
      await this.audit.appendWithClient(tx, {
        operation: 'settings.update',
        parameters: {
          key,
          from: previous ? previous.value : def.default,
          to: normalized,
          enforced: def.enforced,
        },
        outcome: 'success',
        actorUserId: actorUserId ?? null,
      });
      return upserted;
    });

    this.logger.log(
      `setting ${key} updated → ${JSON.stringify(normalized)} (by ${actorUserId ?? 'system'})`,
    );
    return toDto(def, row);
  }

  /** Unknown key: 404 on read paths, 400 on write paths. */
  private definition(key: string, onMissing: new (m: string) => Error): SettingDefinition {
    const def = findSettingDefinition(key);
    if (!def) {
      throw new onMissing(
        `unknown setting key '${key}' (the settings vocabulary is whitelisted; see the server-settings screen)`,
      );
    }
    return def;
  }
}

function toDto(def: SettingDefinition, row?: SettingRow | null): SettingDto {
  return {
    key: def.key,
    category: def.category,
    label: def.label,
    description: def.description,
    type: def.type,
    value: row ? (row.value as string | number | boolean) : def.default,
    default: def.default,
    min: def.min ?? null,
    max: def.max ?? null,
    min_length: def.min_length ?? null,
    max_length: def.max_length ?? null,
    enforced: def.enforced,
    updated_at: row ? row.updated_at.toISOString() : null,
    updated_by: row?.updated_by ?? null,
  };
}
