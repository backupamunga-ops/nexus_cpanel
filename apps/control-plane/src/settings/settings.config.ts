/**
 * Server settings catalog — the whitelist that makes system_settings safe.
 *
 * Fail-closed by construction (mirrors the packages quota-key rule):
 *
 *   - ONLY the keys below exist. Reads of unknown keys are 404, writes are
 *     400 — a typo'd key can never silently enforce nothing.
 *   - Each definition is a typed scalar (string | integer | boolean) with
 *     explicit bounds; the service rejects anything outside them, so the UI
 *     can render bounds from the same source the server enforces.
 *   - Values are NON-SECRET configuration. Secrets (JWT key, TOTP envelope
 *     key, SMTP credentials) live in env/secret files — never in this table.
 *
 * `enforced` is an honesty flag, not a capability flag: `false` means the
 * value is stored, validated and audited but the runtime seam that reads it
 * has not landed yet. The UI renders "stored — not yet enforced" for those;
 * enforcement wiring lands incrementally (decision D-11) and flips the flag.
 *
 * Enforced today (live-read at each enforcement event, stored override
 * wins, catalog default on any read failure — SettingsService.runtimeInt):
 *   - security.max_failed_logins / security.lockout_minutes (login lockout)
 *   - security.session_ttl_days (refresh sliding window + cookie Max-Age)
 *   - security.password_min_length (every new password, via PasswordService)
 *
 * Still stored-only: platform.instance_name, platform.login_notice,
 * security.totp_required, audit.retention_days (their seams — UI headings,
 * sign-in banner, a TOTP enrollment gate, retention pruning — are separate
 * batches).
 */

export type SettingCategory = 'platform' | 'security' | 'audit';
export type SettingType = 'string' | 'integer' | 'boolean';

export interface SettingDefinition {
  key: string;
  category: SettingCategory;
  label: string;
  description: string;
  type: SettingType;
  default: string | number | boolean;
  /** Integer bounds (type === 'integer'). */
  min?: number;
  max?: number;
  /** String length bounds (type === 'string'). */
  min_length?: number;
  max_length?: number;
  enforced: boolean;
}

export const SETTING_DEFINITIONS: readonly SettingDefinition[] = [
  {
    key: 'platform.instance_name',
    category: 'platform',
    label: 'Instance name',
    description:
      'Display name for this NexusPanel installation (panel headings and outbound mail signatures once wired).',
    type: 'string',
    default: 'NexusPanel',
    min_length: 1,
    max_length: 64,
    enforced: false,
  },
  {
    key: 'platform.login_notice',
    category: 'platform',
    label: 'Login notice',
    description:
      'Optional banner text shown on the sign-in page once wired — e.g. an authorized-use warning.',
    type: 'string',
    default: '',
    min_length: 0,
    max_length: 200,
    enforced: false,
  },
  {
    key: 'security.totp_required',
    category: 'security',
    label: 'Require two-factor authentication',
    description:
      'When enforced, every user must enroll TOTP (C2) before the panel grants access. Enforcement wiring pending.',
    type: 'boolean',
    default: false,
    enforced: false,
  },
  {
    key: 'security.max_failed_logins',
    category: 'security',
    label: 'Max failed logins before lockout',
    description:
      'Failed password or second-factor attempts allowed before the account locks. Read live at every login attempt; falls back to 5 only if unset.',
    type: 'integer',
    default: 5,
    min: 3,
    max: 10,
    enforced: true,
  },
  {
    key: 'security.lockout_minutes',
    category: 'security',
    label: 'Lockout duration (minutes)',
    description:
      'How long an account stays locked after exceeding the failure threshold. Read live when a lock is applied; falls back to 15 only if unset.',
    type: 'integer',
    default: 15,
    min: 5,
    max: 1440,
    enforced: true,
  },
  {
    key: 'security.password_min_length',
    category: 'security',
    label: 'Minimum password length',
    description:
      'Shortest accepted password (Argon2id, C1). Read live whenever a password is set; falls back to 12 only if unset. Backup codes are hashed outside this policy.',
    type: 'integer',
    default: 12,
    min: 8,
    max: 128,
    enforced: true,
  },
  {
    key: 'security.session_ttl_days',
    category: 'security',
    label: 'Session lifetime (days)',
    description:
      'Refresh-token lifetime; sessions are device-bound (C3) and rotate on every refresh. Read live at login and each refresh (cookie Max-Age follows); falls back to 7 only if unset.',
    type: 'integer',
    default: 7,
    min: 1,
    max: 30,
    enforced: true,
  },
  {
    key: 'audit.retention_days',
    category: 'audit',
    label: 'Audit retention (days)',
    description:
      'How long hash-chained audit entries (C11) are kept before archival. Retention pruning is not built yet.',
    type: 'integer',
    default: 365,
    min: 30,
    max: 3650,
    enforced: false,
  },
];

const BY_KEY = new Map(SETTING_DEFINITIONS.map((d) => [d.key, d]));

/** Definition lookup — undefined for unknown keys (callers fail closed). */
export function findSettingDefinition(key: string): SettingDefinition | undefined {
  return BY_KEY.get(key);
}

/**
 * Validates `input` against a definition and returns the normalized value.
 * Throws BadRequestLike on any mismatch — the service maps that to a 400
 * whose detail names the exact rule broken (same style as the packages
 * quota validators).
 */
export function validateSettingValue(
  def: SettingDefinition,
  input: unknown,
): string | number | boolean {
  if (def.type === 'boolean') {
    if (typeof input !== 'boolean') {
      throw new BadRequestLike(`${def.key} must be a boolean`);
    }
    return input;
  }
  if (def.type === 'integer') {
    if (typeof input !== 'number' || !Number.isInteger(input)) {
      throw new BadRequestLike(`${def.key} must be an integer`);
    }
    if (def.min !== undefined && input < def.min) {
      throw new BadRequestLike(`${def.key} must be at least ${def.min}`);
    }
    if (def.max !== undefined && input > def.max) {
      throw new BadRequestLike(`${def.key} must be at most ${def.max}`);
    }
    return input;
  }
  // string
  if (typeof input !== 'string') {
    throw new BadRequestLike(`${def.key} must be a string`);
  }
  const trimmed = input.trim();
  if (def.min_length !== undefined && trimmed.length < def.min_length) {
    throw new BadRequestLike(`${def.key} must be at least ${def.min_length} character(s)`);
  }
  if (def.max_length !== undefined && trimmed.length > def.max_length) {
    throw new BadRequestLike(`${def.key} must be at most ${def.max_length} characters`);
  }
  return trimmed;
}

/** Local shim so this file stays dependency-free (the service maps it to BadRequestException). */
export class BadRequestLike extends Error {}
