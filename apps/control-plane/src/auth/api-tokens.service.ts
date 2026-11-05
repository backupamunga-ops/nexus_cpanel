import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { KNOWN_PERMISSIONS } from '../common/permissions';
import * as crypto from 'node:crypto';
import { isIP } from 'node:net';

/**
 * API tokens (security control C4, API spec §4.3) — scoped automation
 * credentials for CLIs and machines.
 *
 * Token format:  `npt_<base64url(32 random bytes)>` — opaque, high-entropy,
 * shown exactly once at create/rotate. Only the SHA-256 of the full string is
 * stored (`api_tokens.token_hash bytea UNIQUE`); a database leak therefore
 * reveals nothing usable.
 *
 * Authorization model (defense in depth): a token authenticates AS its owner,
 * but the PermissionsGuard requires BOTH (a) the required permission is in
 * the token's scopes AND (b) the owner's own session-level authorization
 * would pass. A token can never grant more than its owner holds, and a
 * super-admin's token is still bounded by its scopes.
 *
 * Token lifecycle routes are @SessionOnly(): an API token can never list,
 * mint, rotate or revoke credentials — least privilege for stolen-token
 * blast radius. `last_used_at` is updated at most once per minute
 * (fire-and-forget) so hot automation loops don't hammer the database.
 */

export const API_TOKEN_PREFIX = 'npt_';
const SECRET_BYTES = 32;
const NAME_MAX = 100;
const LAST_USED_THROTTLE_MS = 60_000;

export interface ApiTokenDto {
  id: string;
  name: string;
  scopes: string[];
  ip_allowlist: string[];
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
  revoked_at: string | null;
}

export interface CreateApiTokenInput {
  name?: string;
  scopes?: unknown;
  expires_at?: unknown;
  ip_allowlist?: unknown;
}

/** Discriminated result of presenting a bearer API token. */
export type ApiTokenAuthResult =
  | { ok: true; userId: string; tokenId: string; scopes: string[] }
  | {
      ok: false;
      /** `unknown` hashes are NOT audited (pure noise); the rest are. */
      reason: 'unknown' | 'revoked' | 'expired' | 'ip_denied' | 'user_inactive';
      userId?: string;
      tokenId?: string;
      scopes?: string[];
    };

export function hashApiToken(raw: string): Buffer {
  return crypto.createHash('sha256').update(raw, 'utf8').digest();
}

export function mintApiToken(): string {
  return API_TOKEN_PREFIX + crypto.randomBytes(SECRET_BYTES).toString('base64url');
}

@Injectable()
export class ApiTokensService {
  constructor(
    private readonly prisma: PrismaService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  /**
   * Authenticates a raw `npt_…` bearer credential. Uniform `unknown` result
   * for hash misses — the caller answers 401 without revealing why.
   */
  async authenticate(raw: string, ip: string | null): Promise<ApiTokenAuthResult> {
    const row = await this.prisma.apiToken.findUnique({
      where: { token_hash: new Uint8Array(hashApiToken(raw)) },
      include: { user: { select: { id: true, is_active: true, deleted_at: true } } },
    });
    if (!row) {
      return { ok: false, reason: 'unknown' };
    }
    if (row.revoked_at) {
      await this.auditRejected('revoked', row);
      return { ok: false, reason: 'revoked', userId: row.user_id, tokenId: row.id, scopes: row.scopes };
    }
    if (row.expires_at && row.expires_at.getTime() <= Date.now()) {
      await this.auditRejected('expired', row);
      return { ok: false, reason: 'expired', userId: row.user_id, tokenId: row.id, scopes: row.scopes };
    }
    if (row.ip_allowlist.length > 0) {
      // Exact textual match against Postgres-rendered inet values; entries
      // must be literal addresses (CIDR ranges are a documented non-goal of
      // the P2 slice).
      if (!ip || !row.ip_allowlist.includes(ip)) {
        await this.auditRejected('ip_denied', row);
        return { ok: false, reason: 'ip_denied', userId: row.user_id, tokenId: row.id, scopes: row.scopes };
      }
    }
    if (!row.user.is_active || row.user.deleted_at) {
      await this.auditRejected('user_inactive', row);
      return { ok: false, reason: 'user_inactive', userId: row.user_id, tokenId: row.id, scopes: row.scopes };
    }

    const stale =
      !row.last_used_at || Date.now() - row.last_used_at.getTime() > LAST_USED_THROTTLE_MS;
    if (stale) {
      // Fire-and-forget: auth must not fail because a telemetry write did.
      void this.prisma.apiToken
        .update({ where: { id: row.id }, data: { last_used_at: new Date() } })
        .catch(() => undefined);
    }
    return { ok: true, userId: row.user_id, tokenId: row.id, scopes: row.scopes };
  }

  /** Creates a token. The plaintext secret is returned ONCE and never stored. */
  async create(userId: string, input: CreateApiTokenInput): Promise<{ token: string; record: ApiTokenDto }> {
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (name.length < 1 || name.length > NAME_MAX) {
      throw new BadRequestException(`name is required (1–${NAME_MAX} characters)`);
    }

    const scopes = this.validateScopes(input.scopes);
    const ipAllowlist = this.validateIpAllowlist(input.ip_allowlist);
    const expiresAt = this.validateExpiry(input.expires_at);

    const token = mintApiToken();
    const row = await this.prisma.apiToken.create({
      data: {
        user_id: userId,
        name,
        scopes,
        ip_allowlist: ipAllowlist,
        expires_at: expiresAt,
        token_hash: new Uint8Array(hashApiToken(token)),
      },
    });

    await this.audit.append({
      operation: 'api_token.create',
      parameters: { token_id: row.id, name, scopes, expires_at: expiresAt?.toISOString() ?? null },
      outcome: 'success',
      actorUserId: userId,
    });
    return { token, record: this.toDto(row) };
  }

  /** Lists the caller's own tokens (never the hash, never any secret). */
  async list(userId: string): Promise<{ data: ApiTokenDto[] }> {
    const rows = await this.prisma.apiToken.findMany({
      where: { user_id: userId },
      orderBy: { created_at: 'desc' },
      take: 200,
    });
    return { data: rows.map((r) => this.toDto(r)) };
  }

  /** Revokes one of the caller's own tokens. Idempotent for own tokens. */
  async revoke(userId: string, tokenId: string): Promise<void> {
    const row = await this.prisma.apiToken.findFirst({ where: { id: tokenId, user_id: userId } });
    if (!row) {
      await this.audit.append({
        operation: 'api_token.revoke',
        parameters: { token_id: tokenId, reason: 'not_found_or_foreign' },
        outcome: 'failure',
        actorUserId: userId,
      });
      throw new NotFoundException('token not found');
    }
    if (!row.revoked_at) {
      await this.prisma.apiToken.update({
        where: { id: row.id },
        data: { revoked_at: new Date() },
      });
      await this.audit.append({
        operation: 'api_token.revoke',
        parameters: { token_id: row.id, name: row.name },
        outcome: 'success',
        actorUserId: userId,
      });
    }
  }

  /**
   * Rotates a token: the old secret is revoked, a new secret is minted with
   * the same name/scopes/IP allowlist and the SAME expiry (rotation never
   * extends a token's lifetime). The new secret is returned once.
   */
  async rotate(userId: string, tokenId: string): Promise<{ token: string; record: ApiTokenDto }> {
    const old = await this.prisma.apiToken.findFirst({ where: { id: tokenId, user_id: userId } });
    if (!old || old.revoked_at) {
      await this.audit.append({
        operation: 'api_token.rotate',
        parameters: { token_id: tokenId, reason: old ? 'already_revoked' : 'not_found_or_foreign' },
        outcome: 'failure',
        actorUserId: userId,
      });
      throw new NotFoundException('token not found');
    }

    const token = mintApiToken();
    const created = await this.prisma.$transaction(async (tx) => {
      await tx.apiToken.update({ where: { id: old.id }, data: { revoked_at: new Date() } });
      return tx.apiToken.create({
        data: {
          user_id: userId,
          name: old.name,
          scopes: old.scopes,
          ip_allowlist: old.ip_allowlist,
          expires_at: old.expires_at,
          token_hash: new Uint8Array(hashApiToken(token)),
        },
      });
    });

    await this.audit.append({
      operation: 'api_token.rotate',
      parameters: { token_id: old.id, new_token_id: created.id, name: old.name, scopes: old.scopes },
      outcome: 'success',
      actorUserId: userId,
    });
    return { token, record: this.toDto(created) };
  }

  // ───────────────────────────── validation ─────────────────────────────

  /**
   * Scopes must be a non-empty array of KNOWN_PERMISSIONS strings. Unknown
   * permissions are rejected (a typo'd scope would silently match nothing —
   * the operator deserves the error instead). Duplicates removed; order
   * normalized for stable storage.
   */
  private validateScopes(raw: unknown): string[] {
    if (!Array.isArray(raw) || raw.length === 0) {
      throw new BadRequestException('scopes must be a non-empty array');
    }
    const known = new Set<string>(KNOWN_PERMISSIONS);
    const out = new Set<string>();
    for (const s of raw) {
      if (typeof s !== 'string' || !known.has(s)) {
        throw new BadRequestException(`unknown scope: ${JSON.stringify(s ?? null)}`);
      }
      out.add(s);
    }
    return [...out].sort();
  }

  private validateIpAllowlist(raw: unknown): string[] {
    if (raw === undefined || raw === null) {
      return [];
    }
    if (!Array.isArray(raw)) {
      throw new BadRequestException('ip_allowlist must be an array of IP addresses');
    }
    const out = new Set<string>();
    for (const v of raw) {
      if (typeof v !== 'string' || isIP(v.trim()) === 0) {
        throw new BadRequestException(`ip_allowlist entry is not a valid IP address: ${JSON.stringify(v ?? null)}`);
      }
      out.add(v.trim());
    }
    return [...out];
  }

  private validateExpiry(raw: unknown): Date | null {
    if (raw === undefined || raw === null) {
      return null;
    }
    const d = new Date(String(raw));
    if (Number.isNaN(d.getTime())) {
      throw new BadRequestException('expires_at is not a valid date');
    }
    if (d.getTime() <= Date.now()) {
      throw new BadRequestException('expires_at must be in the future');
    }
    return d;
  }

  // ───────────────────────────── helpers ─────────────────────────────

  private toDto(row: {
    id: string;
    name: string;
    scopes: string[];
    ip_allowlist: string[];
    expires_at: Date | null;
    last_used_at: Date | null;
    created_at: Date;
    revoked_at: Date | null;
  }): ApiTokenDto {
    return {
      id: row.id,
      name: row.name,
      scopes: row.scopes,
      ip_allowlist: row.ip_allowlist,
      expires_at: row.expires_at?.toISOString() ?? null,
      last_used_at: row.last_used_at?.toISOString() ?? null,
      created_at: row.created_at.toISOString(),
      revoked_at: row.revoked_at?.toISOString() ?? null,
    };
  }

  private async auditRejected(
    reason: Exclude<ApiTokenAuthResult, { ok: true }>['reason'],
    row: { id: string; user_id: string; name: string },
  ): Promise<void> {
    await this.audit.append({
      operation: 'api_token.auth_rejected',
      parameters: { token_id: row.id, name: row.name, reason },
      outcome: 'failure',
      actorUserId: row.user_id,
    });
  }
}


