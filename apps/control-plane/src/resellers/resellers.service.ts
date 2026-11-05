import { BadRequestException, ConflictException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';

/**
 * Resellers (API spec §4.6) — a reseller IS a hosting account granted
 * reseller capability (master architecture §Resellers): the `resellers` row
 * hangs off a live `hosting_accounts` row (UNIQUE, ON DELETE CASCADE) and
 * carries nesting, white-label branding and the custom panel domain
 * (ADR-0003, v1.0).
 *
 * Nesting policy (Decision 3): the data model supports unlimited depth; the
 * DEFAULT POLICY caps at 2 levels and server admins raise it via
 * `RESELLER_MAX_DEPTH` — no code ceiling, an admin-controlled policy knob.
 * Re-parenting recomputes depths for the whole moved subtree and refuses
 * moves that would push the node or any descendant past the cap, or create
 * a cycle.
 *
 * Custom domains (ADR-0003 + C14): POST sets the domain with status
 * 'pending' — the certificate issuance that flips it to 'active' is an
 * out-of-band ACME process (record management only here). Uniqueness among
 * LIVE resellers is enforced in the service (the schema index is plain, not
 * unique). C14 enforcement (auth/session-host.ts) consumes ONLY rows with
 * status 'active'.
 *
 * Deletion is a SOFT delete refused with 409 while live child resellers
 * exist; the underlying hosting account is untouched (capability removal,
 * not account termination).
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
const BRANDING_KEY_RE = /^[a-z0-9_]{1,32}$/;
const BRANDING_MAX_BYTES = 8 * 1024;
const HEX_COLOR_RE = /^#[0-9a-f]{6}$/;

/** Nesting depth cap (Decision 3): default 2, admin-raisable via env. */
export function resellerMaxDepth(): number {
  const raw = Number(process.env.RESELLER_MAX_DEPTH ?? 2);
  return Number.isInteger(raw) && raw >= 1 ? raw : 2;
}

export interface ResellerDto {
  id: string;
  hosting_account: { id: string; username: string; status: string };
  parent_reseller_id: string | null;
  depth: number;
  branding: Record<string, unknown>;
  custom_domain: string | null;
  custom_domain_status: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateResellerInput {
  hosting_account_id?: unknown;
  parent_reseller_id?: unknown;
}

export interface UpdateResellerInput {
  parent_reseller_id?: unknown; // null re-parents to top level
}

/**
 * Fail-closed branding validation. Key-open (the schema stores jsonb and
 * the branded login page reads the flags it knows), but every value is
 * type- and size-checked, and the semantically known keys get strict
 * formats: brand_name (1–100), primary_color/accent_color (#rrggbb),
 * logo_url (https only, ≤ 500), login_message (≤ 300).
 */
export function validateBranding(input: unknown): Record<string, unknown> {
  if (input === null || input === undefined) {
    return {};
  }
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new BadRequestException('branding must be an object');
  }
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (!BRANDING_KEY_RE.test(key)) {
      throw new BadRequestException(`branding: key '${key}' must match [a-z0-9_], ≤ 32 chars`);
    }
    if (typeof value === 'string') {
      if (value.trim().length > 300) {
        throw new BadRequestException(`branding: '${key}' exceeds 300 characters`);
      }
    } else if (typeof value !== 'boolean' && (typeof value !== 'number' || !Number.isFinite(value))) {
      throw new BadRequestException(`branding: '${key}' must be a string, boolean or number`);
    }
  }
  const branding = input as Record<string, unknown>;
  const brandName = branding['brand_name'];
  if (brandName !== undefined && (typeof brandName !== 'string' || brandName.trim().length < 1 || brandName.trim().length > 100)) {
    throw new BadRequestException("branding: 'brand_name' must be 1–100 characters");
  }
  for (const key of ['primary_color', 'accent_color'] as const) {
    const v = branding[key];
    if (v !== undefined && (typeof v !== 'string' || !HEX_COLOR_RE.test(v.trim()))) {
      throw new BadRequestException(`branding: '${key}' must be a #rrggbb color`);
    }
  }
  const logo = branding['logo_url'];
  if (logo !== undefined && (typeof logo !== 'string' || !logo.trim().startsWith('https://') || logo.trim().length > 500)) {
    throw new BadRequestException("branding: 'logo_url' must be an https:// URL (≤ 500 chars)");
  }
  const message = branding['login_message'];
  if (message !== undefined && (typeof message !== 'string' || message.trim().length > 300)) {
    throw new BadRequestException("branding: 'login_message' must be ≤ 300 characters");
  }
  if (Buffer.byteLength(JSON.stringify(branding), 'utf8') > BRANDING_MAX_BYTES) {
    throw new BadRequestException('branding exceeds 8 KiB');
  }
  return branding;
}

/**
 * Validates a reseller custom domain candidate (ADR-0003). Returns the
 * normalized (lowercase, trailing dot stripped) domain or throws. Ports,
 * paths, wildcards and underscores are rejected — the value becomes a cookie
 * origin (C14), not a URL.
 */
export function validateCustomDomain(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new BadRequestException('custom_domain must be a string');
  }
  const domain = raw.trim().toLowerCase().replace(/\.$/, '');
  if (domain.length < 3 || domain.length > 253 || !DOMAIN_RE.test(domain)) {
    throw new BadRequestException(
      'custom_domain must be a valid hostname (dot-separated [a-z0-9-] labels; no port, path or wildcard)',
    );
  }
  return domain;
}

@Injectable()
export class ResellersService {
  private readonly logger = new Logger(ResellersService.name);

  constructor(
    private readonly prisma: PrismaService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  async list(): Promise<{ data: ResellerDto[] }> {
    const rows = await this.prisma.reseller.findMany({
      where: { deleted_at: null },
      orderBy: { created_at: 'asc' },
      take: 200,
      include: { hosting_account: { select: { id: true, username: true, status: true } } },
    });
    return { data: rows.map((r) => toDto(r)) };
  }

  async get(id: string): Promise<ResellerDto> {
    const row = await this.findLive(id);
    return toDto(row);
  }

  /** Grants reseller capability to an existing, live hosting account. */
  async create(input: CreateResellerInput, actorUserId?: string): Promise<ResellerDto> {
    const accountId = typeof input.hosting_account_id === 'string' ? input.hosting_account_id.trim() : '';
    if (!UUID_RE.test(accountId)) {
      throw new BadRequestException('hosting_account_id must be a uuid');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true, status: true },
    });
    if (!account) {
      throw new NotFoundException('hosting account not found');
    }
    const existing = await this.prisma.reseller.findFirst({
      where: { hosting_account_id: account.id, deleted_at: null },
      select: { id: true },
    });
    if (existing) {
      throw new ConflictException('account is already a reseller');
    }

    let parentId: string | null = null;
    let depth = 1;
    if (input.parent_reseller_id !== undefined && input.parent_reseller_id !== null) {
      if (typeof input.parent_reseller_id !== 'string' || !UUID_RE.test(input.parent_reseller_id.trim())) {
        throw new BadRequestException('parent_reseller_id must be a uuid or null');
      }
      const parent = await this.findLive(input.parent_reseller_id.trim());
      parentId = parent.id;
      depth = parent.depth + 1;
      if (depth > resellerMaxDepth()) {
        throw new BadRequestException(
          `reseller depth ${depth} exceeds the configured cap of ${resellerMaxDepth()} (RESELLER_MAX_DEPTH)`,
        );
      }
    }

    const row = await this.prisma.reseller.create({
      data: { hosting_account_id: account.id, parent_reseller_id: parentId, depth },
      include: { hosting_account: { select: { id: true, username: true, status: true } } },
    });
    await this.audit.append({
      operation: 'reseller.create',
      parameters: {
        reseller_id: row.id,
        hosting_account_id: account.id,
        username: account.username,
        parent_reseller_id: parentId,
        depth,
      },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    this.logger.log(`reseller granted on account ${account.username} (depth ${depth})`);
    return toDto(row);
  }

  /**
   * Re-parents a reseller (the only mutable scalar — branding and the custom
   * domain have dedicated endpoints). `parent_reseller_id: null` moves the
   * reseller to the top level. Validates cycles, shifts the moved subtree's
   * depths with the node and enforces the depth cap for EVERY shifted row.
   */
  async update(id: string, input: UpdateResellerInput, actorUserId?: string): Promise<ResellerDto> {
    if (input.parent_reseller_id === undefined) {
      throw new BadRequestException('nothing to update (only parent_reseller_id is mutable here)');
    }
    const row = await this.findLive(id);

    let nextParentId: string | null = null;
    let nextDepth = 1;
    if (input.parent_reseller_id !== null) {
      if (typeof input.parent_reseller_id !== 'string' || !UUID_RE.test(input.parent_reseller_id.trim())) {
        throw new BadRequestException('parent_reseller_id must be a uuid or null');
      }
      const parent = await this.findLive(input.parent_reseller_id.trim());
      if (parent.id === row.id) {
        throw new BadRequestException('a reseller cannot be its own parent');
      }
      const subtreeIds = await this.collectSubtreeIds(row.id);
      if (subtreeIds.has(parent.id)) {
        throw new BadRequestException('cannot re-parent a reseller under its own descendant');
      }
      nextParentId = parent.id;
      nextDepth = parent.depth + 1;
    }

    const shift = nextDepth - row.depth;
    if (shift !== 0) {
      const cap = resellerMaxDepth();
      if (nextDepth > cap) {
        throw new BadRequestException(
          `reseller depth ${nextDepth} exceeds the configured cap of ${cap} (RESELLER_MAX_DEPTH)`,
        );
      }
      const subtree = await this.collectSubtree(row.id); // descendants only
      for (const node of subtree) {
        if (node.depth + shift > cap) {
          throw new BadRequestException(
            `re-parent would push '${node.username}' to depth ${node.depth + shift}, beyond the cap of ${cap} (RESELLER_MAX_DEPTH)`,
          );
        }
      }
      for (const node of subtree) {
        await this.prisma.reseller.update({
          where: { id: node.id },
          data: { depth: node.depth + shift, updated_at: new Date() },
        });
      }
    }

    const updated = await this.prisma.reseller.update({
      where: { id: row.id },
      data: { parent_reseller_id: nextParentId, depth: nextDepth, updated_at: new Date() },
      include: { hosting_account: { select: { id: true, username: true, status: true } } },
    });
    await this.audit.append({
      operation: 'reseller.update',
      parameters: { reseller_id: row.id, parent_reseller_id: nextParentId, depth: nextDepth },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    return toDto(updated);
  }

  /** Soft-deletes; refused while live child resellers reference the row. */
  async remove(id: string, actorUserId?: string): Promise<void> {
    const row = await this.findLive(id);
    const children = await this.prisma.reseller.count({
      where: { parent_reseller_id: row.id, deleted_at: null },
    });
    if (children > 0) {
      throw new ConflictException(
        `reseller still has ${children} child reseller(s) — re-parent or delete them first`,
      );
    }
    await this.prisma.reseller.update({
      where: { id: row.id },
      data: { deleted_at: new Date(), custom_domain: null, custom_domain_status: null },
    });
    await this.audit.append({
      operation: 'reseller.delete',
      parameters: { reseller_id: row.id, hosting_account_id: row.hosting_account_id },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    this.logger.log(`deleted reseller ${row.id} (account ${row.hosting_account_id})`);
  }

  async getBranding(id: string): Promise<{ branding: Record<string, unknown> }> {
    const row = await this.findLive(id);
    return { branding: (row.branding ?? {}) as Record<string, unknown> };
  }

  /** FULL replacement (same semantics as package quotas/features updates). */
  async updateBranding(
    id: string,
    input: { branding?: unknown },
    actorUserId?: string,
  ): Promise<{ branding: Record<string, unknown> }> {
    const row = await this.findLive(id);
    const branding = validateBranding(input.branding);
    await this.prisma.reseller.update({
      where: { id: row.id },
      data: { branding: branding as object, updated_at: new Date() },
    });
    await this.audit.append({
      operation: 'reseller.branding.update',
      parameters: { reseller_id: row.id, keys: Object.keys(branding) },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    return { branding };
  }

  /**
   * Sets the custom panel domain (status 'pending' — an out-of-band ACME
   * process flips it to 'active'; C14 enforcement consumes active rows only).
   * Uniqueness among LIVE resellers (409): two resellers claiming one origin
   * would defeat the C14 host classification.
   */
  async setCustomDomain(id: string, input: { custom_domain?: unknown }, actorUserId?: string): Promise<ResellerDto> {
    const row = await this.findLive(id);
    const domain = validateCustomDomain(input.custom_domain);
    const clash = await this.prisma.reseller.findFirst({
      where: { custom_domain: domain, deleted_at: null, id: { not: row.id } },
      select: { id: true },
    });
    if (clash) {
      throw new ConflictException('custom_domain is already claimed by another reseller');
    }
    const updated = await this.prisma.reseller.update({
      where: { id: row.id },
      data: { custom_domain: domain, custom_domain_status: 'pending', updated_at: new Date() },
      include: { hosting_account: { select: { id: true, username: true, status: true } } },
    });
    await this.audit.append({
      operation: 'reseller.custom_domain.set',
      parameters: { reseller_id: row.id, custom_domain: domain },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    return toDto(updated);
  }

  async clearCustomDomain(id: string, actorUserId?: string): Promise<ResellerDto> {
    const row = await this.findLive(id);
    const updated = await this.prisma.reseller.update({
      where: { id: row.id },
      data: { custom_domain: null, custom_domain_status: null, updated_at: new Date() },
      include: { hosting_account: { select: { id: true, username: true, status: true } } },
    });
    await this.audit.append({
      operation: 'reseller.custom_domain.clear',
      parameters: { reseller_id: row.id, previous_domain: row.custom_domain },
      outcome: 'success',
      actorUserId: actorUserId ?? null,
    });
    return toDto(updated);
  }

  private async findLive(id: string) {
    if (!UUID_RE.test(id)) {
      throw new NotFoundException('reseller not found');
    }
    const row = await this.prisma.reseller.findFirst({
      where: { id, deleted_at: null },
      include: { hosting_account: { select: { id: true, username: true, status: true } } },
    });
    if (!row) {
      throw new NotFoundException('reseller not found');
    }
    return row;
  }

  /** ids of the node itself + every live descendant (cycle guard). */
  private async collectSubtreeIds(rootId: string): Promise<Set<string>> {
    const ids = new Set<string>([rootId]);
    let frontier = [rootId];
    while (frontier.length > 0) {
      const children = await this.prisma.reseller.findMany({
        where: { parent_reseller_id: { in: frontier }, deleted_at: null },
        select: { id: true },
      });
      frontier = children.map((c) => c.id).filter((cid) => !ids.has(cid));
      for (const cid of frontier) ids.add(cid);
    }
    return ids;
  }

  /** live descendants EXCLUDING the node itself, with depth + username. */
  private async collectSubtree(rootId: string): Promise<Array<{ id: string; depth: number; username: string }>> {
    const out: Array<{ id: string; depth: number; username: string }> = [];
    let frontier = [rootId];
    while (frontier.length > 0) {
      const children = await this.prisma.reseller.findMany({
        where: { parent_reseller_id: { in: frontier }, deleted_at: null },
        select: { id: true, depth: true, hosting_account: { select: { username: true } } },
      });
      frontier = [];
      for (const c of children) {
        out.push({ id: c.id, depth: c.depth, username: c.hosting_account.username });
        frontier.push(c.id);
      }
    }
    return out;
  }
}

type ResellerRow = {
  id: string;
  hosting_account: { id: string; username: string; status: string };
  hosting_account_id: string;
  parent_reseller_id: string | null;
  depth: number;
  branding: unknown;
  custom_domain: string | null;
  custom_domain_status: string | null;
  created_at: Date;
  updated_at: Date;
};

function toDto(row: ResellerRow): ResellerDto {
  return {
    id: row.id,
    hosting_account: row.hosting_account,
    parent_reseller_id: row.parent_reseller_id,
    depth: row.depth,
    branding: (row.branding ?? {}) as Record<string, unknown>,
    custom_domain: row.custom_domain,
    custom_domain_status: row.custom_domain_status,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
  };
}
