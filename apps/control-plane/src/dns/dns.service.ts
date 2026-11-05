import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import * as dns from 'node:dns';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { Actor } from '../sites/sites.service';

/**
 * DNS zones & records (API spec §4.9) — PowerDNS authority, ADR-0012.
 *
 * The agent is the only writer of DNS state (PowerDNS API + pdnsutil); the
 * panel owns the registry mirror (dns_zones / dns_records, DDL-first) and
 * the rules:
 *   - provisioning is agent-first: a failed agent call leaves NO row;
 *   - record-level POST/PATCH/DELETE recompute the zone's full desired set
 *     and go through one `dns.apply_records` diff (one writer, one serial
 *     bump) — there is no record-level agent primitive by design;
 *   - SOA is nameserver-owned and rejected in payloads (the agent enforces
 *     this too — both layers);
 *   - DNSSEC state is read LIVE from the node (dns.get_dnssec) — the panel
 *     never claims a secured zone it cannot show material for (D-11).
 *
 * Ownership boundary (C7): every route resolves the owning account and
 * 404s for invisible resources (§3.2 anti-enumeration).
 */

const ZONE_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const ALLOWED_TYPES = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'NS']);
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z-]{2,63}\.?$/i;
const MAX_ZONE_RECORDS = 500;

export interface DnsRecordInput {
  name?: unknown;
  type?: unknown;
  content?: unknown;
  ttl?: unknown;
  priority?: unknown;
  weight?: unknown;
  port?: unknown;
}

export interface DnsRecordDto {
  id: string;
  zone_id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  priority: number | null;
  weight: number | null;
  port: number | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DnsZoneDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  name: string;
  is_active: boolean;
  dnssec_enabled: boolean;
  record_count: number;
  created_at: string;
}

function intOrNull(v: unknown): number | null {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new BadRequestException('priority/weight/port must be integers 0-65535');
  }
  return n;
}

@Injectable()
export class DnsService {
  private readonly logger = new Logger(DnsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  // ---- validation ------------------------------------------------------------

  /**
   * Validates one record input against the zone and returns the shaped row
   * the agent expects. Mirrors the agent's rules (ADR-0012) so callers get
   * a 400 with an actionable message before any node round-trip.
   */
  private shapeRecord(zoneName: string, in_: DnsRecordInput): {
    name: string;
    type: string;
    content: string;
    ttl: number;
    priority: number | null;
    weight: number | null;
    port: number | null;
    /** Content as it will live in PowerDNS (MX/SRV priority composed). */
    wire: string;
  } {
    const type = typeof in_.type === 'string' ? in_.type.trim().toUpperCase() : '';
    if (type === 'SOA') {
      // Named before the allowlist so the operator gets the real reason (ADR-0012).
      throw new BadRequestException('SOA is managed by the nameserver and cannot be set through the panel');
    }
    if (!ALLOWED_TYPES.has(type)) {
      throw new BadRequestException(
        `type must be one of A, AAAA, CNAME, MX, TXT, SRV, CAA, NS (got "${type || 'empty'}")`,
      );
    }
    const rawName = typeof in_.name === 'string' ? in_.name.trim().toLowerCase() : '';
    if (!rawName) {
      throw new BadRequestException('name is required (use "@" for the zone apex)');
    }
    // Name → FQDN without trailing dot, inside the zone.
    let fqdn: string;
    const absolute = rawName.endsWith('.');
    const base = rawName.replace(/\.$/, '');
    if (base === '@') {
      fqdn = zoneName;
    } else if (base === zoneName || base.endsWith('.' + zoneName)) {
      fqdn = base;
    } else if (absolute) {
      throw new BadRequestException(
        `"${rawName}" is outside the zone "${zoneName}" (relative names like "www" get the zone appended)`,
      );
    } else {
      const labels = base.split('.');
      for (let i = 0; i < labels.length; i++) {
        const l = labels[i];
        if (l === '*' && i === 0) continue;
        if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) {
          throw new BadRequestException(`invalid name label "${l}" (letters, digits, hyphens)`);
        }
      }
      fqdn = `${base}.${zoneName}`;
    }

    let content = typeof in_.content === 'string' ? in_.content.trim() : '';
    if (!content || content.length > 4096 || /[\n\r\x00]/.test(content)) {
      throw new BadRequestException('content must be a single line of 1-4096 bytes');
    }
    const ttlRaw = in_.ttl === undefined || in_.ttl === null || in_.ttl === '' ? 3600 : Number(in_.ttl);
    if (!Number.isInteger(ttlRaw) || ttlRaw < 60 || ttlRaw > 604800) {
      throw new BadRequestException('ttl must be an integer between 60 and 604800 seconds');
    }
    const priority = intOrNull(in_.priority);
    const weight = intOrNull(in_.weight);
    const port = intOrNull(in_.port);

    switch (type) {
      case 'A': {
        const m = IPV4_RE.exec(content);
        if (!m || m.slice(1).some((o) => Number(o) > 255)) {
          throw new BadRequestException(`"${content}" is not a valid IPv4 address`);
        }
        break;
      }
      case 'AAAA':
        if (!content.includes(':') || !/^[0-9a-f:]{2,45}$/i.test(content)) {
          throw new BadRequestException(`"${content}" is not a valid IPv6 address`);
        }
        break;
      case 'CNAME':
        if (fqdn === zoneName) {
          throw new BadRequestException('CNAME at the zone apex is not allowed');
        }
        if (!HOST_RE.test(content)) {
          throw new BadRequestException(`CNAME target "${content}" is not a valid hostname`);
        }
        break;
      case 'NS':
        if (!HOST_RE.test(content)) {
          throw new BadRequestException(`NS target "${content}" is not a valid hostname`);
        }
        break;
      case 'MX':
        if (priority === null) throw new BadRequestException('MX records require a priority (0-65535)');
        if (content !== '.' && !HOST_RE.test(content)) {
          throw new BadRequestException(`MX target "${content}" is not a valid hostname`);
        }
        break;
      case 'SRV':
        if (priority === null || weight === null || port === null) {
          throw new BadRequestException('SRV records require priority, weight and port');
        }
        if (content !== '.' && !HOST_RE.test(content)) {
          throw new BadRequestException(`SRV target "${content}" is not a valid hostname`);
        }
        break;
      case 'CAA':
        if (!/^(0|128)\s+(issue|issuewild|iodef)\s+"[^"]*"$/.test(content)) {
          throw new BadRequestException('CAA value must be `0|128 tag "value"` with tag in issue|issuewild|iodef');
        }
        break;
      case 'TXT':
        if (!content.startsWith('"') && /[\s;]/.test(content)) {
          // The API quotes at the boundary; shape it here so the UI preview matches.
          content = `"${content.replace(/"/g, '\\"')}"`;
        }
        break;
    }

    const wire =
      type === 'MX' && priority !== null
        ? `${priority} ${content}`
        : type === 'SRV' && priority !== null && weight !== null && port !== null
          ? `${priority} ${weight} ${port} ${content}`
          : content;

    return { name: fqdn, type, content, ttl: ttlRaw, priority, weight, port, wire };
  }

  private shapeAll(zoneName: string, records: unknown): ReturnType<DnsService['shapeRecord']>[] {
    if (!Array.isArray(records)) {
      throw new BadRequestException('records must be an array');
    }
    if (records.length > MAX_ZONE_RECORDS) {
      throw new BadRequestException(`a zone carries at most ${MAX_ZONE_RECORDS} records`);
    }
    return records.map((r) => this.shapeRecord(zoneName, r as DnsRecordInput));
  }

  // ---- ownership (C7) ---------------------------------------------------------

  private async requireAccount(actor: Actor | undefined, accountId: unknown): Promise<{
    id: string;
    username: string;
  }> {
    if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
      throw new BadRequestException('account_id is required');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true },
    });
    if (!account) throw new NotFoundException('hosting account not found');
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) throw new NotFoundException('hosting account not found');
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: account.id, revoked_at: null },
        select: { id: true },
      });
      if (!access) throw new NotFoundException('hosting account not found');
    }
    return account;
  }

  private async requireVisibleZone(id: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('dns zone not found');
    }
    const zone = await this.prisma.dnZone.findFirst({
      where: { id, deleted_at: null },
      include: { hosting_account: { select: { id: true, username: true } } },
    });
    if (!zone) throw new NotFoundException('dns zone not found');
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) throw new NotFoundException('dns zone not found');
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: zone.hosting_account_id, revoked_at: null },
        select: { id: true },
      });
      if (!access) throw new NotFoundException('dns zone not found');
    }
    return zone;
  }

  // ---- zones -------------------------------------------------------------------

  async listZones(actor: Actor | undefined, accountId: unknown): Promise<{ data: DnsZoneDto[] }> {
    const account = await this.requireAccount(actor, accountId);
    const zones = await this.prisma.dnZone.findMany({
      where: { hosting_account_id: account.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
      include: {
        hosting_account: { select: { username: true } },
        dns_records__zone_id: { where: { deleted_at: null }, select: { id: true } },
      },
    });
    return {
      data: zones.map((z) => ({
        id: z.id,
        hosting_account_id: z.hosting_account_id,
        account_username: z.hosting_account?.username ?? account.username,
        name: z.name,
        is_active: z.is_active,
        dnssec_enabled: z.dnssec_enabled,
        record_count: z.dns_records__zone_id.length,
        created_at: z.created_at.toISOString(),
      })),
    };
  }

  async createZone(
    actor: Actor | undefined,
    input: { account_id?: unknown; name?: unknown; records?: unknown },
  ): Promise<DnsZoneDto> {
    const account = await this.requireAccount(actor, input.account_id);
    const name = typeof input.name === 'string' ? input.name.trim().toLowerCase().replace(/\.$/, '') : '';
    if (!ZONE_NAME_RE.test(name)) {
      throw new BadRequestException(
        'zone must be a lowercase FQDN with at least two labels (e.g. example.com)',
      );
    }
    const dup = await this.prisma.dnZone.findFirst({ where: { name, deleted_at: null }, select: { id: true } });
    if (dup) throw new ConflictException('this zone is already managed by the panel');

    const shaped = this.shapeAll(name, input.records ?? []);

    let agentResult: { status: string; soa_seeded: boolean; record_count: number };
    try {
      agentResult = await this.agent.dnsCreateZone(name, shaped);
    } catch (e) {
      await this.audit.append({
        operation: 'dns.zone.create',
        parameters: { account_id: account.id, zone: name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.dnZone.create({
        data: {
          hosting_account_id: account.id,
          name,
          is_active: true,
          dnssec_enabled: false,
        },
        include: {
          hosting_account: { select: { username: true } },
          dns_records__zone_id: { where: { deleted_at: null }, select: { id: true } },
        },
      });
      if (shaped.length > 0) {
        await tx.dnRecord.createMany({
          data: shaped.map((r) => ({
            zone_id: created.id,
            name: r.name,
            type: r.type,
            content: r.wire,
            ttl: r.ttl,
            priority: r.priority,
            weight: r.weight,
            port: r.port,
          })),
        });
      }
      await this.audit.appendWithClient(tx, {
        operation: 'dns.zone.create',
        parameters: {
          account_id: account.id,
          zone: name,
          soa_seeded: agentResult.soa_seeded,
          record_count: shaped.length,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return created;
    });
    if (agentResult.soa_seeded) {
      this.logger.log(`zone ${name} created with a seeded SOA (ns1.${name}) — replace it if your NS plan differs`);
    }
    return {
      id: row.id,
      hosting_account_id: row.hosting_account_id,
      account_username: row.hosting_account?.username ?? account.username,
      name: row.name,
      is_active: row.is_active,
      dnssec_enabled: row.dnssec_enabled,
      record_count: shaped.length,
      created_at: row.created_at.toISOString(),
    };
  }

  async getZone(actor: Actor | undefined, id: string): Promise<DnsZoneDto> {
    const zone = await this.requireVisibleZone(id, actor);
    const count = await this.prisma.dnRecord.count({ where: { zone_id: zone.id, deleted_at: null } });
    return {
      id: zone.id,
      hosting_account_id: zone.hosting_account_id,
      account_username: zone.hosting_account?.username ?? '',
      name: zone.name,
      is_active: zone.is_active,
      dnssec_enabled: zone.dnssec_enabled,
      record_count: count,
      created_at: zone.created_at.toISOString(),
    };
  }

  async deleteZone(actor: Actor | undefined, id: string): Promise<void> {
    const zone = await this.requireVisibleZone(id, actor);
    try {
      await this.agent.dnsDeleteZone(zone.name);
    } catch (e) {
      await this.audit.append({
        operation: 'dns.zone.delete',
        parameters: { zone_id: zone.id, zone: zone.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: zone.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.dnZone.update({ where: { id: zone.id }, data: { deleted_at: new Date(), is_active: false } });
      await tx.dnRecord.updateMany({
        where: { zone_id: zone.id, deleted_at: null },
        data: { deleted_at: new Date(), is_active: false },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'dns.zone.delete',
        parameters: { zone_id: zone.id, zone: zone.name },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: zone.hosting_account_id,
      });
    });
  }

  // ---- records -------------------------------------------------------------------

  async listRecords(actor: Actor | undefined, zoneId: string): Promise<{ data: DnsRecordDto[] }> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    const rows = await this.prisma.dnRecord.findMany({
      where: { zone_id: zone.id, deleted_at: null },
      orderBy: [{ name: 'asc' }, { type: 'asc' }],
    });
    return { data: rows.map(recordToDto) };
  }

  async exportZone(actor: Actor | undefined, zoneId: string): Promise<{ zone: string; content: string }> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    return this.agent.dnsAXFRExport(zone.name);
  }

  /** Adds one record: full desired set = current mirror + this record. */
  async addRecord(
    actor: Actor | undefined,
    zoneId: string,
    input: DnsRecordInput,
  ): Promise<DnsRecordDto> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    const shaped = this.shapeRecord(zone.name, input);
    const current = await this.mirrorRows(zone.id);
    if (current.length >= MAX_ZONE_RECORDS) {
      throw new BadRequestException(`a zone carries at most ${MAX_ZONE_RECORDS} records`);
    }
    const dto = await this.applyDesired(actor, zone.id, zone.name, zone.hosting_account_id,
      [...current, shaped], 'dns.record.create',
      { record: `${shaped.name} ${shaped.type}` }, shaped);
    if (!dto) throw new NotFoundException('dns record not found after apply');
    return dto;
  }

  /** Replaces one record: full desired set = mirror with this row swapped. */
  async updateRecord(
    actor: Actor | undefined,
    zoneId: string,
    recordId: string,
    input: DnsRecordInput,
  ): Promise<DnsRecordDto> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    const existing = await this.requireRecordRow(zone.id, recordId);
    const shaped = this.shapeRecord(zone.name, input);
    const current = (await this.mirrorRows(zone.id)).map((r) =>
      r.id === existing.id ? shaped : r,
    );
    const dto = await this.applyDesired(actor, zone.id, zone.name, zone.hosting_account_id,
      current, 'dns.record.update',
      { record_id: existing.id, record: `${shaped.name} ${shaped.type}` }, shaped);
    if (!dto) throw new NotFoundException('dns record not found after apply');
    return dto;
  }

  /** Removes one record: full desired set = mirror without this row. */
  async deleteRecord(actor: Actor | undefined, zoneId: string, recordId: string): Promise<void> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    const existing = await this.requireRecordRow(zone.id, recordId);
    const current = (await this.mirrorRows(zone.id)).filter((r) => r.id !== existing.id);
    await this.applyDesired(actor, zone.id, zone.name, zone.hosting_account_id,
      current, 'dns.record.delete',
      { record_id: existing.id, record: `${existing.name} ${existing.type}` }, null);
  }

  private async mirrorRows(zoneId: string): Promise<Array<{
    id: string;
    name: string;
    type: string;
    content: string;
    ttl: number;
    priority: number | null;
    weight: number | null;
    port: number | null;
  }>> {
    const rows = await this.prisma.dnRecord.findMany({
      where: { zone_id: zoneId, deleted_at: null },
      orderBy: { created_at: 'asc' },
    });
    return rows.map((r) => ({
      id: r.id, name: r.name, type: r.type, content: r.content,
      ttl: r.ttl, priority: r.priority, weight: r.weight, port: r.port,
    }));
  }

  /**
   * One agent call for the whole desired set, then a transactional mirror
   * replace + audit. `focus` (when given) is the row the caller cares about.
   */
  private async applyDesired(
    actor: Actor | undefined,
    zoneId: string,
    zoneName: string,
    hostingAccountId: string,
    desired: Array<{ name: string; type: string; content: string; ttl: number; priority: number | null; weight: number | null; port: number | null; wire?: string }>,
    operation: string,
    extra: Record<string, unknown>,
    focus: { name: string; type: string; content: string; wire?: string; priority: number | null; weight: number | null; port: number | null } | null,
  ): Promise<DnsRecordDto | null> {
    try {
      await this.agent.dnsApplyRecords(zoneName, desired);
    } catch (e) {
      await this.audit.append({
        operation,
        parameters: { zone_id: zoneId, zone: zoneName, ...extra, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.dnRecord.updateMany({
        where: { zone_id: zoneId, deleted_at: null },
        data: { deleted_at: new Date() },
      });
      if (desired.length > 0) {
        await tx.dnRecord.createMany({
          data: desired.map((r) => ({
            zone_id: zoneId,
            name: r.name,
            type: r.type,
            content: r.wire ?? r.content,
            ttl: r.ttl,
            priority: r.priority,
            weight: r.weight,
            port: r.port,
          })),
        });
      }
      await this.audit.appendWithClient(tx, {
        operation,
        parameters: { zone_id: zoneId, zone: zoneName, ...extra, desired_count: desired.length },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId,
      });
    });
    if (focus) {
      const row = await this.prisma.dnRecord.findFirst({
        where: {
          zone_id: zoneId, deleted_at: null,
          name: focus.name, type: focus.type, content: focus.wire ?? focus.content,
        },
      });
      if (!row) throw new NotFoundException('dns record not found after apply');
      return recordToDto(row);
    }
    // Deletion flow: nothing to focus — the caller only needs 204.
    return null;
  }

  private async requireRecordRow(zoneId: string, recordId: string) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(recordId)) {
      throw new NotFoundException('dns record not found');
    }
    const row = await this.prisma.dnRecord.findFirst({
      where: { id: recordId, zone_id: zoneId, deleted_at: null },
    });
    if (!row) throw new NotFoundException('dns record not found');
    return row;
  }

  // ---- DNSSEC ------------------------------------------------------------------

  async getDnssec(actor: Actor | undefined, zoneId: string): Promise<{
    zone: string;
    enabled: boolean;
    ds: string[];
    dnskey: string[];
    keys: Array<{ key_type: string; key_id: string; detail: string }>;
  }> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    return this.agent.dnsGetDnssec(zone.name);
  }

  async enableDnssec(actor: Actor | undefined, zoneId: string): Promise<{
    status: string;
    zone: string;
    ds: string[];
    dnskey: string[];
  }> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    try {
      const res = await this.agent.dnsEnableDnssec(zone.name);
      await this.prisma.dnZone.update({ where: { id: zone.id }, data: { dnssec_enabled: true } });
      await this.audit.append({
        operation: 'dns.dnssec.enable',
        parameters: { zone_id: zone.id, zone: zone.name, ds_count: res.ds.length, key_count: res.keys.length },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: zone.hosting_account_id,
      });
      return res;
    } catch (e) {
      await this.audit.append({
        operation: 'dns.dnssec.enable',
        parameters: { zone_id: zone.id, zone: zone.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: zone.hosting_account_id,
      });
      throw e;
    }
  }

  async disableDnssec(actor: Actor | undefined, zoneId: string): Promise<void> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    try {
      await this.agent.dnsDisableDnssec(zone.name);
      await this.prisma.dnZone.update({ where: { id: zone.id }, data: { dnssec_enabled: false } });
      await this.audit.append({
        operation: 'dns.dnssec.disable',
        parameters: { zone_id: zone.id, zone: zone.name },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: zone.hosting_account_id,
      });
    } catch (e) {
      await this.audit.append({
        operation: 'dns.dnssec.disable',
        parameters: { zone_id: zone.id, zone: zone.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: zone.hosting_account_id,
      });
      throw e;
    }
  }

  // ---- checks -------------------------------------------------------------------

  /** Live zone check on the node (pdnsutil check-zone, verbatim findings). */
  async zoneCheck(actor: Actor | undefined, zoneId: string): Promise<{ zone: string; ok: boolean; issues: string[] }> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    return this.agent.dnsZoneCheck(zone.name);
  }

  /**
   * Propagation check (API spec §4.9) — runs in the CONTROL PLANE by design
   * (ADR-0012): querying public resolvers is not a privileged node operation,
   * and keeping it out of the agent allowlist preserves the minimal-execution
   * posture. For each A/AAAA/TXT/CNAME record in the mirror we ask each
   * configured resolver and compare with the expected value. Honest scope:
   * public resolver answers only; missing/timeout are reported per resolver,
   * never silently ignored.
   */
  async checkPropagation(
    actor: Actor | undefined,
    zoneId: string,
    resolversInput?: unknown,
  ): Promise<{
    zone: string;
    resolvers: string[];
    checked: number;
    consistent: boolean;
    results: Array<{ name: string; type: string; resolver: string; state: 'match' | 'mismatch' | 'missing' | 'timeout'; answer?: string }>;
  }> {
    const zone = await this.requireVisibleZone(zoneId, actor);
    const resolvers = Array.isArray(resolversInput) && resolversInput.length > 0
      ? resolversInput.slice(0, 5).map((r) => String(r))
      : ['1.1.1.1', '8.8.8.8'];
    for (const r of resolvers) {
      if (!IPV4_RE.test(r)) {
        throw new BadRequestException(`resolver "${r}" must be an IPv4 address`);
      }
    }
    const records = await this.prisma.dnRecord.findMany({
      where: { zone_id: zone.id, deleted_at: null, type: { in: ['A', 'AAAA', 'TXT', 'CNAME'] } },
      orderBy: [{ name: 'asc' }, { type: 'asc' }],
      take: 50,
    });

    const results: Array<{ name: string; type: string; resolver: string; state: 'match' | 'mismatch' | 'missing' | 'timeout'; answer?: string }> = [];
    for (const record of records) {
      for (const resolver of resolvers) {
        const answer = await resolveOnce(resolver, record.name, record.type, record.content);
        results.push({
          name: record.name, type: record.type, resolver,
          state: answer.state,
          ...(answer.answer !== undefined ? { answer: answer.answer } : {}),
        });
      }
    }
    const consistent = results.length > 0 && results.every((r) => r.state === 'match');
    await this.audit.append({
      operation: 'dns.propagation_check',
      parameters: { zone_id: zone.id, zone: zone.name, resolvers, checked: records.length, consistent },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: zone.hosting_account_id,
    });
    return { zone: zone.name, resolvers, checked: records.length, consistent, results };
  }
}

function recordToDto(r: {
  id: string;
  zone_id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  priority: number | null;
  weight: number | null;
  port: number | null;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
}): DnsRecordDto {
  return {
    id: r.id,
    zone_id: r.zone_id,
    name: r.name,
    type: r.type,
    content: r.content,
    ttl: r.ttl,
    priority: r.priority,
    weight: r.weight,
    port: r.port,
    is_active: r.is_active,
    created_at: r.created_at.toISOString(),
    updated_at: r.updated_at.toISOString(),
  };
}

type ResolveState = 'match' | 'mismatch' | 'missing' | 'timeout';

/** One DNS question via the stdlib resolver pinned to one server. */
async function resolveOnce(
  resolver: string,
  name: string,
  type: string,
  expected: string,
): Promise<{ state: ResolveState; answer?: string }> {
  const r = new dns.promises.Resolver({ timeout: 2000, tries: 1 });
  r.setServers([resolver]);
  try {
    switch (type) {
      case 'A': {
        const answers = await r.resolve4(name);
        return compare(answers, expected.replace(/\.$/, ''));
      }
      case 'AAAA': {
        const answers = await r.resolve6(name);
        const want = expected.toLowerCase();
        return compare(answers.map((a) => a.toLowerCase()), want);
      }
      case 'TXT': {
        const answers = await r.resolveTxt(name);
        const flat = answers.map((chunks) => chunks.join(''));
        // Expected may be quoted ("text") or not; compare both ways.
        const want = expected.replace(/^"(.*)"$/, '$1');
        return flat.includes(want)
          ? { state: 'match', answer: flat[0]!.slice(0, 200) }
          : { state: 'mismatch', answer: (flat[0] ?? '').slice(0, 200) };
      }
      case 'CNAME': {
        const answers = await r.resolveCname(name);
        return compare(answers.map((a) => a.replace(/\.$/, '')), expected.replace(/\.$/, ''));
      }
      default:
        return { state: 'missing' };
    }
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOTFOUND' || code === 'ENODATA') return { state: 'missing' };
    return { state: 'timeout' };
  }
}

function compare(answers: string[], want: string): { state: ResolveState; answer?: string } {
  if (answers.length === 0) return { state: 'missing' };
  if (answers.includes(want)) return { state: 'match', answer: answers[0] };
  return { state: 'mismatch', answer: answers[0] };
}
