import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { generateKeyPairSync } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { DnsService } from '../dns/dns.service';
import { Actor } from '../sites/sites.service';
import { getSecretBox } from '../common/secretbox';
/**
 * Deliverability & relay (API spec §4.8, ADR-0014) — B08.
 *
 *   - DKIM: the CP mints RSA-2048, hands the private PEM to the agent over
 *     the signed socket (stored 0600, never persisted in the panel DB), and
 *     writes the `<selector>._domainkey` TXT through the DnsService module
 *     call — one code path for wizard and API, PowerDNS stays the only DNS
 *     writer. No managed DNS zone → 409 with the record to add manually.
 *   - SPF/DMARC: upserts through the same DNS path with explicit conflict
 *     rules (an existing v=spf1 / v=DMARC1 record is replaced, since every
 *     record in a managed zone is panel-registry state).
 *   - Relay: server-wide profile in system_settings['mail.relay']
 *     (ADR-0002 stands; per-account override is v1.2). Credentials are
 *     SecretBox-encrypted (ADR-0009) and never returned by GET.
 *   - Queue: postqueue/postsuper through the agent, server-wide scope.
 */

const RELAY_SETTING_KEY = 'mail.relay';
const RELAY_PROVIDERS = new Set(['ses', 'mailgun', 'postmark', 'custom']);
const DMARC_POLICIES = new Set(['none', 'quarantine', 'reject']);
const SPF_RE = /^v=spf1[ a-z0-9:\/.~\-]*$/i;

export interface DkimStateDto {
  mail_domain_id: string;
  domain: string;
  selector: string | null;
  rotated_at: string | null;
  created_at: string | null;
  dns_record_present: boolean;
  signing: boolean;
  signing_note: string | null;
}

export interface RelayDto {
  provider: string;
  smtp_host: string;
  smtp_port: number;
  username: string;
  has_credentials: boolean;
  is_active: boolean;
  updated_at: string;
}

@Injectable()
export class MailDeliverabilityService {
  private readonly logger = new Logger(MailDeliverabilityService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    private readonly dns: DnsService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  // ---- shared ----------------------------------------------------------------

  private async requireVisibleMailDomain(id: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('mail domain not found');
    }
    const domain = await this.prisma.mailDomain.findFirst({
      where: { id, deleted_at: null },
      include: { hosting_account: { select: { id: true, username: true } } },
    });
    if (!domain) throw new NotFoundException('mail domain not found');
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) throw new NotFoundException('mail domain not found');
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: domain.hosting_account_id, revoked_at: null },
        select: { id: true },
      });
      if (!access) throw new NotFoundException('mail domain not found');
    }
    return domain;
  }

  /** The managed DNS zone for a mail domain, or null (honest 409 path). */
  private async findManagedZone(domainName: string): Promise<{ id: string; name: string } | null> {
    return this.prisma.dnZone.findFirst({
      where: { name: domainName, deleted_at: null },
      select: { id: true, name: true },
    });
  }

  // ---- DKIM --------------------------------------------------------------------

  async getDkim(actor: Actor | undefined, domainId: string): Promise<DkimStateDto> {
    const domain = await this.requireVisibleMailDomain(domainId, actor);
    const row = await this.prisma.mailDomainDkim.findUnique({ where: { mail_domain_id: domain.id } });
    if (!row) {
      return {
        mail_domain_id: domain.id,
        domain: domain.name,
        selector: null,
        rotated_at: null,
        created_at: null,
        dns_record_present: false,
        signing: false,
        signing_note: null,
      };
    }
    const recordName = `${row.selector}._domainkey.${domain.name}`;
    const zone = await this.findManagedZone(domain.name);
    let recordPresent = false;
    if (zone) {
      const records = await this.prisma.dnRecord.findFirst({
        where: { zone_id: zone.id, name: recordName, type: 'TXT', deleted_at: null },
        select: { id: true },
      });
      recordPresent = !!records;
    }
    return {
      mail_domain_id: domain.id,
      domain: domain.name,
      selector: row.selector,
      rotated_at: row.rotated_at ? row.rotated_at.toISOString() : null,
      created_at: row.created_at.toISOString(),
      dns_record_present: recordPresent,
      signing: recordPresent,
      signing_note: recordPresent
        ? null
        : zone
          ? 'DKIM key is stored on the node but the DNS TXT record is missing from the managed zone — re-enable to rewrite it'
          : 'DKIM key is stored on the node; this domain has no managed DNS zone, so the TXT record must exist at your DNS host',
    };
  }

  async enableDkim(
    actor: Actor | undefined,
    domainId: string,
    input: { selector?: unknown },
  ): Promise<DkimStateDto & { dns_record: string }> {
    const domain = await this.requireVisibleMailDomain(domainId, actor);
    const existing = await this.prisma.mailDomainDkim.findUnique({ where: { mail_domain_id: domain.id } });
    if (existing) {
      throw new ConflictException(
        `DKIM is already enabled for ${domain.name} (selector ${existing.selector}) — use rotate for a new key`,
      );
    }
    return this.mintAndApply(actor, domain, typeof input.selector === 'string' ? input.selector.trim() : '', 'mail.dkim.enable', null);
  }

  async rotateDkim(
    actor: Actor | undefined,
    domainId: string,
    input: { selector?: unknown },
  ): Promise<DkimStateDto & { dns_record: string }> {
    const domain = await this.requireVisibleMailDomain(domainId, actor);
    const existing = await this.prisma.mailDomainDkim.findUnique({ where: { mail_domain_id: domain.id } });
    if (!existing) {
      throw new NotFoundException('DKIM is not enabled on this domain yet');
    }
    return this.mintAndApply(actor, domain, typeof input.selector === 'string' ? input.selector.trim() : '', 'mail.dkim.rotate', existing.selector);
  }

  private async mintAndApply(
    actor: Actor | undefined,
    domain: { id: string; name: string; hosting_account_id: string },
    rawSelector: string,
    operation: string,
    previousSelector: string | null,
  ): Promise<DkimStateDto & { dns_record: string }> {
    const selector = rawSelector || defaultSelector();
    if (!/^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/.test(selector)) {
      throw new BadRequestException('selector must be 2-64 chars: lowercase letters, digits, dash');
    }
    const zone = await this.findManagedZone(domain.name);
    if (!zone) {
      throw new ConflictException(
        `${domain.name} has no managed DNS zone in the panel — create it under DNS first, or publish this TXT at your DNS host manually`,
      );
    }

    // Mint + apply: private key exists in process memory only until the
    // agent stores it; nothing credential-bearing is written to the panel
    // DB or the audit chain.
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const privateKeyPem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
    const dnsTxt = `v=DKIM1; k=rsa; p=${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`;

    let agentResult: Awaited<ReturnType<AgentClientService['mailApplyDkim']>>;
    try {
      agentResult = await this.agent.mailApplyDkim(domain.name, selector, privateKeyPem);
    } catch (e) {
      await this.audit.append({
        operation,
        parameters: { mail_domain_id: domain.id, domain: domain.name, selector, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
    if (agentResult.opendkim.applied === false && agentResult.opendkim.skipped) {
      this.logger.warn(`DKIM ${domain.name}/${selector}: ${agentResult.opendkim.skipped}`);
    }

    // DNS record through the module path (B06): one writer, one audit chain.
    await this.dns.addRecord(actor, zone.id, { name: `${selector}._domainkey`, type: 'TXT', content: dnsTxt, ttl: 3600 });

    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await tx.mailDomainDkim.upsert({
        where: { mail_domain_id: domain.id },
        create: { mail_domain_id: domain.id, selector },
        update: { selector, rotated_at: previousSelector ? now : null },
      });
      await this.audit.appendWithClient(tx, {
        operation,
        parameters: {
          mail_domain_id: domain.id,
          domain: domain.name,
          selector,
          previous_selector: previousSelector,
          key_fingerprint: agentResult.key_fingerprint,
          opendkim_applied: agentResult.opendkim.applied,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });

    if (previousSelector) {
      this.logger.log(
        `DKIM rotated for ${domain.name}: ${previousSelector} → ${selector}. The old TXT stays published until you remove it — in-flight verifiers may still check it.`,
      );
    }
    return {
      mail_domain_id: domain.id,
      domain: domain.name,
      selector,
      rotated_at: previousSelector ? now.toISOString() : null,
      created_at: now.toISOString(),
      dns_record_present: true,
      signing: agentResult.opendkim.applied,
      signing_note: agentResult.opendkim.applied
        ? null
        : `opendkim not wired on the node: ${agentResult.opendkim.skipped ?? 'unknown reason'} — key stored, DNS published, signing not active yet`,
      dns_record: `${selector}._domainkey.${domain.name} TXT "${dnsTxt}"`,
    };
  }

  // ---- SPF / DMARC ---------------------------------------------------------------

  async applySpf(
    actor: Actor | undefined,
    domainId: string,
    input: { record?: unknown },
  ): Promise<{ domain: string; record: string }> {
    const domain = await this.requireVisibleMailDomain(domainId, actor);
    const zone = await this.findManagedZone(domain.name);
    if (!zone) {
      throw new ConflictException(`${domain.name} has no managed DNS zone in the panel — publish the SPF TXT at your DNS host`);
    }
    const record = typeof input.record === 'string' && input.record.trim() !== '' ? input.record.trim() : 'v=spf1 mx a ~all';
    if (!SPF_RE.test(record)) {
      throw new BadRequestException('record must look like "v=spf1 ..." (mechanisms a, mx, ip4:, include:, ~all)');
    }
    const existing = await this.findTxtRecord(zone.id, domain.name, domain.name);
    await this.upsertTxt(actor, zone.id, domain.name, record, existing, 'mail.spf.apply', domain.hosting_account_id, 'SPF');
    await this.audit.append({
      operation: 'mail.spf.apply',
      parameters: { mail_domain_id: domain.id, domain: domain.name, record },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: domain.hosting_account_id,
    });
    return { domain: domain.name, record };
  }

  async applyDmarc(
    actor: Actor | undefined,
    domainId: string,
    input: { policy?: unknown; rua?: unknown },
  ): Promise<{ domain: string; record: string }> {
    const domain = await this.requireVisibleMailDomain(domainId, actor);
    const zone = await this.findManagedZone(domain.name);
    if (!zone) {
      throw new ConflictException(`${domain.name} has no managed DNS zone in the panel — publish the DMARC TXT at your DNS host`);
    }
    const policy = typeof input.policy === 'string' ? input.policy.toLowerCase() : 'quarantine';
    if (!DMARC_POLICIES.has(policy)) {
      throw new BadRequestException('policy must be none | quarantine | reject');
    }
    const rua = typeof input.rua === 'string' && input.rua.trim() !== '' ? input.rua.trim() : null;
    if (rua && !/^[^@\s]+@[^@\s]+$/.test(rua)) {
      throw new BadRequestException('rua must be an email address');
    }
    const record = `v=DMARC1; p=${policy}${rua ? `; rua=mailto:${rua}` : ''}`;
    const name = `_dmarc.${domain.name}`;
    const existing = await this.findTxtRecord(zone.id, name, domain.name);
    await this.upsertTxt(actor, zone.id, name, record, existing, 'mail.dmarc.apply', domain.hosting_account_id, 'DMARC');
    await this.audit.append({
      operation: 'mail.dmarc.apply',
      parameters: { mail_domain_id: domain.id, domain: domain.name, policy, rua },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: domain.hosting_account_id,
    });
    return { domain: domain.name, record };
  }

  private async findTxtRecord(zoneId: string, name: string, _zoneName: string) {
    return this.prisma.dnRecord.findFirst({
      where: { zone_id: zoneId, name, type: 'TXT', deleted_at: null },
      select: { id: true, content: true },
    });
  }

  private async upsertTxt(
    actor: Actor | undefined,
    zoneId: string,
    name: string,
    record: string,
    existing: { id: string; content: string } | null,
    operation: string,
    hostingAccountId: string,
    label: string,
  ): Promise<void> {
    if (existing && existing.content === record) {
      return; // idempotent: desired state already met
    }
    if (existing) {
      await this.dns.updateRecord(actor, zoneId, existing.id, { name, type: 'TXT', content: record, ttl: 3600 });
    } else {
      await this.dns.addRecord(actor, zoneId, { name, type: 'TXT', content: record, ttl: 3600 });
    }
    this.logger.log(`${label} record ${operation === 'mail.spf.apply' ? 'at apex' : name} ${existing ? 'replaced' : 'published'} in zone ${zoneId}`);
  }

  // ---- relay (server-wide, ADR-0002) ------------------------------------------------

  async getRelay(): Promise<RelayDto> {
    const row = await this.prisma.systemSetting.findUnique({ where: { key: RELAY_SETTING_KEY } });
    if (!row) {
      return {
        provider: 'none',
        smtp_host: '',
        smtp_port: 587,
        username: '',
        has_credentials: false,
        is_active: false,
        updated_at: new Date(0).toISOString(),
      };
    }
    const value = row.value as Record<string, unknown>;
    return {
      provider: String(value['provider'] ?? 'custom'),
      smtp_host: String(value['smtp_host'] ?? ''),
      smtp_port: Number(value['smtp_port'] ?? 587),
      username: String(value['username'] ?? ''),
      has_credentials: typeof value['credentials_enc'] === 'string',
      is_active: value['is_active'] === true,
      updated_at: row.updated_at.toISOString(),
    };
  }

  async putRelay(
    actor: Actor | undefined,
    input: { provider?: unknown; smtp_host?: unknown; smtp_port?: unknown; username?: unknown; password?: unknown },
  ): Promise<RelayDto> {
    const provider = typeof input.provider === 'string' ? input.provider.toLowerCase() : '';
    if (!RELAY_PROVIDERS.has(provider)) {
      throw new BadRequestException('provider must be ses | mailgun | postmark | custom');
    }
    const host = typeof input.smtp_host === 'string' ? input.smtp_host.trim() : '';
    if (!/^[a-z0-9.-]{1,253}$/i.test(host)) {
      throw new BadRequestException('smtp_host must be a hostname');
    }
    const port = Number(input.smtp_port ?? 587);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new BadRequestException('smtp_port must be 1-65535');
    }
    const username = typeof input.username === 'string' ? input.username.trim() : '';
    const password = typeof input.password === 'string' ? input.password : '';
    if (password.length > 4096) {
      throw new BadRequestException('password too long');
    }
    const previous = await this.prisma.systemSetting.findUnique({ where: { key: RELAY_SETTING_KEY } });
    const previousValue = (previous?.value ?? {}) as Record<string, unknown>;
    // A blank password keeps the stored credentials (rotation-friendly).
    const credentialsEnc =
      password === ''
        ? typeof previousValue['credentials_enc'] === 'string'
          ? previousValue['credentials_enc']
          : null
        : getSecretBox().encrypt(JSON.stringify({ username, password }));

    const value = {
      provider,
      smtp_host: host,
      smtp_port: port,
      username,
      credentials_enc: credentialsEnc,
      is_active: true,
    };
    await this.prisma.systemSetting.upsert({
      where: { key: RELAY_SETTING_KEY },
      create: { key: RELAY_SETTING_KEY, value: value as object },
      update: { value: value as object },
    });
    await this.audit.append({
      operation: 'mail.relay.configure',
      parameters: {
        provider,
        smtp_host: host,
        smtp_port: port,
        credentials_stored: credentialsEnc !== null,
        transport_wiring: 'stored — postfix transport wiring lands with the config-engine pipeline',
      },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: null,
    });
    this.logger.warn('relay profile stored — node transport wiring is NOT applied yet (honest, ADR-0014)');
    return this.getRelay();
  }

  async deleteRelay(actor: Actor | undefined): Promise<void> {
    const existing = await this.prisma.systemSetting.findUnique({ where: { key: RELAY_SETTING_KEY } });
    if (existing) {
      await this.prisma.systemSetting.delete({ where: { key: RELAY_SETTING_KEY } });
    }
    await this.audit.append({
      operation: 'mail.relay.remove',
      parameters: { existed: !!existing },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: null,
    });
  }

  // ---- queue (server-wide) ----------------------------------------------------------

  async queueList() {
    try {
      return await this.agent.mailQueueList();
    } catch (e) {
      await this.audit.append({
        operation: 'mail.queue.list',
        parameters: { error: (e as Error).message },
        outcome: 'failure',
        actorUserId: null,
        hostingAccountId: null,
      });
      throw e;
    }
  }

  async queueFlush(actor: Actor | undefined, queueId?: string) {
    try {
      const res = await this.agent.mailQueueFlush(queueId);
      await this.audit.append({
        operation: 'mail.queue.flush',
        parameters: { queue_id: queueId ?? null },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: null,
      });
      return res;
    } catch (e) {
      await this.audit.append({
        operation: 'mail.queue.flush',
        parameters: { queue_id: queueId ?? null, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: null,
      });
      throw e;
    }
  }

  async queueRetry(actor: Actor | undefined, messageId: string) {
    try {
      const res = await this.agent.mailQueueRetry(messageId);
      await this.audit.append({
        operation: 'mail.queue.retry',
        parameters: { message_id: messageId },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: null,
      });
      return res;
    } catch (e) {
      await this.audit.append({
        operation: 'mail.queue.retry',
        parameters: { message_id: messageId, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: null,
      });
      throw e;
    }
  }
}

function defaultSelector(): string {
  return `s${Math.floor(Date.now() / 1000)}`;
}
