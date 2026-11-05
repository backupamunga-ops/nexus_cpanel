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
import { getSecretBox } from '../common/secretbox';
import { Actor } from '../sites/sites.service';

/**
 * SSL certificates (API spec §4.7 ssl composite + §4.14 cross-domain list).
 *
 * Storage contract (ADR-0009): the node keeps the serving copy under the
 * agent's CertRoot; the database keeps an ENCRYPTED copy (cert_pem_enc /
 * key_pem_enc via SecretBox) for metadata, renewals and migration. API
 * responses carry metadata only — private key material never leaves the
 * box once stored, and never appears in a list response at all.
 *
 * ACME issuance is agent-executed http-01 with the challenge served from
 * the site's own docroot (ADR-0009); dns-01 is a documented precondition
 * until the DNS write path exists. Manual installs go through
 * POST /ssl/certificates with the pair validated on the node.
 */

export interface SslCertDto {
  id: string;
  domain_id: string;
  domain_name: string;
  issuer: string;
  common_name: string;
  san_names: string[];
  expires_at: string;
  last_renewed_at: string | null;
  auto_renew: boolean;
  created_at: string;
}

@Injectable()
export class SslService {
  private readonly logger = new Logger(SslService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  private async requireVisibleDomain(id: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('domain not found');
    }
    const row = await this.prisma.domain.findFirst({
      where: { id, deleted_at: null },
    });
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

  /** GET /domains/{id}/ssl — metadata only; null when no cert is installed. */
  async getForDomain(domainId: string, actor?: Actor): Promise<{ certificate: SslCertDto | null }> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const row = await this.prisma.certificate.findFirst({
      where: { domain_id: domain.id },
      orderBy: { created_at: 'desc' },
    });
    if (!row) {
      return { certificate: null };
    }
    return { certificate: toDto(row, domain.name) };
  }

  /**
   * POST /domains/{id}/ssl/issue — ACME http-01 issuance via the agent.
   * The webroot is the site's document root; challenge tokens are served
   * by the running webserver from there.
   */
  async issue(domainId: string, input: { email?: unknown }, actor?: Actor): Promise<SslCertDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: domain.hosting_account_id },
      select: { username: true },
    });
    if (!account) {
      throw new NotFoundException('hosting account not found');
    }
    const email = typeof input.email === 'string' ? input.email.trim() : '';
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      throw new BadRequestException('a valid email is required for ACME registration');
    }

    const existing = await this.prisma.certificate.findFirst({
      where: { domain_id: domain.id },
      select: { id: true },
    });
    if (existing) {
      throw new ConflictException('a certificate already exists for this domain (renew or revoke first)');
    }

    try {
      const res = await this.agent.sslIssueAcme(domain.name, email, domain.document_root);
      const box = getSecretBox();
      const row = await this.prisma.$transaction(async (tx) => {
        const created = await tx.certificate.create({
          data: {
            domain_id: domain.id,
            issuer: res.issuer || 'letsencrypt',
            common_name: domain.name,
            san_names: res.san_names ?? [domain.name],
            cert_pem_enc: Buffer.from(box.encrypt(res.cert_pem), 'utf8'),
            key_pem_enc: Buffer.from(box.encrypt(res.key_pem), 'utf8'),
            issued_at: new Date(),
            expires_at: new Date(res.expires_at),
            auto_renew: true,
          },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'ssl.issue',
          parameters: {
            domain_id: domain.id,
            domain: domain.name,
            issuer: res.issuer,
            expires_at: res.expires_at,
          },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: domain.hosting_account_id,
        });
        return created;
      });
      this.logger.log(`issued ACME certificate for ${domain.name} (expires ${res.expires_at})`);
      return toDto(row, domain.name);
    } catch (e) {
      await this.audit.append({
        operation: 'ssl.issue',
        parameters: { domain_id: domain.id, domain: domain.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
  }

  /**
   * POST /domains/{id}/ssl/renew — ACME certs re-issue; manual certs must
   * be re-installed with the new pair (the CA of record is not ours).
   */
  async renew(domainId: string, actor?: Actor): Promise<SslCertDto> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const row = await this.prisma.certificate.findFirst({
      where: { domain_id: domain.id },
      orderBy: { created_at: 'desc' },
    });
    if (!row) {
      throw new NotFoundException('no certificate to renew for this domain');
    }
    if (row.issuer === 'manual') {
      throw new BadRequestException(
        'manual certificates are renewed by installing the new pair (POST /ssl/certificates)',
      );
    }

    const box = getSecretBox();
    const emailRow = await this.prisma.user.findFirst({
      where: { id: actor?.userId ?? '' },
      select: { email: true },
    });
    const email = emailRow?.email ?? `admin@${domain.name}`;
    try {
      const res = await this.agent.sslIssueAcme(domain.name, email, domain.document_root);
      const updated = await this.prisma.$transaction(async (tx) => {
        const u = await tx.certificate.update({
          where: { id: row.id },
          data: {
            cert_pem_enc: Buffer.from(box.encrypt(res.cert_pem), 'utf8'),
            key_pem_enc: Buffer.from(box.encrypt(res.key_pem), 'utf8'),
            issued_at: new Date(),
            expires_at: new Date(res.expires_at),
            last_renewed_at: new Date(),
          },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'ssl.renew',
          parameters: { domain_id: domain.id, domain: domain.name, expires_at: res.expires_at },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: domain.hosting_account_id,
        });
        return u;
      });
      return toDto(updated, domain.name);
    } catch (e) {
      await this.audit.append({
        operation: 'ssl.renew',
        parameters: { domain_id: domain.id, domain: domain.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
  }

  /** DELETE /domains/{id}/ssl — revokes on the node, removes the row. */
  async revoke(domainId: string, actor?: Actor): Promise<void> {
    const domain = await this.requireVisibleDomain(domainId, actor);
    const row = await this.prisma.certificate.findFirst({
      where: { domain_id: domain.id },
      select: { id: true },
    });
    if (!row) {
      throw new NotFoundException('no certificate for this domain');
    }
    await this.agent.sslRevoke(domain.name);
    await this.prisma.$transaction(async (tx) => {
      await tx.certificate.delete({ where: { id: row.id } });
      await this.audit.appendWithClient(tx, {
        operation: 'ssl.revoke',
        parameters: { domain_id: domain.id, domain: domain.name },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
    });
  }

  /** POST /ssl/certificates — manual install of a provided pair. */
  async installManual(
    input: { domain_id?: unknown; cert_pem?: unknown; key_pem?: unknown },
    actor?: Actor,
  ): Promise<SslCertDto> {
    const domainId = typeof input.domain_id === 'string' ? input.domain_id : '';
    const domain = await this.requireVisibleDomain(domainId, actor);
    if (typeof input.cert_pem !== 'string' || !input.cert_pem.includes('BEGIN CERTIFICATE')) {
      throw new BadRequestException('cert_pem must be a PEM certificate');
    }
    if (typeof input.key_pem !== 'string' || !input.key_pem.includes('PRIVATE KEY')) {
      throw new BadRequestException('key_pem must be a PEM private key');
    }
    const existing = await this.prisma.certificate.findFirst({
      where: { domain_id: domain.id },
      select: { id: true },
    });
    if (existing) {
      throw new ConflictException('a certificate already exists for this domain (revoke first)');
    }

    try {
      const res = await this.agent.sslInstallCert(domain.name, input.cert_pem, input.key_pem);
      const box = getSecretBox();
      const row = await this.prisma.$transaction(async (tx) => {
        const created = await tx.certificate.create({
          data: {
            domain_id: domain.id,
            issuer: 'manual',
            common_name: res.common_name || domain.name,
            san_names: res.san_names ?? [domain.name],
            cert_pem_enc: Buffer.from(box.encrypt(input.cert_pem as string), 'utf8'),
            key_pem_enc: Buffer.from(box.encrypt(input.key_pem as string), 'utf8'),
            issued_at: new Date(),
            expires_at: new Date(res.expires_at),
            auto_renew: false,
          },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'ssl.install',
          parameters: { domain_id: domain.id, domain: domain.name, expires_at: res.expires_at },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
          hostingAccountId: domain.hosting_account_id,
        });
        return created;
      });
      return toDto(row, domain.name);
    } catch (e) {
      await this.audit.append({
        operation: 'ssl.install',
        parameters: { domain_id: domain.id, domain: domain.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: domain.hosting_account_id,
      });
      throw e;
    }
  }

  /** GET /ssl/certificates — cross-domain list, visibility-scoped. */
  async list(actor?: Actor): Promise<{ data: SslCertDto[] }> {
    const rows = await this.prisma.certificate.findMany({
      orderBy: { created_at: 'desc' },
      take: 500,
      include: { domain: { select: { name: true, hosting_account_id: true, deleted_at: true } } },
    });
    const visible: SslCertDto[] = [];
    for (const row of rows) {
      if (row.domain.deleted_at) {
        continue;
      }
      if (!actor?.isSuperAdmin) {
        if (!actor?.userId) {
          continue;
        }
        const access = await this.prisma.userHostingAccountAccess.findFirst({
          where: {
            user_id: actor.userId,
            hosting_account_id: row.domain.hosting_account_id,
            revoked_at: null,
          },
          select: { id: true },
        });
        if (!access) {
          continue;
        }
      }
      visible.push(toDto(row, row.domain.name));
    }
    return { data: visible };
  }
}

type CertRow = {
  id: string;
  domain_id: string;
  issuer: string;
  common_name: string;
  san_names: string[];
  expires_at: Date;
  last_renewed_at: Date | null;
  auto_renew: boolean;
  created_at: Date;
};

function toDto(row: CertRow, domainName: string): SslCertDto {
  return {
    id: row.id,
    domain_id: row.domain_id,
    domain_name: domainName,
    issuer: row.issuer,
    common_name: row.common_name,
    san_names: row.san_names ?? [],
    expires_at: row.expires_at.toISOString(),
    last_renewed_at: row.last_renewed_at ? row.last_renewed_at.toISOString() : null,
    auto_renew: row.auto_renew,
    created_at: row.created_at.toISOString(),
  };
}
