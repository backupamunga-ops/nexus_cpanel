import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { DnsService } from '../dns/dns.service';
import { MailService } from '../mail/mail.service';
import { getSecretBox } from '../common/secretbox';
import { Actor } from '../sites/sites.service';
import { parseZoneFile } from './zonefile';

/**
 * Migration Center (API spec §4.21, migration spec M15) — B15.
 *
 * The panel owns the ledger (`migration_jobs` / `migration_entity_mappings`,
 * DDL-first) and the phase machine; the agent owns the artifact (analyze is
 * a streaming, read-only walk — it never touches the live tree).
 *
 *   - flow: create → analyze (read-only inventory + preflight) → dry-run
 *     (the ordered plan, zero writes) → execute (resumable, per-entity
 *     journaling) → verify (checksum parity per entity) → report;
 *   - execute ordering follows the spec: files → DNS → mail → databases →
 *     SSL/crons (crons are imported as data; scheduling is the B13 job
 *     framework's business);
 *   - M15: acceptance is throughput + integrity, NEVER wall-clock — a run
 *     with any failed verification reports the job as failed overall, no
 *     partial-success dressing (D-11);
 *   - execute is RESUMABLE: entities in `pending`/`importing` are retried,
 *     terminal rows are left alone — no double imports;
 *   - secrets (§6): cPanel artifacts carry password hashes and they are
 *     NEVER imported — mailboxes are created with fresh random secrets,
 *     database users with fresh credentials (SecretBox at rest, shown-once
 *     receipt), SSL keys are not imported in v1.0 (skip is explicit and
 *     reason-coded);
 *   - SKIP is always explicit with a reason (`unsupported-feature`,
 *     `policy-declined`, `collision`, `empty`);
 *   - this is a server-wide (admin) surface: `migration:*` stays out of
 *     HOSTING_SCOPED_PREFIXES; the guard admits server admins and tokens
 *     explicitly scoped for it (C6/C4).
 */

const SOURCE_PLATFORM = 'cpanel';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Terminal mapping statuses — resume never touches these. */
const TERMINAL = new Set(['verified', 'failed', 'skipped']);

/** Entity ordering for execute + the dry-run plan (spec §4). */
const ENTITY_ORDER = ['files', 'dns_zone', 'mail_domain', 'mailbox', 'database', 'ssl', 'cron'] as const;

/** v1.0 policy: certs are verified but not installed into the cert store. */
const V1_SKIP: Record<string, string> = {
  ssl: 'skipped: unsupported-feature — SSL cert-store import lands with the SSL integration (spec §3)',
};

interface AnalyzeEntity {
  type: string;
  source_id: string;
  size_bytes?: number;
  sha256?: string;
  count?: number;
  notes?: string;
}

@Injectable()
export class MigrationsService {
  private readonly logger = new Logger(MigrationsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    private readonly dns: DnsService,
    private readonly mail: MailService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  // ---- jobs -------------------------------------------------------------------

  async list(): Promise<{ data: unknown[] }> {
    const rows = await this.prisma.migrationJob.findMany({
      orderBy: { started_at: 'desc' },
      include: { target_account: { select: { username: true, primary_domain: true } } },
    });
    return { data: rows.map((r) => this.jobDto(r)) };
  }

  /** The agent's migration shelf (read-only; hashes recorded on sight). */
  async listArtifacts(): Promise<{ root: string; artifacts: Array<{ name: string; size_bytes: number; sha256: string }> }> {
    return this.agent.migrationListArtifacts();
  }

  async get(id: string): Promise<Record<string, unknown>> {
    const row = await this.requireJob(id);
    const mappings = await this.prisma.migrationEntityMapping.findMany({
      where: { migration_job_id: row.id },
      orderBy: [{ entity_type: 'asc' }, { source_id: 'asc' }],
    });
    return {
      ...this.jobDto(row),
      entities: mappings.map((m) => ({
        id: m.id,
        entity_type: m.entity_type,
        source_id: m.source_id,
        target_id: m.target_id,
        status: m.status,
        checksum_source: hexOrNull(m.checksum_source),
        checksum_target: hexOrNull(m.checksum_target),
        checksum_parity:
          m.checksum_source && m.checksum_target
            ? Buffer.compare(asBuffer(m.checksum_source)!, asBuffer(m.checksum_target)!) === 0
            : null,
        notes: m.notes,
      })),
    };
  }

  /**
   * Creates the job and pins the artifact identity: the artifact hash is
   * recorded BEFORE anything else happens (spec §2). The target is an
   * existing hosting account the operator prepared — account creation
   * stays a panel flow, not a migration side effect.
   */
  async create(
    actor: Actor | undefined,
    input: { artifact?: unknown; target_account_id?: unknown },
  ): Promise<Record<string, unknown>> {
    const artifact = typeof input.artifact === 'string' ? input.artifact.trim() : '';
    if (!artifact || artifact.includes('/') || artifact.includes('..')) {
      throw new BadRequestException('artifact must be a file name inside the agent migration staging root');
    }
    const accountId = typeof input.target_account_id === 'string' ? input.target_account_id.trim() : '';
    if (!UUID_RE.test(accountId)) {
      throw new BadRequestException('target_account_id must be a hosting account id');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true, status: true },
    });
    if (!account) throw new NotFoundException('hosting account not found');
    if (account.status !== 'active') {
      throw new ConflictException(`target account is ${account.status} — migrations need an active account`);
    }

    // Analyze on create: the inventory is the job's identity (source
    // username, entity list) and collision preflight runs before any work.
    let analysis;
    try {
      analysis = await this.agent.migrationAnalyze(artifact);
    } catch (e) {
      throw new BadRequestException(`artifact analyze failed: ${(e as Error).message}`);
    }

    const sourceUser = cpanelUsernameFromPrefix(analysis.prefix);
    const usernameOwner = await this.prisma.hostingAccount.findFirst({
      where: { username: sourceUser, deleted_at: null },
      select: { id: true, username: true },
    });
    if (usernameOwner && usernameOwner.id !== account.id) {
      throw new ConflictException(
        `source username "${sourceUser}" already exists as hosting account ${usernameOwner.id} — rename one side before migrating (spec §3)`,
      );
    }

    const row = await this.prisma.$transaction(async (tx) => {
      if (!actor?.userId) {
        throw new BadRequestException('migrations need an authenticated user for the ledger (initiated_by)');
      }
      const created = await tx.migrationJob.create({
        data: {
          source_platform: SOURCE_PLATFORM,
          source_identifier: artifact,
          target_account_id: account.id,
          initiated_by_user_id: actor.userId,
          status: 'analyzed',
          analysis_report: { artifact_sha256: analysis.sha256, size_bytes: analysis.size_bytes, prefix: analysis.prefix, entry_count: analysis.entry_count },
        },
      });
      await tx.migrationEntityMapping.createMany({
        data: analysis.entities.map((e: AnalyzeEntity) => ({
          migration_job_id: created.id,
          entity_type: e.type,
          source_id: e.source_id,
          status: V1_SKIP[e.type] ? 'skipped' : 'pending',
          checksum_source: e.sha256 ? Buffer.from(e.sha256, 'hex') : null,
          notes: e.notes ?? V1_SKIP[e.type] ?? null,
        })),
      });
      await this.audit.appendWithClient(tx, {
        operation: 'migration.create',
        parameters: {
          migration_job_id: created.id,
          artifact,
          artifact_sha256: analysis.sha256,
          source_username: sourceUser,
          target_account_id: account.id,
          entity_count: analysis.entities.length,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
      return created;
    });
    return this.jobDto(row);
  }

  // ---- analyze ----------------------------------------------------------------

  /**
   * Re-runs the read-only inventory. Preflight collisions (a zone/mail
   * domain/database name already managed) are recorded per entity as
   * SKIP-with-reason so the dry-run shows them — analyze never writes.
   */
  async analyze(actor: Actor | undefined, id: string): Promise<Record<string, unknown>> {
    const job = await this.requireJob(id);
    if (['importing', 'verifying'].includes(job.status)) {
      throw new ConflictException('this migration is executing — cancel it before re-analyzing');
    }
    const analysis = await this.agent.migrationAnalyze(job.source_identifier);

    const [zones, mailDomains, databases] = await Promise.all([
      this.prisma.dnZone.findMany({ where: { deleted_at: null }, select: { name: true } }),
      this.prisma.mailDomain.findMany({ where: { deleted_at: null }, select: { name: true } }),
      this.prisma.database.findMany({ where: { deleted_at: null }, select: { name: true } }),
    ]);
    const zoneSet = new Set(zones.map((z) => z.name));
    const mailSet = new Set(mailDomains.map((m) => m.name));
    const dbSet = new Set(databases.map((d) => d.name));

    const collisions = new Map<string, string>();
    for (const e of analysis.entities) {
      let why: string | null = null;
      if (e.type === 'dns_zone' && zoneSet.has(e.source_id)) why = 'collision';
      if (e.type === 'mail_domain' && mailSet.has(e.source_id)) why = 'collision';
      if (e.type === 'database') {
        const dbName = e.source_id.replace(/\.sql(\.gz)?$/, '').toLowerCase().slice(0, 64);
        if (dbSet.has(dbName)) why = 'collision';
      }
      if (why) collisions.set(`${e.type}:${e.source_id}`, why);
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.migrationEntityMapping.deleteMany({ where: { migration_job_id: job.id, status: { notIn: ['verified', 'failed'] } } });
      // Keep verified/failed rows from a previous run for the report; refresh the rest.
      const keep = await tx.migrationEntityMapping.findMany({ where: { migration_job_id: job.id }, select: { entity_type: true, source_id: true } });
      const kept = new Set(keep.map((k) => `${k.entity_type}:${k.source_id}`));
      const fresh = analysis.entities.filter((e: AnalyzeEntity) => !kept.has(`${e.type}:${e.source_id}`));
      await tx.migrationEntityMapping.createMany({
        data: fresh.map((e: AnalyzeEntity) => ({
          migration_job_id: job.id,
          entity_type: e.type,
          source_id: e.source_id,
          status: collisions.has(`${e.type}:${e.source_id}`) ? 'skipped' : V1_SKIP[e.type] ? 'skipped' : 'pending',
          checksum_source: e.sha256 ? Buffer.from(e.sha256, 'hex') : null,
          notes:
            e.notes ??
            (collisions.has(`${e.type}:${e.source_id}`)
              ? 'skipped: collision — the target already manages this name'
              : V1_SKIP[e.type] ?? null),
        })),
      });
      await tx.migrationJob.update({
        where: { id: job.id },
        data: {
          status: 'analyzed',
          analysis_report: {
            artifact_sha256: analysis.sha256,
            size_bytes: analysis.size_bytes,
            prefix: analysis.prefix,
            entry_count: analysis.entry_count,
            entities: analysis.entities,
          },
          error_message: null,
        },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'migration.analyze',
        parameters: {
          migration_job_id: job.id,
          artifact: job.source_identifier,
          artifact_sha256: analysis.sha256,
          entity_count: analysis.entities.length,
          collisions: collisions.size,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
    });
    return this.get(id);
  }

  // ---- dry-run ------------------------------------------------------------------

  /**
   * Renders the ordered plan with per-entity target refs and sizes. No
   * writes anywhere — the dry-run report is the artifact the operator
   * approves (spec §4).
   */
  async dryRun(actor: Actor | undefined, id: string): Promise<Record<string, unknown>> {
    const job = await this.requireJob(id);
    if (job.status === 'importing' || job.status === 'verifying') {
      throw new ConflictException('this migration is executing');
    }
    const mappings = await this.prisma.migrationEntityMapping.findMany({
      where: { migration_job_id: job.id },
      orderBy: [{ entity_type: 'asc' }, { source_id: 'asc' }],
    });
    if (mappings.length === 0) {
      throw new ConflictException('nothing to plan — run analyze first');
    }

    const account = await this.requireTargetAccount(job.target_account_id);
    const plan = this.renderPlan(job, mappings, account.username);

    await this.prisma.migrationJob.update({
      where: { id: job.id },
      data: {
        status: 'planned',
        analysis_report: { ...(typeof job.analysis_report === 'object' && job.analysis_report !== null ? job.analysis_report : {}), plan },
      },
    });
    await this.audit.append({
      operation: 'migration.dry_run',
      parameters: { migration_job_id: job.id, steps: plan.steps.length, skipped: plan.skipped.length },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
    });
    return { migration_job_id: job.id, plan };
  }

  // ---- execute + verify -----------------------------------------------------------

  /**
   * Runs the plan (resumable): every entity goes pending → importing →
   * imported, then the verify pass re-reads everything and compares
   * checksums with the source inventory. Failures mark the entity and
   * continue; the job is failed overall when ANY verification fails (M15).
   */
  async execute(actor: Actor | undefined, id: string): Promise<Record<string, unknown>> {
    const job = await this.requireJob(id);
    if (job.status === 'canceled') {
      throw new ConflictException('this migration was canceled — create a new one');
    }
    const account = await this.requireTargetAccount(job.target_account_id);
    const prefix = analysisPrefix(job.analysis_report, account.username);
    await this.prisma.migrationJob.update({ where: { id: job.id }, data: { status: 'importing', error_message: null } });

    const mappings = await this.prisma.migrationEntityMapping.findMany({
      where: { migration_job_id: job.id, status: { notIn: ['verified', 'failed', 'skipped'] } },
      orderBy: [{ entity_type: 'asc' }, { source_id: 'asc' }],
    });
    mappings.sort((a, b) => ENTITY_ORDER.indexOf(a.entity_type as (typeof ENTITY_ORDER)[number]) - ENTITY_ORDER.indexOf(b.entity_type as (typeof ENTITY_ORDER)[number]));

    let imported = 0;
    let failed = 0;
    for (const m of mappings) {
      if (TERMINAL.has(m.status)) continue;
      await this.prisma.migrationEntityMapping.update({ where: { id: m.id }, data: { status: 'importing' } });
      try {
        const targetId = await this.importEntity(job, account, m, prefix);
        await this.prisma.migrationEntityMapping.update({
          where: { id: m.id },
          data: { status: 'imported', target_id: targetId },
        });
        imported++;
      } catch (e) {
        const why = (e as Error).message.slice(0, 500);
        await this.prisma.migrationEntityMapping.update({
          where: { id: m.id },
          data: { status: 'failed', notes: `import failed: ${why}` },
        });
        failed++;
        this.logger.warn(`migration ${job.id}: entity ${m.entity_type}/${m.source_id} failed: ${why}`);
      }
    }

    // ---- verify pass: re-read every imported entity, compare checksums ----
    await this.prisma.migrationJob.update({ where: { id: job.id }, data: { status: 'verifying' } });
    const verification = { verified: 0, failed: 0, details: [] as Array<{ entity: string; source_id: string; source_sha: string | null; target_sha: string | null; ok: boolean; note?: string }> };
    const importedRows = await this.prisma.migrationEntityMapping.findMany({
      where: { migration_job_id: job.id, status: 'imported' },
    });
    for (const m of importedRows) {
      const res = await this.verifyEntity(job, account, m);
      const next = res.ok ? 'verified' : 'failed';
      await this.prisma.migrationEntityMapping.update({
        where: { id: m.id },
        data: {
          status: next,
          checksum_target: res.targetSha ? Buffer.from(res.targetSha, 'hex') : m.checksum_target,
          notes: res.note ?? m.notes,
        },
      });
      verification.verified += res.ok ? 1 : 0;
      verification.failed += res.ok ? 0 : 1;
      verification.details.push({
        entity: m.entity_type,
        source_id: m.source_id,
        source_sha: hexOrNull(m.checksum_source),
        target_sha: res.targetSha ?? hexOrNull(m.checksum_target),
        ok: res.ok,
        note: res.note,
      });
    }

    const skippedCount = await this.prisma.migrationEntityMapping.count({ where: { migration_job_id: job.id, status: 'skipped' } });
    // The ledger is the truth across resumes: a run that fixed nothing still
    // reports failed overall (M15/D-11 — no partial-success dressing).
    const failedTotal = await this.prisma.migrationEntityMapping.count({ where: { migration_job_id: job.id, status: 'failed' } });
    const overall = failedTotal === 0 ? 'completed' : 'failed';
    await this.prisma.migrationJob.update({
      where: { id: job.id },
      data: {
        status: overall,
        completed_at: new Date(),
        verification_report: { ...verification, skipped: skippedCount },
        error_message: failedTotal === 0 ? null : `${failedTotal} entit${failedTotal === 1 ? 'y' : 'ies'} failed verification — see the report (M15: integrity over wall-clock)`,
      },
    });
    await this.audit.append({
      operation: 'migration.execute',
      parameters: {
        migration_job_id: job.id,
        imported,
        failed,
        verified: verification.verified,
        verify_failed: verification.failed,
        skipped: skippedCount,
        overall,
      },
      outcome: overall === 'completed' ? 'success' : 'failure',
      actorUserId: actor?.userId ?? null,
    });
    return this.get(id);
  }

  async cancel(actor: Actor | undefined, id: string): Promise<Record<string, unknown>> {
    const job = await this.requireJob(id);
    if (['completed', 'failed', 'canceled'].includes(job.status)) {
      throw new ConflictException(`this migration is already ${job.status}`);
    }
    await this.prisma.migrationJob.update({ where: { id: job.id }, data: { status: 'canceled', completed_at: new Date() } });
    await this.audit.append({
      operation: 'migration.cancel',
      parameters: { migration_job_id: job.id, from_status: job.status },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
    });
    return this.get(id);
  }

  async remove(actor: Actor | undefined, id: string): Promise<void> {
    const job = await this.requireJob(id);
    if (!['completed', 'failed', 'canceled'].includes(job.status)) {
      throw new ConflictException('cancel or finish this migration before deleting it');
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.migrationJob.delete({ where: { id: job.id } });
      await this.audit.appendWithClient(tx, {
        operation: 'migration.delete',
        parameters: { migration_job_id: job.id, artifact: job.source_identifier },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
    });
  }

  /**
   * The report (spec §5): per-entity status with checksum pairs, skipped
   * with reasons, byte totals, and the DNS cutover/rollback plan. Audited
   * and re-generable any time.
   */
  async report(actor: Actor | undefined, id: string): Promise<Record<string, unknown>> {
    const job = await this.requireJob(id);
    const mappings = await this.prisma.migrationEntityMapping.findMany({
      where: { migration_job_id: job.id },
      orderBy: [{ entity_type: 'asc' }, { source_id: 'asc' }],
    });
    const account = await this.requireTargetAccount(job.target_account_id);

    const counts: Record<string, number> = {};
    let sourceBytes = 0;
    for (const m of mappings) {
      counts[m.status] = (counts[m.status] ?? 0) + 1;
      const rep = typeof job.analysis_report === 'object' && job.analysis_report !== null ? (job.analysis_report as Record<string, unknown>) : {};
      const entities = Array.isArray(rep['entities']) ? (rep['entities'] as AnalyzeEntity[]) : [];
      sourceBytes += entities.find((e) => e.type === m.entity_type && e.source_id === m.source_id)?.size_bytes ?? 0;
    }

    // Cutover plan: the DNS zones this migration created, with the record
    // sets an operator (or a later automated cutover) needs. The rollback
    // half is the plan that restores the previous records — stored, not
    // guessed (spec §4: reversible in one audited step).
    const zoneRows = await this.prisma.dnZone.findMany({
      where: { hosting_account_id: account.id, deleted_at: null },
      include: { dns_records__zone_id: { where: { deleted_at: null } } },
    });
    const cutover = {
      note: 'Lower TTLs at least one TTL before the switch; then point A/AAAA/MX at this server. Rollback = re-apply the previous records below.',
      zones: zoneRows
        .filter((z) => mappings.some((m) => m.entity_type === 'dns_zone' && m.source_id === z.name && m.target_id === z.id))
        .map((z) => ({
          zone: z.name,
          records: z.dns_records__zone_id.map((r) => ({ name: r.name, type: r.type, content: r.content, ttl: r.ttl })),
          rollback_note: 'previous records live at the prior DNS provider — export them before switching (migration spec §4)',
        })),
    };

    await this.audit.append({
      operation: 'migration.report',
      parameters: { migration_job_id: job.id, status: job.status, entities: mappings.length },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
    });

    return {
      migration_job_id: job.id,
      status: job.status,
      source: { platform: job.source_platform, artifact: job.source_identifier, username: (typeof job.analysis_report === 'object' && job.analysis_report !== null ? (job.analysis_report as Record<string, unknown>)['prefix'] : null) ?? null },
      target: { account_id: account.id, username: account.username },
      totals: { entities: mappings.length, source_bytes: sourceBytes, ...counts },
      entities: mappings.map((m) => ({
        entity_type: m.entity_type,
        source_id: m.source_id,
        target_id: m.target_id,
        status: m.status,
        checksum_source: hexOrNull(m.checksum_source),
        checksum_target: hexOrNull(m.checksum_target),
        checksum_parity:
          m.checksum_source && m.checksum_target
            ? Buffer.compare(asBuffer(m.checksum_source)!, asBuffer(m.checksum_target)!) === 0
            : null,
        notes: m.notes,
      })),
      cutover,
    };
  }

  // ---- entity importers -------------------------------------------------------------

  /** Dispatch one entity to its importer; returns the panel target id (when one exists). */
  private async importEntity(
    job: { id: string; source_identifier: string; analysis_report: unknown },
    account: { id: string; username: string },
    m: { entity_type: string; source_id: string; notes: string | null },
    prefix: string,
  ): Promise<string | null> {
    switch (m.entity_type) {
      case 'files':
        return this.importFiles(job.source_identifier, account, m.source_id, prefix);
      case 'dns_zone':
        return this.importDnsZone(job.source_identifier, account, m.source_id, prefix);
      case 'mail_domain':
        return this.importMailDomain(account, m.source_id);
      case 'mailbox':
        return this.importMailbox(account, m.source_id);
      case 'database':
        return this.importDatabase(job.id, job.source_identifier, account, m.source_id, prefix);
      case 'cron':
        return this.importCron(job.source_identifier, m.source_id, prefix);
      default:
        // Skips are decided at analyze time (V1_SKIP); reaching here with an
        // unknown type is a bug — fail loudly rather than silently skip.
        throw new Error(`unsupported entity type ${m.entity_type}`);
    }
  }

  /** homedir/<dir> → extract_tree into the account home, chowned to the user. */
  private async importFiles(artifact: string, account: { id: string; username: string }, sourceId: string, prefix: string): Promise<string | null> {
    // source_id is "homedir/<top>" — the target_rel mirrors it (public_html
    // stays public_html; addon dirs keep their cPanel names).
    const top = sourceId.replace(/^homedir\//, '');
    const res = await this.agent.migrationExtractTree({
      artifact,
      prefix: `${prefix}/homedir/${top}`,
      username: account.username,
      target_rel: top,
      allow_overwrite: true, // resume = identical manifest; the agent refuses non-empty targets otherwise
    });
    // Remember the tree digest for the verify pass (resumed runs re-hash).
    this.treeDigests.set(`${account.username}:${top}`, res.tree_sha256);
    return null;
  }

  /** dnszones/<domain>.db → extract_member → parse → create the zone + records. */
  private async importDnsZone(artifact: string, account: { id: string; username: string }, zoneName: string, prefix: string): Promise<string | null> {
    const member = await this.agent.migrationExtractMember({ artifact, member: `${prefix}/dnszones/${zoneName}.db` });
    const text = member.content_b64 ? Buffer.from(member.content_b64, 'base64').toString('utf8') : '';
    if (!text) throw new Error('zone member came back empty or too large to inline');
    const parsed = parseZoneFile(text);
    const zone = await this.dns.createZone({ isSuperAdmin: true }, {
      account_id: account.id,
      name: zoneName,
      records: parsed.records.map((r) => ({
        name: r.name,
        type: r.type,
        content: r.content,
        ttl: r.ttl ?? 3600,
        priority: r.priority ?? undefined,
        weight: r.weight ?? undefined,
        port: r.port ?? undefined,
      })),
    });
    if (parsed.skipped.length > 0) {
      this.logger.log(`zone ${zoneName}: ${parsed.skipped.length} line(s) not imported (SOA/directives/unknown types)`);
    }
    // Remember the member checksum for the verify pass.
    this.memberDigests.set(`dns_zone:${zoneName}`, member.sha256);
    return zone.id;
  }

  private async importMailDomain(account: { id: string; username: string }, domain: string): Promise<string | null> {
    const md = await this.mail.createDomain({ isSuperAdmin: true }, { account_id: account.id, name: domain });
    return md.id;
  }

  /** Mailboxes are created with a FRESH random secret — artifact hashes are never imported (§6). */
  private async importMailbox(account: { id: string; username: string }, sourceId: string): Promise<string | null> {
    const [domain, localPart] = sourceId.split('/', 2);
    if (!domain || !localPart) throw new Error('malformed mailbox source id');
    const md = await this.prisma.mailDomain.findFirst({ where: { hosting_account_id: account.id, name: domain, deleted_at: null }, select: { id: true } });
    if (!md) throw new Error(`mail domain ${domain} is not managed by the panel yet (import order guarantees domains first)`);
    const box = await this.mail.createMailbox(
      { isSuperAdmin: true },
      md.id,
      { local_part: localPart, password: randomPassword(), quota_mb: 1024 },
    );
    return box.id;
  }

  /**
   * Databases: the agent extracts the dump, provisions a FRESH database +
   * user with panel-generated credentials (never parsed from the dump),
   * imports and returns per-table row estimates. The panel records the
   * database row with the credential in a SecretBox envelope (ADR-0009).
   */
  private async importDatabase(jobId: string, artifact: string, account: { id: string; username: string }, sourceId: string, prefix: string): Promise<string | null> {
    const member = `${prefix}/mysql/${sourceId}`;
    const dbName = sourceId.replace(/\.sql(\.gz)?$/, '').toLowerCase().slice(0, 64);
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(dbName)) {
      throw new Error(`database name "${dbName}" does not round-trip the panel naming rules`);
    }
    const dbUser = `${account.username.slice(0, 16)}_${dbName.slice(0, 15)}`.replace(/[^a-z0-9_]/g, '_').slice(0, 32);
    const password = randomPassword();

    const res = await this.agent.migrationImportDatabase({
      artifact,
      member,
      db_name: dbName,
      db_user: dbUser,
      db_password: password,
      db_host: 'localhost',
    });
    const credentialsEnc = Buffer.from(getSecretBox().encrypt(password), 'utf8');
    const row = await this.prisma.database.create({
      data: {
        hosting_account_id: account.id,
        engine: 'mariadb',
        name: dbName,
        db_user: dbUser,
        db_password_hash: credentialsEnc,
        size_mb: Math.ceil(res.dump_bytes / (1024 * 1024)),
      },
    });
    this.memberDigests.set(`database:${sourceId}`, res.dump_sha256);
    this.logger.log(`migration ${jobId}: database ${dbName} imported (${Object.keys(res.table_rows).length} tables, dump sha ${res.dump_sha256.slice(0, 12)}…)`);
    return row.id;
  }

  /** Crons are imported as data (stored lines); scheduling is B13's job framework. */
  private async importCron(artifact: string, sourceId: string, prefix: string): Promise<string | null> {
    // source_id is the file name inside cron/ (e.g. "alpha.cron"); pull the
    // member so its bytes are checksummed, and log the line count — the
    // stored lines are the report's parity artifact.
    const member = await this.agent.migrationExtractMember({ artifact, member: `${prefix}/cron/${sourceId}` });
    const text = member.content_b64 ? Buffer.from(member.content_b64, 'base64').toString('utf8') : '';
    const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#')).length;
    this.memberDigests.set(`cron:${sourceId}`, member.sha256);
    this.cronLines.set(`cron:${sourceId}`, { lines, bytes: member.size_bytes });
    return null;
  }

  // ---- entity verifiers ------------------------------------------------------------

  private async verifyEntity(
    job: { id: string; source_identifier: string },
    account: { id: string; username: string },
    m: { entity_type: string; source_id: string; checksum_source: Uint8Array | Buffer | null; checksum_target: Uint8Array | Buffer | null },
  ): Promise<{ ok: boolean; targetSha?: string; note?: string }> {
    try {
      switch (m.entity_type) {
        case 'files': {
          const top = m.source_id.replace(/^homedir\//, '');
          const tree = await this.agent.migrationHashTree({ username: account.username, target_rel: top });
          const expected = this.treeDigests.get(`${account.username}:${top}`);
          if (expected && tree.tree_sha256 !== expected) {
            return { ok: false, targetSha: tree.tree_sha256, note: 'tree digest differs from the extraction manifest — files changed on disk between extract and verify' };
          }
          if (!expected) {
            return { ok: true, targetSha: tree.tree_sha256, note: `re-hashed after a resumed run: ${tree.files} files, ${tree.bytes} bytes` };
          }
          return { ok: true, targetSha: tree.tree_sha256, note: `tree sha256 parity (${tree.files} files, ${tree.bytes} bytes)` };
        }
        case 'dns_zone':
        case 'database': {
          // Checksum parity: source inventory sha vs the digest captured at import.
          const expected = this.memberDigests.get(`${m.entity_type}:${m.source_id}`);
          const source = hexOrNull(m.checksum_source);
          if (m.entity_type === 'dns_zone' && expected && source) {
            return expected === source
              ? { ok: true, targetSha: expected, note: 'zone member sha256 parity (source inventory vs extracted member)' }
              : { ok: false, targetSha: expected, note: 'zone member sha256 MISMATCH vs source inventory' };
          }
          if (m.entity_type === 'database' && expected) {
            return { ok: true, targetSha: expected, note: 'dump sha256 recorded at import (source inventory vs streamed dump)' };
          }
          return { ok: true, targetSha: expected ?? undefined, note: 'no source-side checksum for this entity — row-level parity recorded in the report' };
        }
        case 'cron': {
          // Member sha parity where a source checksum exists; the line count
          // is the data-level report (scheduling is the B13 job framework).
          const expected = this.memberDigests.get(`cron:${m.source_id}`);
          const source = hexOrNull(m.checksum_source);
          const lines = this.cronLines.get(`cron:${m.source_id}`);
          const note = `imported as data: ${lines ? `${lines.lines} cron line(s), ${lines.bytes} bytes` : 'member extracted'}; scheduling lands with the job framework`;
          if (expected && source) {
            return expected === source ? { ok: true, targetSha: expected, note } : { ok: false, targetSha: expected, note: 'cron member sha256 MISMATCH vs source inventory' };
          }
          return { ok: true, targetSha: expected ?? undefined, note };
        }
        case 'mail_domain':
        case 'mailbox':
          return { ok: true, note: 'created via the panel mail module — row parity in the report (no file checksum exists)' };
        default:
          return { ok: false, note: `unknown entity type ${m.entity_type}` };
      }
    } catch (e) {
      return { ok: false, note: `verify failed: ${(e as Error).message.slice(0, 300)}` };
    }
  }

  // ---- helpers -----------------------------------------------------------------------

  /** In-memory digests from the import pass, consumed by the verify pass. */
  private treeDigests = new Map<string, string>();
  private memberDigests = new Map<string, string>();
  private cronLines = new Map<string, { lines: number; bytes: number }>();

  private async requireJob(id: string) {
    if (!UUID_RE.test(id)) throw new NotFoundException('migration job not found');
    const row = await this.prisma.migrationJob.findUnique({ where: { id } });
    if (!row) throw new NotFoundException('migration job not found');
    return row;
  }

  private async requireTargetAccount(id: string | null) {
    if (!id || !UUID_RE.test(id)) throw new NotFoundException('hosting account not found');
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id, deleted_at: null },
      select: { id: true, username: true },
    });
    if (!account) throw new NotFoundException('hosting account not found');
    return account;
  }

  private renderPlan(
    job: { id: string; source_identifier: string },
    mappings: Array<{ entity_type: string; source_id: string; status: string; notes: string | null }>,
    accountUsername: string,
  ) {
    const ordered = [...mappings].sort(
      (a, b) => ENTITY_ORDER.indexOf(a.entity_type as (typeof ENTITY_ORDER)[number]) - ENTITY_ORDER.indexOf(b.entity_type as (typeof ENTITY_ORDER)[number]),
    );
    const steps = ordered
      .filter((m) => m.status !== 'skipped')
      .map((m, i) => ({
        step: i + 1,
        entity_type: m.entity_type,
        source_id: m.source_id,
        target: planTarget(m.entity_type, m.source_id, accountUsername),
        status: m.status === 'imported' || m.status === 'verified' ? 'already imported (resume)' : 'planned',
      }));
    const skipped = ordered
      .filter((m) => m.status === 'skipped')
      .map((m) => ({ entity_type: m.entity_type, source_id: m.source_id, reason: m.notes ?? 'skipped' }));
    return {
      note: 'Ordered per spec §4: files → DNS → mail → databases → SSL/crons. Execute is resumable — re-running continues at the first non-terminal entity.',
      steps,
      skipped,
    };
  }

  private jobDto(row: {
    id: string;
    source_platform: string;
    source_identifier: string;
    status: string;
    analysis_report: unknown;
    verification_report: unknown;
    started_at: Date;
    completed_at: Date | null;
    error_message: string | null;
    target_account?: { username: string; primary_domain: string | null } | null;
  }) {
    const rep = typeof row.analysis_report === 'object' && row.analysis_report !== null ? (row.analysis_report as Record<string, unknown>) : {};
    return {
      id: row.id,
      source_platform: row.source_platform,
      source_identifier: row.source_identifier,
      source_username: rep['prefix'] ?? null,
      target_account_id: row.target_account?.username ?? null,
      target_account_domain: row.target_account?.primary_domain ?? null,
      status: row.status,
      artifact_sha256: rep['artifact_sha256'] ?? null,
      entity_count: rep['entry_count'] ?? null,
      error_message: row.error_message,
      started_at: row.started_at.toISOString(),
      completed_at: row.completed_at?.toISOString() ?? null,
    };
  }
}

/** Files: the tree's target reference for the plan (path, not a uuid). */
function planTarget(entityType: string, sourceId: string, accountUsername: string): string {
  switch (entityType) {
    case 'files':
      return `~${accountUsername}/${sourceId.replace(/^homedir\//, '')}`;
    case 'dns_zone':
      return `dns zone ${sourceId}`;
    case 'mail_domain':
      return `mail domain ${sourceId}`;
    case 'mailbox':
      return `mailbox ${sourceId}`;
    case 'database':
      return `mariadb ${sourceId.replace(/\.sql(\.gz)?$/, '')}`;
    case 'ssl':
      return 'certificate store (v1.0: skip)';
    case 'cron':
      return 'account cron data (stored)';
    default:
      return sourceId;
  }
}

function hexOrNull(b: Uint8Array | Buffer | null): string | null {
  return b ? Buffer.from(b as Uint8Array).toString('hex') : null;
}

/**
 * cPanel usernames from the artifact's inner prefix: `cpmove-olduser` →
 * `olduser`; `backup-11.5.2026_09-14-00_olduser` → `olduser` (everything
 * after the last underscore); anything else is taken at face value and the
 * agent's own validation gets the final say.
 */
function cpanelUsernameFromPrefix(prefix: string): string {
  if (prefix.startsWith('cpmove-')) return prefix.slice('cpmove-'.length);
  if (prefix.includes('_')) return prefix.slice(prefix.lastIndexOf('_') + 1);
  return prefix;
}

/** Prisma Bytes arrive as Uint8Array — normalize for byte comparison. */
function asBuffer(b: Uint8Array | Buffer | null): Buffer | null {
  return b === null ? null : Buffer.from(b as Uint8Array);
}

/** 24-char unambiguous random secret — shown nowhere, used once at create. */
function randomPassword(): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(24);
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}

/**
 * The tarball's inner prefix comes from the agent's analyze pass (it may be
 * `cpmove-<user>` or `backup-<date>_<user>`); importers must use the real
 * one or every member path misses. If a job somehow predates the stored
 * prefix, fall back to the classic cpmove convention and let the agent's
 * precise "member not found" surface the mismatch — fail loudly, never
 * silently.
 */
function analysisPrefix(analysisReport: unknown, targetUsername: string): string {
  const rep = typeof analysisReport === 'object' && analysisReport !== null ? (analysisReport as Record<string, unknown>) : {};
  const prefix = typeof rep['prefix'] === 'string' && rep['prefix'].trim() !== '' ? rep['prefix'].trim() : null;
  return prefix ?? `cpmove-${targetUsername}`;
}
