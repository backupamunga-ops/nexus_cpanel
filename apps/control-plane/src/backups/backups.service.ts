import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { createHmac } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { getSecretBox } from '../common/secretbox';
import { Actor } from '../sites/sites.service';

/**
 * Backups (API spec §4.16) — B10.
 *
 *   - the agent is the only writer of node state: it stages, tars,
 *     encrypts (age, C15) and uploads artifacts; the panel owns the
 *     registry (destinations, jobs, runs — DDL-first tables);
 *   - destination configs live as SecretBox envelopes (ADR-0009) in
 *     `config_enc` — decrypted only at the point of an agent call, never
 *     returned by any list/get, never in audit payloads (a fingerprint
 *     instead), never logged;
 *   - a backup run is a JOURNAL row, not a resource: it is created in
 *     `running` state before the agent call and honestly records failures
 *     (`failed` + error_message). Provisioned resources stay agent-first
 *     (no row on failure); journal rows exist to tell the truth about
 *     attempts;
 *   - the "verified" badge is only ever set by a real proof: an integrity
 *     verify (checksum +, for encrypted artifacts, an actual age
 *     decryption) or a dry-run test-restore. It is never inferred from
 *     backup success alone;
 *   - retention (GFS) is computed panel-side from the run registry after
 *     each successful run: keep N daily / N weekly / N monthly restore
 *     points plus everything inside retention_days; the rest is purged
 *     through the agent (which protects any artifact whose manifest is
 *     newer than the cutoff, belt-and-suspenders);
 *   - schedules are validated cron expressions stored on the job — the
 *     firing engine is the B13 job framework, so today they are honestly
 *     "stored — not yet firing" and every job has a Run now path.
 *
 * This is a server-wide (admin) surface: `backup:*` is NOT in the
 * hosting-scoped prefix family; the guard admits server admins and tokens
 * explicitly scoped for it (C6/C4).
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CRON_RE = /^(\S+\s+){4}\S+$/; // five fields; the firing engine (B13) validates deeper
const JOB_SCOPES = ['server', 'account', 'site', 'database'] as const;
const DEST_TYPES = ['local', 's3', 'sftp'] as const;
type JobScope = (typeof JOB_SCOPES)[number];
type DestinationType = (typeof DEST_TYPES)[number];

export interface DestinationDto {
  id: string;
  name: string;
  type: DestinationType;
  is_default: boolean;
  age_recipients_note: string;
  created_at: string;
}

export interface JobDto {
  id: string;
  name: string;
  scope: JobScope;
  scope_id: string | null;
  scope_label: string;
  destination_id: string;
  destination_name: string;
  schedule: string;
  /** Honest scheduling note — the firing engine lands with B13. */
  schedule_note: string;
  retention_days: number;
  keep_daily: number;
  keep_weekly: number;
  keep_monthly: number;
  is_enabled: boolean;
  created_at: string;
}

export interface RunDto {
  id: string;
  job_id: string;
  job_name: string;
  status: 'running' | 'success' | 'failed' | 'verified';
  started_at: string;
  completed_at: string | null;
  size_bytes: number | null;
  artifact_path: string | null;
  checksum_sha256: string | null;
  verified_at: string | null;
  error_message: string | null;
}

interface DestinationRow {
  id: string;
  name: string;
  type: string;
  config_enc: Uint8Array | Buffer;
  is_default: boolean;
  created_at: Date;
}

interface JobRow {
  id: string;
  name: string;
  scope: string;
  scope_id: string | null;
  destination_id: string;
  schedule: string;
  retention_days: number;
  keep_daily: number;
  keep_weekly: number;
  keep_monthly: number;
  is_enabled: boolean;
  created_at: Date;
  destination?: { name: string } | null;
}

@Injectable()
export class BackupsService {
  private readonly logger = new Logger(BackupsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  // ---- destinations ------------------------------------------------------------

  async listDestinations(): Promise<{ data: DestinationDto[] }> {
    const rows = await this.prisma.backupDestination.findMany({ orderBy: { created_at: 'asc' } });
    return { data: rows.map(destinationToDto) };
  }

  /**
   * Validates per-type config, stores it as a SecretBox envelope, and
   * returns the DTO without any config material.
   */
  async createDestination(
    actor: Actor | undefined,
    input: { name?: unknown; type?: unknown; is_default?: unknown; config?: unknown },
  ): Promise<DestinationDto> {
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (name.length < 1 || name.length > 100) {
      throw new BadRequestException('destination name must be 1-100 characters');
    }
    const type = typeof input.type === 'string' ? input.type.trim().toLowerCase() : '';
    if (!DEST_TYPES.includes(type as DestinationType)) {
      throw new BadRequestException('type must be local | s3 | sftp');
    }
    const config = (input.config ?? {}) as Record<string, unknown>;
    if (typeof config !== 'object' || config === null || Array.isArray(config)) {
      throw new BadRequestException('config must be an object');
    }
    this.validateDestinationConfig(type as DestinationType, config);

    const dup = await this.prisma.backupDestination.findFirst({ where: { name }, select: { id: true } });
    if (dup) throw new ConflictException('a destination with this name already exists');

    const isDefault = input.is_default === true;
    const envelope = Buffer.from(getSecretBox().encrypt(JSON.stringify(config)), 'utf8');

    const row = await this.prisma.$transaction(async (tx) => {
      if (isDefault) {
        // Exactly one default: flip the others before inserting.
        await tx.backupDestination.updateMany({ data: { is_default: false } });
      }
      const created = await tx.backupDestination.create({
        data: { name, type, config_enc: envelope, is_default: isDefault },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'backup.destination.create',
        parameters: {
          destination_id: created.id,
          name,
          type,
          is_default: isDefault,
          // ADR-0015 discipline: fingerprint, never the material.
          config_fingerprint: fingerprintOf(JSON.stringify(config)),
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
      return created;
    });
    return destinationToDto(row);
  }

  async deleteDestination(actor: Actor | undefined, id: string): Promise<void> {
    const row = await this.requireDestination(id);
    const jobs = await this.prisma.backupJob.count({ where: { destination_id: row.id } });
    if (jobs > 0) {
      throw new ConflictException(`this destination is used by ${jobs} backup job(s) — delete or re-point them first`);
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.backupDestination.delete({ where: { id: row.id } });
      await this.audit.appendWithClient(tx, {
        operation: 'backup.destination.delete',
        parameters: { destination_id: row.id, name: row.name, type: row.type },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
    });
  }

  /** Probe round trip through the agent; config decrypted at point of use. */
  async testDestination(actor: Actor | undefined, id: string) {
    const row = await this.requireDestination(id);
    const dest = this.decryptDestinationConfig(row);
    let result;
    try {
      result = await this.agent.backupTestDestination(dest);
    } catch (e) {
      await this.audit.append({
        operation: 'backup.destination.test',
        parameters: { destination_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
      });
      throw e;
    }
    await this.audit.append({
      operation: 'backup.destination.test',
      parameters: {
        destination_id: row.id,
        material: 'fingerprint-only (ADR-0015)',
        config_fingerprint: fingerprintOf(JSON.stringify(dest)),
      },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
    });
    return result;
  }

  private validateDestinationConfig(type: DestinationType, config: Record<string, unknown>): void {
    const str = (k: string): string => (typeof config[k] === 'string' ? (config[k] as string).trim() : '');
    const ageRecipients = Array.isArray(config['age_recipients']) ? (config['age_recipients'] as unknown[]) : [];
    for (const r of ageRecipients) {
      if (typeof r !== 'string' || r.length < 10 || r.includes('\0')) {
        throw new BadRequestException('age_recipients must be an array of recipient public key strings');
      }
    }
    if (type === 'local') {
      const root = str('root');
      if (!root.startsWith('/') || root.includes('..') || root.includes('\0')) {
        throw new BadRequestException("local config requires an absolute 'root' without '..'");
      }
    } else if (type === 's3') {
      if (!str('bucket')) throw new BadRequestException("s3 config requires 'bucket'");
      if (!str('access_key_id') || !str('secret_access_key')) {
        throw new BadRequestException("s3 config requires 'access_key_id' and 'secret_access_key'");
      }
      const endpoint = str('endpoint');
      if (endpoint && !/^https?:\/\//.test(endpoint)) {
        throw new BadRequestException("s3 'endpoint' must be an http(s) URL");
      }
    } else {
      if (!str('host') || !str('username')) throw new BadRequestException("sftp config requires 'host' and 'username'");
      if (!str('private_key')) throw new BadRequestException("sftp config requires 'private_key' (PEM)");
      const port = config['port'];
      if (port !== undefined && (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535)) {
        throw new BadRequestException("sftp 'port' must be an integer 1-65535");
      }
    }
  }

  private decryptDestinationConfig(row: DestinationRow): Record<string, unknown> {
    const enc = Buffer.from(row.config_enc).toString('utf8');
    try {
      return JSON.parse(getSecretBox().decrypt(enc)) as Record<string, unknown>;
    } catch (e) {
      throw new Error(`destination config decryption failed (wrong PANEL_SECRET_KEY?): ${(e as Error).message}`);
    }
  }

  private async requireDestination(id: string): Promise<DestinationRow> {
    if (!UUID_RE.test(id)) throw new NotFoundException('destination not found');
    const row = await this.prisma.backupDestination.findFirst({ where: { id } });
    if (!row) throw new NotFoundException('destination not found');
    return row;
  }

  // ---- jobs -----------------------------------------------------------------------

  async listJobs(): Promise<{ data: JobDto[] }> {
    const rows = await this.prisma.backupJob.findMany({
      orderBy: { created_at: 'asc' },
      include: { destination: { select: { name: true } } },
    });
    const labels = await this.scopeLabelsOf(rows);
    return { data: rows.map((r) => jobToDto(r, labels[r.id] ?? '')) };
  }

  async createJob(
    actor: Actor | undefined,
    input: {
      name?: unknown; scope?: unknown; scope_id?: unknown; destination_id?: unknown;
      schedule?: unknown; retention_days?: unknown; keep_daily?: unknown;
      keep_weekly?: unknown; keep_monthly?: unknown; is_enabled?: unknown;
    },
  ): Promise<JobDto> {
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (name.length < 1 || name.length > 100) {
      throw new BadRequestException('job name must be 1-100 characters');
    }
    const scope = typeof input.scope === 'string' ? input.scope.trim().toLowerCase() : '';
    if (!JOB_SCOPES.includes(scope as JobScope)) {
      throw new BadRequestException('scope must be server | account | site | database');
    }
    let scopeId: string | null = null;
    if (scope !== 'server') {
      scopeId = typeof input.scope_id === 'string' ? input.scope_id.trim() : '';
      if (!UUID_RE.test(scopeId)) {
        throw new BadRequestException(`scope_id (a uuid) is required for ${scope} scope`);
      }
      if (scope === 'account') {
        const account = await this.prisma.hostingAccount.findFirst({
          where: { id: scopeId, deleted_at: null },
          select: { id: true, username: true },
        });
        if (!account) throw new NotFoundException('hosting account not found');
      }
    }
    const destinationId = typeof input.destination_id === 'string' ? input.destination_id.trim() : '';
    const destination = await this.prisma.backupDestination.findFirst({ where: { id: destinationId } });
    if (!destination) throw new NotFoundException('destination not found');

    const schedule = typeof input.schedule === 'string' && input.schedule.trim() !== '' ? input.schedule.trim() : '0 3 * * *';
    if (!CRON_RE.test(schedule)) {
      throw new BadRequestException('schedule must be a five-field cron expression');
    }
    const intOr = (v: unknown, dflt: number, min: number, max: number, label: string): number => {
      if (v === undefined || v === null || v === '') return dflt;
      const n = Number(v);
      if (!Number.isInteger(n) || n < min || n > max) {
        throw new BadRequestException(`${label} must be an integer ${min}-${max}`);
      }
      return n;
    };
    const retentionDays = intOr(input.retention_days, 30, 1, 3650, 'retention_days');
    const keepDaily = intOr(input.keep_daily, 7, 0, 365, 'keep_daily');
    const keepWeekly = intOr(input.keep_weekly, 4, 0, 104, 'keep_weekly');
    const keepMonthly = intOr(input.keep_monthly, 6, 0, 120, 'keep_monthly');
    const isEnabled = input.is_enabled !== false;

    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.backupJob.create({
        data: {
          name, scope, scope_id: scopeId, destination_id: destinationId,
          schedule, retention_days: retentionDays,
          keep_daily: keepDaily, keep_weekly: keepWeekly, keep_monthly: keepMonthly,
          is_enabled: isEnabled,
        },
        include: { destination: { select: { name: true } } },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'backup.job.create',
        parameters: { job_id: created.id, name, scope, scope_id: scopeId, destination_id: destinationId, schedule },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
      return created;
    });
    return jobToDto(row, await this.scopeLabelOf(row));
  }

  async updateJob(
    actor: Actor | undefined,
    id: string,
    input: { schedule?: unknown; is_enabled?: unknown; retention_days?: unknown; keep_daily?: unknown; keep_weekly?: unknown; keep_monthly?: unknown; destination_id?: unknown },
  ): Promise<JobDto> {
    const row = await this.requireJob(id);
    const data: Record<string, unknown> = {};
    if (input.schedule !== undefined) {
      const schedule = typeof input.schedule === 'string' ? input.schedule.trim() : '';
      if (!CRON_RE.test(schedule)) throw new BadRequestException('schedule must be a five-field cron expression');
      data['schedule'] = schedule;
    }
    if (input.is_enabled !== undefined) {
      data['is_enabled'] = input.is_enabled === true;
    }
    for (const [key, min, max] of [
      ['retention_days', 1, 3650],
      ['keep_daily', 0, 365],
      ['keep_weekly', 0, 104],
      ['keep_monthly', 0, 120],
    ] as const) {
      const v = input[key];
      if (v !== undefined) {
        const n = Number(v);
        if (!Number.isInteger(n) || n < min || n > max) {
          throw new BadRequestException(`${key} must be an integer ${min}-${max}`);
        }
        data[key] = n;
      }
    }
    if (input.destination_id !== undefined) {
      const destId = String(input.destination_id).trim();
      const destination = await this.prisma.backupDestination.findFirst({ where: { id: destId } });
      if (!destination) throw new NotFoundException('destination not found');
      data['destination_id'] = destId;
    }
    const updated = await this.prisma.$transaction(async (tx) => {
      const u = await tx.backupJob.update({
        where: { id: row.id },
        data,
        include: { destination: { select: { name: true } } },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'backup.job.update',
        parameters: { job_id: row.id, changed: Object.keys(data) },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
      return u;
    });
    return jobToDto(updated, await this.scopeLabelOf(updated));
  }

  async deleteJob(actor: Actor | undefined, id: string): Promise<void> {
    const row = await this.requireJob(id);
    // backup_runs rows cascade (FK ON DELETE CASCADE) — deleting a job
    // forgets its history by design; the artifacts at the destination are
    // NOT deleted here (an operator purges via retention or manually).
    await this.prisma.$transaction(async (tx) => {
      await tx.backupJob.delete({ where: { id: row.id } });
      await this.audit.appendWithClient(tx, {
        operation: 'backup.job.delete',
        parameters: { job_id: row.id, name: row.name },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
    });
  }

  // ---- runs -------------------------------------------------------------------------

  async listRuns(actor: Actor | undefined, jobId?: string): Promise<{ data: RunDto[] }> {
    const where = jobId ? { job_id: jobId } : {};
    const rows = await this.prisma.backupRun.findMany({
      where,
      orderBy: { started_at: 'desc' },
      take: 100,
      include: { job: { select: { name: true } } },
    });
    return { data: rows.map(runToDto) };
  }

  async getRun(actor: Actor | undefined, id: string): Promise<RunDto> {
    const row = await this.requireRun(id);
    return runToDto(row);
  }

  /**
   * Runs a job now: journal row in `running`, agent call, honest terminal
   * state. The agent composes sources per scope (whole home for accounts,
   * the site subtree, a mariadb dump for databases, managed dirs for
   * server) — the panel never passes raw server paths for account data.
   */
  async runJob(actor: Actor | undefined, id: string): Promise<RunDto> {
    const job = await this.requireJob(id);
    if (!job.is_enabled) {
      throw new ConflictException('this job is disabled — enable it first');
    }
    const destination = await this.requireDestination(job.destination_id);
    const destConfig = this.decryptDestinationConfig(destination);

    const { agentParams, scopeLabel } = await this.composeSources(job);

    const run = await this.prisma.backupRun.create({
      data: { job_id: job.id, status: 'running', started_at: new Date() },
      include: { job: { select: { name: true } } },
    });
    // Job-center mirror (B13): the run is visible in the jobs table.
    const jobRow = await this.prisma.jobMetadata.create({
      data: {
        bullmq_job_id: `run_${run.id}`,
        queue_name: 'backups',
        job_type: 'backup.run',
        status: 'active',
        payload: { job_id: job.id, job_name: job.name, scope: job.scope } as object,
        attempts: 1,
      },
    });
    try {
      const res = await this.agent.backupCreate({
        scope: job.scope,
        scope_id: job.scope_id ?? '',
        destination: destConfig,
        ...agentParams,
      });
      const updated = await this.prisma.$transaction(async (tx) => {
        const u = await tx.backupRun.update({
          where: { id: run.id },
          data: {
            status: 'success',
            completed_at: new Date(),
            size_bytes: res.size_bytes,
            artifact_path: res.artifact,
            checksum_sha256: Buffer.from(res.checksum_sha256, 'utf8'),
          },
          include: { job: { select: { name: true } } },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'backup.run.success',
          parameters: {
            run_id: run.id, job_id: job.id, scope: job.scope, scope_id: job.scope_id,
            artifact: res.artifact, size_bytes: res.size_bytes, encrypted: res.encrypted,
          },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
        });
        return u;
      });
      this.logger.log(`backup ${job.name} (${scopeLabel}) → ${res.artifact} (${res.size_bytes} bytes, encrypted=${res.encrypted})`);
      // GFS retention after success — best effort, failures are logged, not fatal.
      await this.applyRetention(actor, job.id).catch((e) =>
        this.logger.warn(`retention pass for job ${job.name} failed: ${(e as Error).message}`),
      );
      await this.prisma.jobMetadata.update({
        where: { id: jobRow.id },
        data: { status: 'completed', progress: 100, result: { run_id: run.id } as object, completed_at: new Date() },
      });
      return runToDto(updated);
    } catch (e) {
      const failed = await this.prisma.backupRun.update({
        where: { id: run.id },
        data: { status: 'failed', completed_at: new Date(), error_message: (e as Error).message },
        include: { job: { select: { name: true } } },
      });
      await this.prisma.jobMetadata.update({
        where: { id: jobRow.id },
        data: { status: 'failed', result: { error: (e as Error).message, run_id: run.id } as object, completed_at: new Date() },
      });
      await this.audit.append({
        operation: 'backup.run.failure',
        parameters: { run_id: run.id, job_id: job.id, scope: job.scope, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
      });
      return runToDto(failed);
    }
  }

  /** Per-scope agent params + a human label for logs/DTOs. */
  private async composeSources(job: JobRow): Promise<{ agentParams: Record<string, unknown>; scopeLabel: string }> {
    if (job.scope === 'server') {
      return { agentParams: {}, scopeLabel: 'server' };
    }
    if (job.scope === 'account') {
      const account = await this.prisma.hostingAccount.findFirst({
        where: { id: job.scope_id ?? '', deleted_at: null },
        select: { id: true, username: true },
      });
      if (!account) throw new NotFoundException('hosting account for this job not found');
      return {
        agentParams: { owner_username: account.username, sources: ['.'] },
        scopeLabel: `account ${account.username}`,
      };
    }
    if (job.scope === 'database') {
      const db = await this.prisma.database.findFirst({
        where: { id: job.scope_id ?? '', deleted_at: null },
        select: { id: true, engine: true, name: true, hosting_account: { select: { username: true } } },
      });
      if (!db) throw new NotFoundException('database for this job not found');
      if (db.engine !== 'mariadb') {
        throw new BadRequestException('database backups in v1.0 cover mariadb (ADR-0001)');
      }
      return {
        agentParams: {
          owner_username: db.hosting_account.username,
          database: { engine: db.engine, name: db.name },
        },
        scopeLabel: `database ${db.name}`,
      };
    }
    // site scope: the site's document root subtree inside the owner home.
    const site = await this.prisma.domain.findFirst({
      where: { id: job.scope_id ?? '', deleted_at: null },
      select: { id: true, name: true, hosting_account: { select: { username: true } } },
    });
    if (!site) throw new NotFoundException('site for this job not found');
    return {
      agentParams: {
        owner_username: site.hosting_account.username,
        sources: ['public_html'],
      },
      scopeLabel: `site ${site.name}`,
    };
  }

  /** Restore preview: manifest + sanitized entry listing through the agent. */
  async restorePreview(actor: Actor | undefined, id: string) {
    const run = await this.requireRun(id);
    if (run.status === 'running') throw new ConflictException('this run is still in progress');
    const { destConfig, row } = await this.destinationConfigForRun(run);
    try {
      const res = await this.agent.backupRestorePreview({
        artifact_path: run.artifact_path ?? '',
        destination: destConfig,
      });
      await this.audit.append({
        operation: 'backup.restore_preview',
        parameters: { run_id: run.id, artifact: run.artifact_path, entries: res.total_entries },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
      return { run_id: run.id, artifact: run.artifact_path, ...res, destination_type: row.type };
    } catch (e) {
      await this.audit.append({
        operation: 'backup.restore_preview',
        parameters: { run_id: run.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
      });
      throw e;
    }
  }

  /**
   * Restore with preview semantics: dry_run=true is the test-restore that
   * earns the "verified" badge; dry_run=false writes back into the account
   * home (databases are additionally re-imported through database.restore).
   */
  async restoreRun(
    actor: Actor | undefined,
    id: string,
    input: { dry_run?: unknown; target_path?: unknown },
  ): Promise<Record<string, unknown>> {
    const run = await this.requireRun(id);
    if (run.status === 'running') throw new ConflictException('this run is still in progress');
    if (!run.artifact_path) throw new ConflictException('this run has no artifact to restore from');
    const dryRun = input.dry_run !== false; // default: the safe, honest dry run
    const { destConfig } = await this.destinationConfigForRun(run);
    const job = await this.requireJob(run.job_id);
    const { agentParams, scopeLabel } = await this.composeSources(job);

    try {
      const res = await this.agent.backupRestore({
        artifact_path: run.artifact_path,
        destination: destConfig,
        scope: job.scope,
        scope_id: job.scope_id ?? '',
        dry_run: dryRun,
        target_path: typeof input.target_path === 'string' ? input.target_path.trim() : undefined,
        ...agentParams,
      });
      const extracted: string[] = res.extracted ?? [];

      // Database scope, real restore: re-import the dumped SQL through the
      // same confined path the dump tool uses (round trip through the agent).
      let dbRestoreNote: string | undefined;
      if (!dryRun && job.scope === 'database') {
        const db = await this.prisma.database.findFirst({
          where: { id: job.scope_id ?? '', deleted_at: null },
          select: { id: true, engine: true, name: true, hosting_account: { select: { username: true } } },
        });
        const dumpEntry = extracted.find((e) => e.endsWith('.sql'));
        if (db && dumpEntry) {
          const owner = db.hosting_account.username;
          const homeRel = this.stripOwnerPrefix(dumpEntry, owner);
          await this.agent.databaseRestore(db.engine, db.name, homeRel, owner);
          dbRestoreNote = `dump ${homeRel} re-imported into ${db.name} via database.restore`;
        } else if (db) {
          dbRestoreNote = 'no .sql dump found in the artifact — files extracted, database not re-imported (stated honestly)';
        }
      }

      const updated = await this.prisma.$transaction(async (tx) => {
        const u = await tx.backupRun.update({
          where: { id: run.id },
          data: dryRun ? { status: 'verified', verified_at: new Date() } : {},
          include: { job: { select: { name: true } } },
        });
        await this.audit.appendWithClient(tx, {
          operation: 'backup.restore',
          parameters: {
            run_id: run.id, artifact: run.artifact_path, dry_run: dryRun,
            extracted: extracted.length, skipped: res.skipped ?? 0,
            ...(dbRestoreNote ? { note: dbRestoreNote } : {}),
          },
          outcome: 'success',
          actorUserId: actor?.userId ?? null,
        });
        return u;
      });
      this.logger.log(`restore of ${run.artifact_path} (${scopeLabel}) dry_run=${dryRun} extracted=${extracted.length}`);
      return {
        run: runToDto(updated),
        status: res.status,
        extracted: extracted.slice(0, 100),
        skipped: res.skipped ?? 0,
        into: res.into ?? null,
        note: dryRun
          ? 'Test-restore passed — the run now carries the verified badge. Nothing was written back.'
          : dbRestoreNote ?? 'Restore written back into the account home.',
      };
    } catch (e) {
      await this.audit.append({
        operation: 'backup.restore',
        parameters: { run_id: run.id, dry_run: dryRun, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
      });
      throw e;
    }
  }

  /** Integrity proof: checksum + (for encrypted artifacts) a real decrypt. */
  async verifyRun(actor: Actor | undefined, id: string) {
    const run = await this.requireRun(id);
    if (run.status === 'running') throw new ConflictException('this run is still in progress');
    if (!run.artifact_path) throw new ConflictException('this run has no artifact to verify');
    const { destConfig } = await this.destinationConfigForRun(run);
    const expected = run.checksum_sha256 ? Buffer.from(run.checksum_sha256).toString('utf8') : '';
    try {
      const res = await this.agent.backupVerify({
        artifact_path: run.artifact_path,
        destination: destConfig,
        checksum: expected || undefined,
      });
      if (res.status === 'verified') {
        await this.prisma.backupRun.update({
          where: { id: run.id },
          data: { status: 'verified', verified_at: new Date() },
        });
      }
      await this.audit.append({
        operation: 'backup.verify',
        parameters: {
          run_id: run.id, artifact: run.artifact_path,
          outcome: res.status, reason: res.reason,
          encrypted: res.encrypted,
        },
        outcome: res.status === 'verified' ? 'success' : 'failure',
        actorUserId: actor?.userId ?? null,
      });
      return {
        run_id: run.id, ...res,
        note: res.status === 'verified'
          ? 'Integrity verified: checksum matched' + (res.encrypted ? ' and the artifact decrypted with the node master key (C15)' : '') + '.'
          : res.reason || 'verification failed',
      };
    } catch (e) {
      await this.audit.append({
        operation: 'backup.verify',
        parameters: { run_id: run.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
      });
      throw e;
    }
  }

  // ---- retention (GFS) ------------------------------------------------------------

  /**
   * GFS selection over the run registry: keep everything inside
   * retention_days, plus the newest keep_daily per-day, keep_weekly
   * per-Monday, keep_monthly per-1st successful restore points outside it.
   * Non-kept runs older than retention_days are purged (agent protects
   * newer manifests) and their journal rows removed.
   */
  async applyRetention(actor: Actor | undefined, jobId: string): Promise<{ deleted: number; kept: number }> {
    const job = await this.requireJob(jobId);
    const destination = await this.requireDestination(job.destination_id);
    const destConfig = this.decryptDestinationConfig(destination);

    const now = Date.now();
    const cutoff = new Date(now - job.retention_days * 86_400_000);
    const runs = await this.prisma.backupRun.findMany({
      where: { job_id: job.id, status: { in: ['success', 'verified'] }, artifact_path: { not: null } },
      orderBy: { started_at: 'desc' },
    });

    const keep = new Set<string>();
    const seen = { day: new Set<string>(), week: new Set<string>(), month: new Set<string>() };
    let daily = 0;
    let weekly = 0;
    let monthly = 0;
    for (const r of runs) {
      const started = r.started_at.getTime();
      if (started >= cutoff.getTime()) {
        keep.add(r.id); // inside the retention window
        continue;
      }
      const d = r.started_at;
      const dayKey = d.toISOString().slice(0, 10);
      const weekKey = `${dayKey}-w${weekOf(d)}`;
      const monthKey = dayKey.slice(0, 7);
      if (daily < job.keep_daily && !seen.day.has(dayKey)) {
        seen.day.add(dayKey); daily++; keep.add(r.id); continue;
      }
      if (weekly < job.keep_weekly && d.getUTCDay() === 1 && !seen.week.has(weekKey)) {
        seen.week.add(weekKey); weekly++; keep.add(r.id); continue;
      }
      if (monthly < job.keep_monthly && d.getUTCDate() === 1 && !seen.month.has(monthKey)) {
        seen.month.add(monthKey); monthly++; keep.add(r.id); continue;
      }
    }

    const doomed = runs.filter((r) => !keep.has(r.id));
    if (doomed.length === 0) return { deleted: 0, kept: keep.size };

    await this.agent.backupPurge({
      destination: destConfig,
      before_date: cutoff.toISOString(),
      delete: doomed.map((r) => r.artifact_path ?? ''),
    });
    await this.prisma.$transaction(async (tx) => {
      await tx.backupRun.deleteMany({ where: { id: { in: doomed.map((r) => r.id) } } });
      await this.audit.appendWithClient(tx, {
        operation: 'backup.retention.apply',
        parameters: {
          job_id: job.id, deleted_runs: doomed.length, kept: keep.size,
          retention_days: job.retention_days,
          keep_daily: job.keep_daily, keep_weekly: job.keep_weekly, keep_monthly: job.keep_monthly,
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
      });
    });
    return { deleted: doomed.length, kept: keep.size };
  }

  /** Shared helper: destination row + decrypted config for a run's job. */
  private async destinationConfigForRun(run: { job_id: string }): Promise<{ destConfig: Record<string, unknown>; row: DestinationRow }> {
    const job = await this.requireJob(run.job_id);
    const row = await this.requireDestination(job.destination_id);
    return { destConfig: this.decryptDestinationConfig(row), row };
  }

  /** Restores report paths relative to the owner home — strip the staging prefix. */
  private stripOwnerPrefix(entry: string, owner: string): string {
    const marker = `${owner}/`;
    const idx = entry.indexOf(marker);
    return idx >= 0 ? entry.slice(idx + marker.length) : entry;
  }

  private async requireJob(id: string): Promise<JobRow> {
    if (!UUID_RE.test(id)) throw new NotFoundException('backup job not found');
    const row = await this.prisma.backupJob.findFirst({
      where: { id },
      include: { destination: { select: { name: true } } },
    });
    if (!row) throw new NotFoundException('backup job not found');
    return row;
  }

  private async requireRun(id: string) {
    if (!UUID_RE.test(id)) throw new NotFoundException('backup run not found');
    const row = await this.prisma.backupRun.findFirst({
      where: { id },
      include: { job: { select: { name: true } } },
    });
    if (!row) throw new NotFoundException('backup run not found');
    return row;
  }

  private async scopeLabelsOf(rows: JobRow[]): Promise<Record<string, string>> {
    const out: Record<string, string> = {};
    for (const r of rows) {
      out[r.id] = await this.scopeLabelOf(r);
    }
    return out;
  }

  private async scopeLabelOf(row: JobRow): Promise<string> {
    if (row.scope === 'server' || !row.scope_id) return row.scope;
    if (row.scope === 'account') {
      const a = await this.prisma.hostingAccount.findFirst({ where: { id: row.scope_id }, select: { username: true } });
      return a ? `account ${a.username}` : 'account (deleted)';
    }
    if (row.scope === 'database') {
      const d = await this.prisma.database.findFirst({ where: { id: row.scope_id }, select: { name: true } });
      return d ? `database ${d.name}` : 'database (deleted)';
    }
    const s = await this.prisma.domain.findFirst({ where: { id: row.scope_id }, select: { name: true } });
    return s ? `site ${s.name}` : 'site (deleted)';
  }
}

// ---- DTO mappers -----------------------------------------------------------------

function destinationToDto(row: DestinationRow): DestinationDto {
  return {
    id: row.id,
    name: row.name,
    type: row.type as DestinationType,
    is_default: row.is_default,
    age_recipients_note: 'the config is stored as an encrypted envelope; its fields are never listed back (ADR-0009/0015 discipline)',
    created_at: row.created_at.toISOString(),
  };
}

function jobToDto(row: JobRow, scopeLabel: string): JobDto {
  return {
    id: row.id,
    name: row.name,
    scope: row.scope as JobScope,
    scope_id: row.scope_id,
    scope_label: scopeLabel,
    destination_id: row.destination_id,
    destination_name: row.destination?.name ?? '',
    schedule: row.schedule,
    schedule_note: 'stored — the firing engine is the job framework (B13); use Run now until then',
    retention_days: row.retention_days,
    keep_daily: row.keep_daily,
    keep_weekly: row.keep_weekly,
    keep_monthly: row.keep_monthly,
    is_enabled: row.is_enabled,
    created_at: row.created_at.toISOString(),
  };
}

function runToDto(row: {
  id: string;
  job_id: string;
  status: string;
  started_at: Date;
  completed_at: Date | null;
  size_bytes: bigint | number | null;
  artifact_path: string | null;
  checksum_sha256: Uint8Array | Buffer | null;
  verified_at: Date | null;
  error_message: string | null;
  job?: { name: string } | null;
}): RunDto {
  return {
    id: row.id,
    job_id: row.job_id,
    job_name: row.job?.name ?? '',
    status: row.status as RunDto['status'],
    started_at: row.started_at.toISOString(),
    completed_at: row.completed_at?.toISOString() ?? null,
    size_bytes: row.size_bytes === null ? null : Number(row.size_bytes),
    artifact_path: row.artifact_path,
    checksum_sha256: row.checksum_sha256 ? Buffer.from(row.checksum_sha256).toString('utf8') : null,
    verified_at: row.verified_at?.toISOString() ?? null,
    error_message: row.error_message,
  };
}

function fingerprintOf(secret: string): string {
  return createHmac('sha256', 'nexuspanel-cred-fingerprint').update(secret).digest('hex').slice(0, 16);
}

function weekOf(d: Date): number {
  // ISO-ish week number for bucketing (deterministic, panel-side only).
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dayNum = (t.getUTCDay() + 6) % 7;
  t.setUTCDate(t.getUTCDate() - dayNum + 3);
  const firstThursday = new Date(Date.UTC(t.getUTCFullYear(), 0, 4));
  const diff = t.getTime() - firstThursday.getTime();
  return 1 + Math.round(diff / (7 * 86_400_000));
}
