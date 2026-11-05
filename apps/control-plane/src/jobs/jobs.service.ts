import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { MalwareService } from '../security/malware.service';
import { BackupsService } from '../backups/backups.service';
import { Actor } from '../sites/sites.service';

/**
 * Job center (B13) — the visible state of long-running work.
 *
 * The registry is `jobs_metadata` (DDL-first, BullMQ-shaped: queue_name,
 * job_type, waiting|active|completed|failed, progress, attempts). v1.0
 * single-node dispatches in-process; `bullmq_job_id` carries the opaque
 * worker id so a BullMQ-backed deployment (multi-node) swaps only the
 * executor, not the contract (ADR-0018).
 *
 * Retrigger: a failed job whose type has a registered handler can be
 * re-fired — it becomes a NEW row (attempts restart at 1) and the old row
 * stays as history. Handlers are explicit; there is deliberately no
 * generic "re-run anything" (that would be a confused-deputy primitive).
 */

export interface JobDto {
  id: string;
  queue_name: string;
  job_type: string;
  status: string;
  progress: number;
  attempts: number;
  payload: unknown;
  result: unknown;
  created_at: string;
  completed_at: string | null;
}

type RetryHandler = (actor: Actor | undefined, payload: Record<string, unknown>) => Promise<unknown>;

@Injectable()
export class JobsService {
  private handlers = new Map<string, RetryHandler>();

  constructor(
    private readonly prisma: PrismaService,
    @InjectAudit() private readonly audit: AuditAppender,
    private readonly malware: MalwareService,
    private readonly backups: BackupsService,
  ) {
    // Registered handlers (explicit allowlist). Backup runs keyed by the
    // originating backup job id ride in payload.job_id.
    this.handlers.set('malware.scan', (actor, payload) =>
      this.malware.startScan(actor, payload as { scope?: string; account_id?: string; path?: string }),
    );
    this.handlers.set('backup.run', (actor, payload) => {
      const jobId = String(payload.job_id ?? '');
      if (!jobId) throw new ConflictException('job payload lacks backup job id');
      return this.backups.runJob(actor, jobId);
    });
  }

  /** Opens a job row in `active` state; returns the row id. */
  async begin(queue: string, jobType: string, payload: Record<string, unknown>, bullmqJobId?: string): Promise<string> {
    const row = await this.prisma.jobMetadata.create({
      data: {
        bullmq_job_id: bullmqJobId ?? `inproc_${cryptoRandomId()}`,
        queue_name: queue,
        job_type: jobType,
        status: 'active',
        payload: payload as object,
        attempts: 1,
      },
    });
    return row.id;
  }

  async complete(jobRowId: string, result: unknown): Promise<void> {
    await this.prisma.jobMetadata.update({
      where: { id: jobRowId },
      data: { status: 'completed', progress: 100, result: (result ?? {}) as object, completed_at: new Date() },
    });
  }

  async fail(jobRowId: string, error: string): Promise<void> {
    await this.prisma.jobMetadata.update({
      where: { id: jobRowId },
      data: { status: 'failed', result: { error } as object, completed_at: new Date() },
    });
  }

  async list(status?: string): Promise<{ data: JobDto[] }> {
    const rows = await this.prisma.jobMetadata.findMany({
      where: status ? { status } : undefined,
      orderBy: { created_at: 'desc' },
      take: 100,
    });
    return { data: rows.map((r: { id: string; queue_name: string; job_type: string; status: string; progress: number; attempts: number; payload: unknown; result: unknown; created_at: Date; completed_at: Date | null }) => this.dto(r)) };
  }

  async get(id: string): Promise<JobDto> {
    const row = await this.prisma.jobMetadata.findUnique({ where: { id } });
    if (!row) throw new NotFoundException('job not found');
    return this.dto(row);
  }

  /** Re-fires a failed job through its registered handler (audited). */
  async retry(actor: Actor | undefined, id: string): Promise<JobDto> {
    const row = await this.prisma.jobMetadata.findUnique({ where: { id } });
    if (!row) throw new NotFoundException('job not found');
    if (row.status !== 'failed') {
      throw new ConflictException('only failed jobs can be retriggered');
    }
    const handler = this.handlers.get(row.job_type);
    if (!handler) {
      throw new ConflictException(`job type "${row.job_type}" has no retrigger handler`);
    }
    const newRow = await this.prisma.jobMetadata.create({
      data: {
        bullmq_job_id: `inproc_${cryptoRandomId()}`,
        queue_name: row.queue_name,
        job_type: row.job_type,
        status: 'active',
        payload: row.payload as object,
        attempts: (row.attempts ?? 0) + 1,
      },
    });
    await this.audit.append({
      operation: 'jobs.retry',
      parameters: { job_type: row.job_type, original_job_id: row.id },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
    });
    // Fire async: the HTTP call returns the new active row immediately; the
    // row transitions to completed/failed as the handler progresses.
    void handler(actor, (row.payload ?? {}) as Record<string, unknown>)
      .then((result) => this.complete(newRow.id, result))
      .catch((e: Error) => this.fail(newRow.id, e.message));
    return this.dto(await this.prisma.jobMetadata.findUniqueOrThrow({ where: { id: newRow.id } }));
  }

  private dto(r: {
    id: string;
    queue_name: string;
    job_type: string;
    status: string;
    progress: number;
    attempts: number;
    payload: unknown;
    result: unknown;
    created_at: Date;
    completed_at: Date | null;
  }): JobDto {
    return {
      id: r.id,
      queue_name: r.queue_name,
      job_type: r.job_type,
      status: r.status,
      progress: r.progress,
      attempts: r.attempts,
      payload: r.payload,
      result: r.result,
      created_at: r.created_at.toISOString(),
      completed_at: r.completed_at?.toISOString() ?? null,
    };
  }
}

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
