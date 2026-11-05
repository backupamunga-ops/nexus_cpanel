import { Inject, Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import {
  AuditAppendInput,
  AuditRecord,
  buildEntry,
  computeHash,
} from './audit-chain';

/**
 * Storage seam for the tamper-evident audit chain (C11).
 *
 * - `InMemoryAuditService` — unit tests / dev fallback.
 * - `DatabaseAuditService` — production writer: every append runs inside a
 *   PostgreSQL transaction that takes `pg_advisory_xact_lock(AUDIT_LOCK_KEY)`
 *   before reading the singleton `audit_chain_heads` row, so concurrent
 *   appends serialize and the chain never forks.
 *
 * Callers that need action + audit atomicity (e.g. hosting-account create)
 * pass their own transaction via `appendWithClient(tx, …)`.
 */
export const AUDIT_APPENDER = Symbol('AUDIT_APPENDER');

export interface AuditAppender {
  append(input: AuditAppendInput): Promise<AuditRecord>;
  appendWithClient(
    client: Prisma.TransactionClient | PrismaService,
    input: AuditAppendInput,
  ): Promise<AuditRecord>;
}

/** Advisory lock key for chain-head serialization (arbitrary constant). */
export const AUDIT_LOCK_KEY = 778811;

/* ────────────────────────── in-memory implementation ────────────────────────── */

@Injectable()
export class InMemoryAuditService implements AuditAppender {
  private readonly entries: AuditRecord[] = [];
  private head = Buffer.alloc(32, 0);

  async append(input: AuditAppendInput): Promise<AuditRecord> {
    return this.appendWithClient(null, input);
  }

  async appendWithClient(_client: unknown, input: AuditAppendInput): Promise<AuditRecord> {
    const entry = buildEntry(this.head, input);
    this.entries.push(entry);
    this.head = Buffer.from(entry.thisHash);
    return entry;
  }

  headHex(): string {
    return this.head.toString('hex');
  }

  list(): AuditRecord[] {
    return [...this.entries];
  }

  /** Walks the chain recomputing every hash (C11 verification). */
  verify(): { verified: boolean; brokenAt: string | null; checked: number } {
    let expectedPrior = Buffer.alloc(32, 0);
    for (const [i, e] of this.entries.entries()) {
      const recomputed = computeHash(
        expectedPrior,
        e.occurredAt,
        e.actorUserId,
        e.operation,
        e.parameters,
        e.outcome,
      );
      if (!e.priorHash.equals(expectedPrior) || !e.thisHash.equals(recomputed)) {
        return { verified: false, brokenAt: e.id, checked: i + 1 };
      }
      expectedPrior = Buffer.from(e.thisHash);
    }
    return { verified: true, brokenAt: null, checked: this.entries.length };
  }
}

/* ────────────────────────── database implementation ────────────────────────── */

interface RowShape {
  id: string;
  occurred_at: Date;
  actor_user_id: string | null;
  operation: string;
  parameters: unknown;
  outcome: string;
  prior_hash: Uint8Array | null;
  this_hash: Uint8Array;
  prev_entry_id: string | null;
}

@Injectable()
export class DatabaseAuditService implements AuditAppender {
  private readonly logger = new Logger(DatabaseAuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  async append(input: AuditAppendInput): Promise<AuditRecord> {
    return this.prisma.$transaction((tx) => this.appendWithClient(tx, input));
  }

  /**
   * Appends inside the CALLER's transaction (hosting-account create writes the
   * account row and its audit entry atomically). Takes the same advisory lock
   * so a joining append also serializes against standalone ones.
   */
  async appendWithClient(
    client: Prisma.TransactionClient,
    input: AuditAppendInput,
  ): Promise<AuditRecord> {
    await client.$executeRaw`SELECT pg_advisory_xact_lock(${AUDIT_LOCK_KEY})`;
    const head = await client.auditChainHead.findUnique({ where: { id: true } });
    const prior = head ? Buffer.from(head.last_hash) : Buffer.alloc(32, 0);

    const entry = buildEntry(prior, input);
    const data = {
      id: entry.id,
      occurred_at: entry.occurredAt,
      actor_user_id: entry.actorUserId,
      operation: entry.operation,
      parameters: entry.parameters as Prisma.InputJsonValue,
      outcome: entry.outcome,
      prior_hash: new Uint8Array(entry.priorHash),
      this_hash: new Uint8Array(entry.thisHash),
    };

    if (head) {
      const created = await client.auditEntry.create({
        data: { ...data, prev_entry_id: head.last_entry_id },
      });
      await client.auditChainHead.update({
        where: { id: true },
        data: { last_entry_id: created.id, last_hash: new Uint8Array(entry.thisHash), updated_at: new Date() },
      });
    } else {
      const created = await client.auditEntry.create({ data });
      await client.auditChainHead.create({
        data: { id: true, last_entry_id: created.id, last_hash: new Uint8Array(entry.thisHash) },
      });
    }
    this.logger.debug(`audit ${entry.operation} → ${entry.thisHash.toString('hex').slice(0, 12)}…`);
    return entry;
  }

  /** Current chain head (hex); zeros when the chain is empty. */
  async headHex(): Promise<string> {
    const head = await this.prisma.auditChainHead.findUnique({ where: { id: true } });
    return head ? Buffer.from(head.last_hash).toString('hex') : Buffer.alloc(32, 0).toString('hex');
  }

  /** Newest-first page; cursor = last seen id. */
  async list(limit = 50, beforeId?: string): Promise<{ data: AuditRecord[]; hasMore: boolean }> {
    const rows = (await this.prisma.auditEntry.findMany({
      where: beforeId ? { id: { lt: beforeId } } : undefined,
      orderBy: [{ occurred_at: 'desc' }, { id: 'desc' }],
      take: limit + 1,
    })) as unknown as RowShape[];
    const hasMore = rows.length > limit;
    return { data: rows.slice(0, limit).map(rowToRecord), hasMore };
  }

  async get(id: string): Promise<AuditRecord | null> {
    const row = (await this.prisma.auditEntry.findUnique({ where: { id } })) as unknown as
      | RowShape
      | null;
    return row ? rowToRecord(row) : null;
  }

  /**
   * Full-chain verification (C11): walks backwards from the head via
   * prev_entry_id, recomputes every hash, and compares both links. Bounded at
   * MAX_VERIFY_ENTRIES per run; large chains page through `from` ranges.
   */
  async verify(): Promise<{ verified: boolean; brokenAt: string | null; checked: number }> {
    const MAX = 5_000;
    const head = await this.prisma.auditChainHead.findUnique({ where: { id: true } });
    if (!head) {
      return { verified: true, brokenAt: null, checked: 0 };
    }

    const chain: RowShape[] = [];
    let cursor: string | null = head.last_entry_id;
    while (cursor && chain.length < MAX) {
      const row = (await this.prisma.auditEntry.findUnique({ where: { id: cursor } })) as unknown as
        | RowShape
        | null;
      if (!row) {
        return { verified: false, brokenAt: cursor, checked: chain.length };
      }
      chain.push(row);
      cursor = row.prev_entry_id;
    }
    chain.reverse();

    let expectedPrior = Buffer.alloc(32, 0);
    for (const [i, row] of chain.entries()) {
      const record = rowToRecord(row);
      const recomputed = computeHash(
        expectedPrior,
        record.occurredAt,
        record.actorUserId,
        record.operation,
        record.parameters,
        record.outcome,
      );
      const priorOk = row.prior_hash
        ? Buffer.compare(Buffer.from(row.prior_hash), expectedPrior) === 0
        : expectedPrior.equals(Buffer.alloc(32, 0));
      if (!priorOk || Buffer.compare(Buffer.from(row.this_hash), recomputed) !== 0) {
        return { verified: false, brokenAt: row.id, checked: i + 1 };
      }
      expectedPrior = Buffer.from(row.this_hash);
    }
    return { verified: true, brokenAt: null, checked: chain.length };
  }
}

function rowToRecord(row: RowShape): AuditRecord {
  return {
    id: row.id,
    occurredAt: row.occurred_at,
    actorUserId: row.actor_user_id,
    operation: row.operation,
    parameters: (row.parameters ?? {}) as Record<string, unknown>,
    outcome: row.outcome as AuditRecord['outcome'],
    priorHash: row.prior_hash ? Buffer.from(row.prior_hash) : Buffer.alloc(32, 0),
    thisHash: Buffer.from(row.this_hash),
  };
}

/** Re-export for @Inject token ergonomics. */
export const InjectAudit = () => Inject(AUDIT_APPENDER);
