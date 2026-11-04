import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as crypto from 'node:crypto';

/**
 * Hash-chained, tamper-evident audit log (security control C11, security model §4).
 *
 *   this_hash = SHA-256(
 *     prior_hash (32 bytes)
 *     || occurred_at (RFC3339 UTC, 8 bytes packed unix-seconds, big-endian)
 *     || actor_user_id (16 bytes; zeros if null)
 *     || operation (UTF-8)
 *     || canonical_json(parameters) (UTF-8, sorted keys)
 *     || outcome (UTF-8)
 *   )
 *
 * M0 keeps the chain in memory; P1 persists to `audit_entries` +
 * `audit_chain_heads` (schema v2.0) inside the same transaction as the action.
 */
export interface AuditEntry {
  id: string;
  occurredAt: Date;
  actorUserId: string | null;
  operation: string;
  parameters: Record<string, unknown>;
  outcome: 'success' | 'failure' | 'partial';
  priorHash: Buffer;
  thisHash: Buffer;
}

@Injectable()
export class AuditService implements OnModuleInit {
  private readonly logger = new Logger(AuditService.name);
  private readonly entries: AuditEntry[] = [];
  private head = Buffer.alloc(32, 0);

  /** Seed the chain head from a checkpoint (e.g., audit_chain_heads.last_hash). */
  onModuleInit(): void {
    const seed = process.env.AUDIT_CHAIN_SEED_HASH;
    if (seed) {
      this.head = Buffer.from(seed, 'hex');
      this.logger.log(`audit chain head seeded from checkpoint (${this.head.toString('hex').slice(0, 12)}…)`);
    }
  }

  /** Appends one entry and returns it. Never throws for business errors —
   *  failed operations are audited as outcome:'failure'. */
  append(
    operation: string,
    parameters: Record<string, unknown>,
    outcome: AuditEntry['outcome'],
    actorUserId: string | null = null,
    occurredAt: Date = new Date(),
  ): AuditEntry {
    const prior = Buffer.from(this.head);
    const entry: AuditEntry = {
      id: crypto.randomUUID(),
      occurredAt,
      actorUserId,
      operation,
      parameters,
      outcome,
      priorHash: prior,
      thisHash: computeHash(prior, occurredAt, actorUserId, operation, parameters, outcome),
    };
    this.entries.push(entry);
    this.head = Buffer.from(entry.thisHash);
    this.logger.debug(`audit ${operation} → ${entry.thisHash.toString('hex').slice(0, 12)}…`);
    return entry;
  }

  /** Current chain head (hex). */
  headHex(): string {
    return this.head.toString('hex');
  }

  /** All entries (read path for the audit UI in P5). */
  list(): AuditEntry[] {
    return [...this.entries];
  }

  /** Walks the chain recomputing every hash (C11 verification).
   *  Returns verified=true, or the first broken entry id. */
  verify(): { verified: boolean; brokenAt: string | null; checked: number } {
    let expectedPrior = Buffer.alloc(32, 0);
    for (const e of this.entries) {
      const recomputed = computeHash(
        expectedPrior,
        e.occurredAt,
        e.actorUserId,
        e.operation,
        e.parameters,
        e.outcome,
      );
      if (!e.priorHash.equals(expectedPrior) || !e.thisHash.equals(recomputed)) {
        return { verified: false, brokenAt: e.id, checked: this.entries.indexOf(e) + 1 };
      }
      expectedPrior = Buffer.from(e.thisHash);
    }
    return { verified: true, brokenAt: null, checked: this.entries.length };
  }
}

/** Exactly the security-model §4 construction. */
export function computeHash(
  priorHash: Buffer,
  occurredAt: Date,
  actorUserId: string | null,
  operation: string,
  parameters: Record<string, unknown>,
  outcome: string,
): Buffer {
  const h = crypto.createHash('sha256');
  h.update(priorHash);

  const ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(Math.floor(occurredAt.getTime() / 1000)));
  h.update(ts);

  const actor = Buffer.alloc(16, 0);
  if (actorUserId) {
    Buffer.from(actorUserId, 'utf8').copy(actor.subarray(0, Math.min(16, Buffer.byteLength(actorUserId))));
  }
  h.update(actor);

  h.update(Buffer.from(operation, 'utf8'));
  h.update(Buffer.from(canonicalJson(parameters), 'utf8'));
  h.update(Buffer.from(outcome, 'utf8'));
  return h.digest();
}

/** Deterministic JSON with recursively sorted object keys. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortValue((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}
