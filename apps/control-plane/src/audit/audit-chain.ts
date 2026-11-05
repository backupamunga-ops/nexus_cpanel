import * as crypto from 'node:crypto';

/**
 * Hash-chained audit math — exactly the security-model §4 construction (C11):
 *
 *   this_hash = SHA-256(
 *     prior_hash (32 bytes)
 *     || occurred_at (8 bytes packed unix-seconds, big-endian)
 *     || actor_user_id (16 bytes; utf8-truncated, zero-padded; zeros if null)
 *     || operation (UTF-8)
 *     || canonical_json(parameters) (UTF-8, recursively sorted keys)
 *     || outcome (UTF-8)
 *   )
 *
 * Pure functions only — no I/O — so both the in-memory and database stores
 * compute byte-identical chains and tests can target the math directly.
 */

export interface AuditAppendInput {
  operation: string;
  parameters?: Record<string, unknown>;
  outcome: 'success' | 'failure' | 'partial';
  actorUserId?: string | null;
  actorIp?: string | null;
  nodeId?: string | null;
  hostingAccountId?: string | null;
  occurredAt?: Date;
}

/** A linked, hash-verified audit record as returned by any store. */
export interface AuditRecord {
  id: string;
  occurredAt: Date;
  actorUserId: string | null;
  operation: string;
  parameters: Record<string, unknown>;
  outcome: AuditAppendInput['outcome'];
  priorHash: Buffer;
  thisHash: Buffer;
}

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

/** Builds one linked entry from a prior head (pure — no storage). */
export function buildEntry(priorHash: Buffer, input: AuditAppendInput): AuditRecord {
  const occurredAt = input.occurredAt ?? new Date();
  const parameters = input.parameters ?? {};
  return {
    id: crypto.randomUUID(),
    occurredAt,
    actorUserId: input.actorUserId ?? null,
    operation: input.operation,
    parameters,
    outcome: input.outcome,
    priorHash: Buffer.from(priorHash),
    thisHash: computeHash(priorHash, occurredAt, input.actorUserId ?? null, input.operation, parameters, input.outcome),
  };
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
