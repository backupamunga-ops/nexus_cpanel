import { AuditService, canonicalJson, computeHash } from './audit.service';

describe('AuditService (C11 hash chain)', () => {
  it('chains entries: each prior equals previous this-hash', () => {
    const svc = new AuditService();
    const e1 = svc.append('account.create', { username: 'alice' }, 'success');
    const e2 = svc.append('account.suspend', { username: 'alice' }, 'success');
    expect(e2.priorHash.equals(e1.thisHash)).toBe(true);
    expect(svc.headHex()).toBe(e2.thisHash.toString('hex'));
  });

  it('verification passes on an intact chain', () => {
    const svc = new AuditService();
    svc.append('account.create', { username: 'alice' }, 'success');
    svc.append('account.delete', { username: 'alice', preserve_files: true }, 'success');
    expect(svc.verify()).toEqual({ verified: true, brokenAt: null, checked: 2 });
  });

  it('verification detects mid-chain parameter tampering (A5)', () => {
    const svc = new AuditService();
    svc.append('account.create', { username: 'alice' }, 'success');
    svc.append('account.create', { username: 'bob' }, 'success');
    svc.append('account.create', { username: 'carol' }, 'success');

    // Attacker edits history in place.
    svc.list()[1].parameters = { username: 'ROOT' };
    const result = svc.verify();
    expect(result.verified).toBe(false);
    expect(result.brokenAt).toBe(svc.list()[1].id);
  });

  it('verification detects outcome tampering', () => {
    const svc = new AuditService();
    svc.append('account.create', { username: 'alice' }, 'success');
    svc.list()[0].outcome = 'failure';
    expect(svc.verify().verified).toBe(false);
  });

  it('failed operations are auditable as outcome=failure', () => {
    const svc = new AuditService();
    const e = svc.append('account.create', { username: 'bad name' }, 'failure');
    expect(e.outcome).toBe('failure');
    expect(svc.verify().verified).toBe(true);
  });

  it('hash matches the security-model §4 construction byte-for-byte', () => {
    const prior = Buffer.alloc(32, 0);
    const at = new Date('2026-11-05T12:00:00Z');
    const actor = '018f3c2e-7b4a-7dead-beef-424242424242';
    const op = 'account.create';
    const params = { username: 'alice', b: 2, a: 1 };
    const outcome = 'success';

    const got = computeHash(prior, at, actor, op, params, outcome).toString('hex');

    // Independent re-implementation of the spec formula:
    const crypto = require('node:crypto');
    const h = crypto.createHash('sha256');
    h.update(prior);
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(1793880000)); // 2026-11-05T12:00:00Z epoch seconds
    h.update(ts);
    const actorBuf = Buffer.alloc(16, 0);
    Buffer.from(actor, 'utf8').copy(actorBuf.subarray(0, 16));
    h.update(actorBuf);
    h.update(Buffer.from(op, 'utf8'));
    h.update(Buffer.from(canonicalJson(params), 'utf8'));
    h.update(Buffer.from(outcome, 'utf8'));
    const want = h.digest('hex');

    expect(got).toBe(want);
  });

  it('canonicalJson is deterministic regardless of key order', () => {
    expect(canonicalJson({ a: 1, b: { y: 2, x: 3 } })).toBe(
      canonicalJson({ b: { x: 3, y: 2 }, a: 1 }),
    );
  });
});
