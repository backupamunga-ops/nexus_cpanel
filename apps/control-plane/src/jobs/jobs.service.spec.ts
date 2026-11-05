import { ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { InMemoryAuditService } from '../audit/audit.service';
import { JobsService } from './jobs.service';

/**
 * Job center tests (B13): lifecycle rows, retrigger rules (failed only,
 * registered handlers only), audit trail.
 */

function harness() {
  const audit = new InMemoryAuditService();
  const rows: Array<Record<string, unknown>> = [];
  let seq = 1;

  const prisma: Record<string, any> = {
    jobMetadata: {
      create: jest.fn(async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `job-${seq++}`, progress: 0, attempts: 0, completed_at: null, created_at: new Date(), ...data };
        rows.push(row);
        return row;
      }),
      findUnique: jest.fn(async ({ where }: { where: { id: string } }) =>
        rows.find((r) => r.id === where.id) ?? null,
      ),
      findUniqueOrThrow: jest.fn(async ({ where }: { where: { id: string } }) =>
        rows.find((r) => r.id === where.id),
      ),
      update: jest.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = rows.find((r) => r.id === where.id) ?? {};
        return Object.assign(row, data);
      }),
      findMany: jest.fn(async () => rows),
    },
  };

  const svc = new JobsService(
    prisma as unknown as PrismaService,
    audit,
    { startScan: jest.fn(async () => ({ status: 'success' })) } as never,
    { runJob: jest.fn(async () => ({})) } as never,
    { deployNow: jest.fn(async () => ({})) } as never, // B14 git.deploy handler
  );
  return { svc, audit, rows };
}

describe('jobs service (B13)', () => {
  it('tracks the lifecycle: begin → complete / fail', async () => {
    const { svc, rows } = harness();
    const id = await svc.begin('security', 'malware.scan', { scope: 'account' });
    expect(rows[0].status).toBe('active');
    await svc.complete(id, { infected: 0 });
    expect(rows[0].status).toBe('completed');
    expect(rows[0].progress).toBe(100);

    const id2 = await svc.begin('security', 'malware.scan', { scope: 'account' });
    await svc.fail(id2, 'clamscan exploded');
    expect(rows[1].status).toBe('failed');
  });

  it('retrigger: failed jobs with registered handlers only; audited; new row', async () => {
    const { svc, rows, audit } = harness();
    const id = await svc.begin('security', 'malware.scan', { scope: 'account', account_id: 'acct-1' });
    await svc.fail(id, 'boom');

    const retried = await svc.retry({ userId: 'u1', isSuperAdmin: true }, id);
    expect(retried.id).not.toBe(id);
    expect(retried.attempts).toBe(2);
    const ops = audit.list().map((e) => e.operation);
    expect(ops).toContain('jobs.retry');

    // active job → refused
    const id2 = await svc.begin('security', 'malware.scan', {});
    await expect(svc.retry({ userId: 'u1', isSuperAdmin: true }, id2)).rejects.toBeInstanceOf(
      ConflictException,
    );
    // rows untouched by the refused retry
    expect(rows).toHaveLength(3);
  });
});
