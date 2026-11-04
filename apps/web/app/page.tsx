import Shell from './shell';

export default function Dashboard() {
  return (
    <Shell active="/">
      <h1 className="np-title">Dashboard</h1>
      <p className="np-subtitle">M0 — Hello, privileged agent.</p>
      <div style={{ display: 'grid', gap: 16, gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', marginTop: 24 }}>
        <div className="np-card">
          <strong>Architecture status</strong>
          <p style={{ color: 'var(--np-muted)', marginTop: 8 }}>
            Control plane (NestJS) → signed commands → Go agent → cgroup v2 →
            hash-chained audit. One thread through every layer, proven in M0
            before the feature build-out.
          </p>
        </div>
        <div className="np-card">
          <strong>Accounts</strong>
          <p style={{ color: 'var(--np-muted)', marginTop: 8 }}>
            Create and observe a test hosting account on the{' '}
            <a href="/accounts">Accounts page</a>.
          </p>
        </div>
        <div className="np-card">
          <strong>Next phases</strong>
          <p style={{ color: 'var(--np-muted)', marginTop: 8 }}>
            P2 identity &amp; RBAC · P3 sites &amp; SSL · P4 mail/DNS/databases ·
            P5 security stack · P6 migrations · P7 v1.0 GA.
          </p>
        </div>
      </div>
    </Shell>
  );
}
