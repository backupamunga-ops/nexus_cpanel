'use client';

import { FormEvent, useState } from 'react';

/**
 * M0 login (dev bootstrap admin from DEV_ADMIN_EMAIL/DEV_ADMIN_PASSWORD).
 * P2 replaces this with the full auth screen: TOTP prompt, session list,
 * password policy messaging — specs: API §4.1, controls C1–C3.
 */
export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const problem = await res.json().catch(() => null);
        setError(problem?.detail ?? 'Login failed.');
        return;
      }
      localStorage.setItem('nexuspanel_session', JSON.stringify(await res.json()));
      window.location.href = '/';
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ display: 'grid', placeItems: 'center', minHeight: '100vh' }}>
      <form onSubmit={onSubmit} className="np-card" style={{ width: 360 }} aria-label="Sign in">
        <h1 className="np-title">Sign in to NexusPanel</h1>
        <p className="np-subtitle" style={{ marginBottom: 16 }}>
          Development build — Argon2-class hashing enforced (C1).
        </p>
        <label htmlFor="email" style={{ display: 'block', marginBottom: 4 }}>
          Email
        </label>
        <input
          id="email"
          className="np-input"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="username"
        />
        <label htmlFor="password" style={{ display: 'block', margin: '12px 0 4px' }}>
          Password
        </label>
        <input
          id="password"
          className="np-input"
          type="password"
          required
          minLength={12}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />
        {error && (
          <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>
            {error}
          </p>
        )}
        <button className="np-button" type="submit" disabled={busy} style={{ marginTop: 16, width: '100%' }}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
