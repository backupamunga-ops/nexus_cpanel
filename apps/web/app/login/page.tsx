'use client';

import { FormEvent, useState } from 'react';
import { login } from '../../lib/api';

/**
 * M0 login — real users-table authentication (Argon2id C1, JWT + rotating
 * refresh C3). P2 replaces this with the full auth screen: TOTP prompt,
 * session list, password policy messaging — specs: API §4.1, controls C1–C3.
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
      await login(email, password);
      window.location.href = '/accounts';
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.');
      setBusy(false);
    }
  }

  return (
    <main style={{ display: 'grid', placeItems: 'center', minHeight: '100vh' }}>
      <form onSubmit={onSubmit} className="np-card" style={{ width: 360 }} aria-label="Sign in">
        <h1 className="np-title">Sign in to NexusPanel</h1>
        <p className="np-subtitle" style={{ marginBottom: 16 }}>
          Sessions are hash-locked: Argon2id passwords (C1), 15-minute tokens with
          rotating refresh bound to this device (C3).
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
