'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';
import { login, TotpChallengeError } from '../../lib/api';

/**
 * P2 login — real users-table authentication (Argon2id C1, JWT + rotating
 * refresh C3) with the C2 second-factor challenge: when the backend answers
 * `totp code required` the form unfolds a 6-digit input (autofocused,
 * one-time-code autocomplete so OS keychain suggestions work) and resubmits
 * with the code. Backup codes are accepted in the same field — the backend
 * routes 6-digit input to TOTP and anything else to the backup path.
 */
export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [challenge, setChallenge] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const totpRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (challenge) {
      totpRef.current?.focus();
    }
  }, [challenge]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password, challenge ? totp : undefined);
      window.location.href = '/accounts';
    } catch (err) {
      if (err instanceof TotpChallengeError) {
        setChallenge(true);
        setError('Two-factor authentication is enabled for this account. Enter a code from your authenticator app (or a backup code).');
      } else {
        setError(err instanceof Error ? err.message : 'Login failed.');
      }
      setBusy(false);
    }
  }

  return (
    <main style={{ display: 'grid', placeItems: 'center', minHeight: '100vh' }}>
      <form onSubmit={onSubmit} className="np-card" style={{ width: 360 }} aria-label="Sign in">
        <h1 className="np-title">Sign in to NexusPanel</h1>
        <p className="np-subtitle" style={{ marginBottom: 16 }}>
          Sessions are hash-locked: Argon2id passwords (C1), 15-minute tokens with
          rotating refresh bound to this device (C3). The refresh secret lives in
          an httpOnly cookie — page scripts never see it.
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
        {challenge && (
          <>
            <label htmlFor="totp" style={{ display: 'block', margin: '12px 0 4px' }}>
              Two-factor code
            </label>
            <input
              id="totp"
              ref={totpRef}
              className="np-input"
              type="text"
              inputMode="numeric"
              required
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              autoComplete="one-time-code"
              aria-describedby="totp-hint"
              style={{ letterSpacing: 2 }}
            />
            <p id="totp-hint" style={{ color: 'var(--np-muted)', fontSize: 12, marginTop: 4 }}>
              6-digit authenticator code or a backup code.
            </p>
          </>
        )}
        {error && (
          <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>
            {error}
          </p>
        )}
        <button className="np-button" type="submit" disabled={busy} style={{ marginTop: 16, width: '100%' }}>
          {busy ? 'Signing in…' : challenge ? 'Verify and sign in' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
