'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { api, getUser, patchStoredUser, SessionUser } from '../../lib/api';
import Shell from '../shell';

/**
 * Security settings (C2 lifecycle, API spec §4.1 /auth/2fa/*).
 *
 * States:
 *   disabled   → [Enable 2FA] → POST /auth/2fa/setup
 *   enrolling  → QR + base32 secret + code input → POST /auth/2fa/verify
 *   backup     → ten one-time codes shown EXACTLY once → acknowledged
 *   enabled    → regenerate backup codes (password), disable (password)
 *
 * Every state change re-reads FRESH rows server-side; the UI only mirrors
 * the stored user snapshot (patched locally, authoritative on next login).
 */

interface SetupResponse {
  secret: string;
  otpauth_uri: string;
}

type Phase =
  | { kind: 'idle' }
  | { kind: 'enrolling'; secret: string; otpauth_uri: string }
  | { kind: 'backup'; codes: string[] };

function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text);
  }
  // Fallback for non-secure contexts.
  const el = document.createElement('textarea');
  el.value = text;
  document.body.appendChild(el);
  el.select();
  document.execCommand('copy');
  document.body.removeChild(el);
  return Promise.resolve();
}

export default function SettingsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const codeRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setUser(getUser());
    if (!getUser()) {
      window.location.href = '/login';
    }
  }, []);

  useEffect(() => {
    if (phase.kind === 'enrolling') {
      codeRef.current?.focus();
    }
  }, [phase]);

  const startEnrollment = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const setup = await api<SetupResponse>('/auth/2fa/setup', { method: 'POST' });
      setQr(await QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 180 }));
      setPhase({ kind: 'enrolling', secret: setup.secret, otpauth_uri: setup.otpauth_uri });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'setup failed');
    } finally {
      setBusy(false);
    }
  }, []);

  async function verifyEnrollment(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { backup_codes } = await api<{ backup_codes: string[] }>('/auth/2fa/verify', {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      setPhase({ kind: 'backup', codes: backup_codes });
      setUser(patchStoredUser({ two_factor_enabled: true }));
      setCode('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'verification failed');
    } finally {
      setBusy(false);
    }
  }

  async function regenerateCodes(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { backup_codes } = await api<{ backup_codes: string[] }>('/auth/2fa/backup-codes', {
        headers: { 'X-Confirm-Password': password },
      });
      setPhase({ kind: 'backup', codes: backup_codes });
      setPassword('');
      setMessage('New backup codes generated — the previous set no longer works.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'regeneration failed');
    } finally {
      setBusy(false);
    }
  }

  async function disable2fa(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api('/auth/2fa/disable', {
        method: 'POST',
        body: JSON.stringify({ password }),
      });
      setUser(patchStoredUser({ two_factor_enabled: false }));
      setPassword('');
      setPhase({ kind: 'idle' });
      setMessage('Two-factor authentication disabled.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'disable failed');
    } finally {
      setBusy(false);
    }
  }

  function finishBackup() {
    setPhase({ kind: 'idle' });
    setMessage(null);
  }

  const enabled = user?.two_factor_enabled ?? false;
  const showingBackup = phase.kind === 'backup';

  return (
    <Shell active="/settings" user={user}>
      <h1 className="np-title">Security settings</h1>
      <p className="np-subtitle">
        Two-factor authentication (C2) for your login. Secrets are AES-256-GCM
        encrypted with a key stored outside the database; every change is
        hash-chained into the audit log.
      </p>

      {message && (
        <p role="status" style={{ color: 'var(--np-muted)', marginTop: 12 }}>
          {message}
        </p>
      )}
      {error && (
        <p role="alert" style={{ color: 'var(--np-danger)', marginTop: 12 }}>
          {error}
        </p>
      )}

      {/* ── one-time backup-code view ─────────────────────────────── */}
      {showingBackup && (
        <div className="np-card" style={{ marginTop: 20, maxWidth: 520 }}>
          <h2 style={{ marginTop: 0 }}>Save your backup codes</h2>
          <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>
            Each code works once at the sign-in prompt, then burns. They are
            shown <strong>only this once</strong> — store them now.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontFamily: 'monospace' }}>
            {phase.codes.map((c) => (
              <code key={c}>{c}</code>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
            <button
              className="np-button"
              onClick={() => void copyText(phase.codes.join('\n'))}
              type="button"
            >
              Copy all
            </button>
            <button className="np-button" onClick={finishBackup} type="button">
              I&apos;ve saved them
            </button>
          </div>
        </div>
      )}

      {/* ── 2FA section ───────────────────────────────────────────── */}
      {!showingBackup && (
        <div className="np-card" style={{ marginTop: 20, maxWidth: 520 }}>
          <h2 style={{ marginTop: 0 }}>
            Two-factor authentication{' '}
            <span className="np-badge">{enabled ? 'enabled' : 'disabled'}</span>
          </h2>

          {phase.kind === 'enrolling' ? (
            <>
              <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>
                Scan the QR code with your authenticator app (or paste the
                secret), then enter the current 6-digit code.
              </p>
              <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                {qr && (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img src={qr} alt="TOTP enrollment QR code" width={180} height={180} />
                )}
                <div style={{ fontSize: 12 }}>
                  <div style={{ color: 'var(--np-muted)', marginBottom: 4 }}>Secret (base32):</div>
                  <code style={{ wordBreak: 'break-all' }}>{phase.secret}</code>{' '}
                  <button
                    className="np-button"
                    style={{ padding: '2px 8px', fontSize: 11 }}
                    onClick={() => void copyText(phase.secret)}
                    type="button"
                  >
                    Copy
                  </button>
                </div>
              </div>
              <form onSubmit={verifyEnrollment} style={{ marginTop: 16 }}>
                <label htmlFor="totp-code" style={{ display: 'block', marginBottom: 4 }}>
                  Verification code
                </label>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    id="totp-code"
                    ref={codeRef}
                    className="np-input"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    required
                    style={{ maxWidth: 160, letterSpacing: 2 }}
                  />
                  <button className="np-button" type="submit" disabled={busy}>
                    {busy ? 'Verifying…' : 'Verify & enable'}
                  </button>
                  <button
                    className="np-button"
                    type="button"
                    disabled={busy}
                    onClick={() => setPhase({ kind: 'idle' })}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </>
          ) : enabled ? (
            <>
              <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>
                Sign-ins require a 6-digit authenticator code (or a backup code)
                after your password. Five wrong attempts lock the account for
                15 minutes — the second factor is protected too.
              </p>
              <form onSubmit={regenerateCodes} style={{ marginTop: 12 }}>
                <label htmlFor="regen-pw" style={{ display: 'block', marginBottom: 4 }}>
                  Regenerate backup codes — confirm your password
                </label>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    id="regen-pw"
                    className="np-input"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                  <button className="np-button" type="submit" disabled={busy}>
                    Regenerate
                  </button>
                </div>
              </form>
              <form onSubmit={disable2fa} style={{ marginTop: 16, borderTop: '1px solid var(--np-border)', paddingTop: 16 }}>
                <label htmlFor="disable-pw" style={{ display: 'block', marginBottom: 4 }}>
                  Disable 2FA — confirm your password
                </label>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    id="disable-pw"
                    className="np-input"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                  <button className="np-button" type="submit" disabled={busy}>
                    {busy ? 'Working…' : 'Disable'}
                  </button>
                </div>
              </form>
            </>
          ) : (
            <>
              <p style={{ color: 'var(--np-muted)', fontSize: 13 }}>
                Add a time-based second factor (RFC 6238 TOTP). You&apos;ll get
                ten one-time backup codes for when you lose the device.
              </p>
              <button className="np-button" onClick={() => void startEnrollment()} disabled={busy} type="button">
                {busy ? 'Preparing…' : 'Enable two-factor authentication'}
              </button>
            </>
          )}
        </div>
      )}
    </Shell>
  );
}
