import { describe, it, expect } from '@jest/globals';
import * as crypto from 'node:crypto';
import {
  base32Decode,
  base32Encode,
  generateTotpSecret,
  otpauthUri,
  totpAt,
  verifyTotp,
  VERIFICATION_WINDOW,
} from './totp';

/**
 * RFC 6238 Appendix B reference vectors (secret = ASCII "12345678901234567890",
 * HMAC-SHA-1). The RFC publishes 8-digit values; the 6-digit panel code is the
 * final six digits — these expectations were derived from the RFC table, not
 * from this implementation (no circularity).
 */
const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890', 'ascii'));

const RFC_VECTORS: Array<[number, string]> = [
  [59, '287082'],
  [1_111_111_109, '081804'],
  [1_111_111_111, '050471'],
  [1_234_567_890, '005924'],
  [2_000_000_000, '279037'],
  [20_000_000_000, '353130'],
];

describe('totp (RFC 6238, C2)', () => {
  it('matches every RFC 6238 Appendix B SHA-1 vector', () => {
    for (const [unix, code] of RFC_VECTORS) {
      expect(totpAt(RFC_SECRET, unix)).toBe(code);
    }
  });

  it('verifies a current code and tolerates ±1 step of drift', () => {
    const secret = generateTotpSecret();
    const nowUnix = 1_700_000_000;
    expect(verifyTotp(secret, totpAt(secret, nowUnix)!, { nowUnix }).valid).toBe(true);
    expect(verifyTotp(secret, totpAt(secret, nowUnix - 30)!, { nowUnix }).valid).toBe(true);
    expect(verifyTotp(secret, totpAt(secret, nowUnix + 30)!, { nowUnix }).valid).toBe(true);
    // Outside the ±VERIFICATION_WINDOW drift the code must fail.
    expect(verifyTotp(secret, totpAt(secret, nowUnix - 30 * (VERIFICATION_WINDOW + 1))!, { nowUnix }).valid).toBe(
      false,
    );
  });

  it('rejects malformed codes and malformed secrets (fail-closed)', () => {
    const secret = generateTotpSecret();
    const nowUnix = 1_700_000_000;
    for (const bad of ['', '12345', '1234567', 'abcdef', '1234567 ', 12_345_6 as unknown as string, null as unknown as string]) {
      expect(verifyTotp(secret, bad, { nowUnix }).valid).toBe(false);
    }
    for (const badSecret of ['', '!!!not-base32!!!', '1']) {
      expect(verifyTotp(badSecret, '123456', { nowUnix }).valid).toBe(false);
    }
  });

  it('enforces the replay guard: steps at or below lastStep are refused', () => {
    const secret = generateTotpSecret();
    const nowUnix = 1_700_000_000;
    const step = Math.floor(nowUnix / 30);
    // The current-step code verifies.
    const first = verifyTotp(secret, totpAt(secret, nowUnix)!, { nowUnix });
    expect(first.valid).toBe(true);
    // Replay with lastStep = matched step → refused even though crypto-valid.
    expect(verifyTotp(secret, totpAt(secret, nowUnix)!, { nowUnix, lastStep: first.step }).valid).toBe(false);
    // A drifted code from the PREVIOUS step is refused once that step is consumed.
    expect(
      verifyTotp(secret, totpAt(secret, nowUnix - 30)!, { nowUnix, lastStep: step - 1 }).valid,
    ).toBe(false);
    // A FUTURE step (above lastStep) still verifies.
    expect(verifyTotp(secret, totpAt(secret, nowUnix + 30)!, { nowUnix, lastStep: step - 1 }).valid).toBe(true);
  });

  it('base32 round-trips and rejects corrupt input', () => {
    for (const buf of [Buffer.from([0]), Buffer.from('hello world'), crypto.randomBytes(20)]) {
      expect(base32Decode(base32Encode(buf))!.equals(buf)).toBe(true);
    }
    expect(base32Decode('abc1!')).toBeNull(); // 1 and ! are not in the RFC 4648 alphabet
    expect(base32Decode('')).toBeNull();
  });

  it('otpauth URIs carry issuer, algorithm and parameters', () => {
    const uri = otpauthUri('admin@example.com', 'JBSWY3DPEHPK3PXP');
    expect(uri.startsWith('otpauth://totp/NexusPanel:admin%40example.com?')).toBe(true);
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(uri).toContain('issuer=NexusPanel');
    expect(uri).toContain('algorithm=SHA1');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });

  it('generated secrets are 160-bit and unique', () => {
    const secrets = new Set(Array.from({ length: 50 }, () => generateTotpSecret()));
    expect(secrets.size).toBe(50);
    expect(base32Decode([...secrets][0]!)!.length).toBe(20);
  });
});
