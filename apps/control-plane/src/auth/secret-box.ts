import { Injectable } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Symmetric encryption for panel secrets at rest (C9 seam — users.totp_secret_enc,
 * users.backup_codes_enc).
 *
 * The security model specifies age with a per-purpose HKDF key hierarchy
 * provisioned by the installer. That hierarchy needs the installer (P3);
 * until it exists, this box provides the same *properties* the schema already
 * commits to (security model §C9: ciphertext at rest, key outside the
 * database, decrypted only at point of use, never sent to the UI):
 *
 *   - AES-256-GCM (authenticated) with a random 96-bit IV per envelope
 *   - key: CP_SECRETS_KEY (base64, 32 bytes) or CP_SECRETS_KEY_PATH (file) —
 *     never a database column, never a source-controlled default
 *   - versioned binary envelope (`NXPB1` magic) so an age-based envelope can
 *     replace it later without ambiguity about what a column contains
 *
 * Missing key configuration is a VALID, safe state for boot (the panel runs
 * without 2FA enrollment); the first use fails loudly instead of silently
 * writing plaintext.
 */

const MAGIC = Buffer.from('NXPB1\0', 'utf8'); // 6 bytes
const IV_LEN = 12;
const TAG_LEN = 16;
const AAD = 'nexuspanel:secrets:v1';

@Injectable()
export class SecretBox {
  private readonly key: Buffer | null;

  /**
   * keyOverride is a unit-test seam; production always resolves from env/files.
   * `null` means explicitly unconfigured (test for the fail-closed path);
   * `undefined` resolves CP_SECRETS_KEY / CP_SECRETS_KEY_PATH.
   */
  constructor(keyOverride?: Buffer | null) {
    this.key = keyOverride === undefined ? SecretBox.resolveKey() : keyOverride;
  }

  get configured(): boolean {
    return this.key !== null;
  }

  private static resolveKey(): Buffer | null {
    const raw = process.env.CP_SECRETS_KEY;
    const path = process.env.CP_SECRETS_KEY_PATH;
    const decode = (value: string, source: string): Buffer | null => {
      const buf = Buffer.from(value.trim(), 'base64');
      if (buf.length !== 32) {
        throw new Error(
          `${source} must decode to exactly 32 bytes (base64 of the master secrets key)`,
        );
      }
      return buf;
    };
    if (raw) {
      return decode(raw, 'CP_SECRETS_KEY');
    }
    if (path) {
      return decode(readFileSync(path, 'utf8'), 'CP_SECRETS_KEY_PATH');
    }
    return null;
  }

  /** Encrypts to the NXPB1 envelope: magic ‖ iv(12) ‖ gcm-tag(16) ‖ ciphertext. */
  encrypt(plaintext: Buffer): Buffer {
    const key = this.requireKey();
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv).setAAD(Buffer.from(AAD));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([MAGIC, iv, tag, ct]);
  }

  decrypt(envelope: Buffer): Buffer {
    const key = this.requireKey();
    if (!Buffer.isBuffer(envelope) || envelope.length < MAGIC.length + IV_LEN + TAG_LEN) {
      throw new Error('secret envelope is truncated or not an NXPB1 box');
    }
    if (!envelope.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw new Error('secret envelope has an unknown format (expected NXPB1)');
    }
    const iv = envelope.subarray(MAGIC.length, MAGIC.length + IV_LEN);
    const tag = envelope.subarray(MAGIC.length + IV_LEN, MAGIC.length + IV_LEN + TAG_LEN);
    const ct = envelope.subarray(MAGIC.length + IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv).setAAD(Buffer.from(AAD));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }

  private requireKey(): Buffer {
    if (!this.key) {
      throw new Error(
        'secrets key not configured — set CP_SECRETS_KEY (base64, 32 bytes) or CP_SECRETS_KEY_PATH',
      );
    }
    return this.key;
  }
}
