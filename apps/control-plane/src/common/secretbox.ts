import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';

/**
 * SecretBox — secrets at rest for the panel database (ADR-0009).
 *
 * The schema marks secret columns `*_enc bytea` with "age-encrypted" in the
 * comments (certificates, smtp relay credentials, webhook secrets, backup
 * destinations). Age's recipient-model (file-based identities, per-file
 * stanzas) targets offline file exchange; the panel's actual threat model
 * is "database row exfiltration" — a single key held by the control plane,
 * authenticated encryption, versioned envelopes. AES-256-GCM with a
 * scrypt-derived key delivers exactly that with zero new dependencies.
 *
 * Envelope: `v1:<iv_b64>:<tag_b64>:<ciphertext_b64>` — the version prefix
 * makes future re-encryption (age, key rotation) a readable migration, not
 * an archaeology project.
 *
 * Key policy (fail-closed): PANEL_SECRET_KEY is required — 32+ bytes of
 * entropy, UTF-8 or base64. A missing key THROWS: silently writing secrets
 * encrypted under an ephemeral or default key would be worse than refusing
 * to start. `deriveKeyForTests` exists so test suites use a fixed key
 * without env plumbing.
 */

const CURRENT_VERSION = 'v1';
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 32 };

export class SecretBox {
  private readonly kek: Buffer;

  constructor(secretKey: string) {
    this.kek = deriveKek(secretKey);
  }

  /** Encrypts plaintext into the versioned envelope. */
  encrypt(plaintext: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.kek, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [
      CURRENT_VERSION,
      iv.toString('base64'),
      tag.toString('base64'),
      ct.toString('base64'),
    ].join(':');
  }

  /** Decrypts a versioned envelope. Unknown versions fail loudly. */
  decrypt(envelope: string): string {
    const parts = envelope.split(':');
    if (parts.length !== 4 || parts[0] !== CURRENT_VERSION) {
      throw new Error(`secretbox: unsupported envelope (want ${CURRENT_VERSION}:iv:tag:ct)`);
    }
    const [, ivB64, tagB64, ctB64] = parts;
    const decipher = createDecipheriv('aes-256-gcm', this.kek, Buffer.from(ivB64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const pt = Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]);
    return pt.toString('utf8');
  }
}

/** The process-wide box; constructed from env (fail-closed on first use). */
let box: SecretBox | null = null;

export function getSecretBox(): SecretBox {
  if (!box) {
    const key = process.env.PANEL_SECRET_KEY;
    if (!key) {
      throw new Error(
        'PANEL_SECRET_KEY is not set — refusing to encrypt or decrypt secrets at rest. ' +
          'Generate one with: openssl rand -base64 48',
      );
    }
    box = new SecretBox(key);
  }
  return box;
}

/** Test seam: a deterministic box for spec suites. */
export function deriveKeyForTests(): SecretBox {
  return new SecretBox('nexuspanel-test-secret-key-do-not-use-in-production');
}

function deriveKek(secret: string): Buffer {
  let material: Buffer;
  const trimmed = secret.trim();
  try {
    const decoded = Buffer.from(trimmed, 'base64');
    // Accept base64 when it round-trips to ≥ 32 bytes of entropy.
    if (decoded.length >= 32 && decoded.toString('base64').replace(/=+$/, '') === trimmed.replace(/=+$/, '')) {
      material = decoded;
    } else {
      material = Buffer.from(trimmed, 'utf8');
    }
  } catch {
    material = Buffer.from(trimmed, 'utf8');
  }
  if (material.length < 32) {
    throw new Error('PANEL_SECRET_KEY must provide at least 32 bytes of entropy');
  }
  // Salt is a fixed application constant: the input is already high-entropy
  // (unlike a password), so scrypt's KDF role here is key extraction.
  return scryptSync(material, 'nexuspanel/secretbox/v1', SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
  });
}
