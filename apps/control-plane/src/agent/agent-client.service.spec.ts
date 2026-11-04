import * as crypto from 'node:crypto';
import { AgentClientService } from './agent-client.service';

/**
 * Contract tests for the signature envelope: what the agent's auth package
 * verifies must be byte-identical to what this client produces.
 */
describe('AgentClientService signature envelope', () => {
  it('signature input is method || raw_params || issued_at || expires_at', () => {
    const rawParams = Buffer.from(JSON.stringify({ username: 'alice' }), 'utf8');
    const issued = '2026-11-05T12:00:00Z';
    const expires = '2026-11-05T12:00:30Z';
    const input = AgentClientService.signatureInput('account.create', rawParams, issued, expires);
    const want = Buffer.concat([
      Buffer.from('account.create', 'utf8'),
      rawParams,
      Buffer.from(issued, 'utf8'),
      Buffer.from(expires, 'utf8'),
    ]);
    expect(input.equals(want)).toBe(true);
  });

  it('produces a valid Ed25519 signature an agent would accept', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const method = 'system.health';
    const rawParams = Buffer.from('{}', 'utf8');
    const issued = '2026-11-05T12:00:00Z';
    const expires = '2026-11-05T12:00:45Z';

    const input = AgentClientService.signatureInput(method, rawParams, issued, expires);
    const sig = crypto.sign(null, input, privateKey);
    const ok = crypto.verify(null, input, publicKey, sig);
    expect(ok).toBe(true);

    // Tamper the input: verification must fail.
    const tampered = Buffer.from(input);
    tampered[0] = tampered[0] ^ 0xff;
    expect(crypto.verify(null, tampered, publicKey, sig)).toBe(false);
  });
});
