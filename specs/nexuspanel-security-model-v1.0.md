> Source: normative specification — Batch 1 (foundation), imported 2026-11-05.
> Status: NORMATIVE. Changes require an ADR per the Engineering Constitution (§P.6).


## 1. Threat Model

### 1.1 Assets (ranked by impact)

| Asset | Impact if compromised | Category |
|---|---|---|
| Customer TLS private keys | Impersonation of customer sites | High |
| DKIM private keys | Email spoofing under customer domain | High |
| Panel admin credentials | Full server compromise | Critical |
| Customer database passwords | Cross-customer data access | High |
| Backups | Full exposure of all customer data | Critical |
| Audit log | Loss of forensic capability | High |
| Control-plane signing key | Arbitrary agent command execution | Critical |
| Agent's CA private key | Agent impersonation | Critical |

### 1.2 Adversaries (STRIDE summary)

| Adversary | Capability | Primary threat |
|---|---|---|
| Malicious authenticated customer | Panel access for their own account | Lateral movement, priv esc, resource exhaustion |
| Compromised customer account | Same as above, gained by credential theft | Spam relay, malware hosting, attack on other accounts |
| External attacker | No credentials | Panel vuln exploitation, credential stuffing |
| Malicious insider | Admin access | Data exfiltration, sabotage |
| Supply chain | Compromised dependency | Arbitrary code execution |

### 1.3 Attack surface

- Panel web UI + API (external)
- Customer-facing sites + email (external)
- Agent socket (local only)
- Managed services (config-only interface)
- Installer (local, sudo)

### 1.4 Trust boundaries

1. Browser ↔ Panel API (untrusted → semi-trusted)
2. Panel API ↔ Agent (semi-trusted → trusted)
3. Agent ↔ System (trusted → privileged)
4. Customer site ↔ Customer site (isolated)
5. Node ↔ Node (mTLS, future)

## 2. Controls Catalog

Each control is listed with: what, why, how, verification.

### C1 — Password policy
- **What:** Argon2id, min 12 chars, no complexity rules (NIST SP 800-63B).
- **Why:** Resist offline attacks; match modern guidance.
- **How:** `crypto/argon2` in NestJS with recommended params (m=64MiB, t=3, p=4); reject known-breached passwords via `HaveIBeenPwned` k-anonymity API (optional, admin-configurable).
- **Verification:** Unit test password hashing; integration test reject weak passwords.

### C2 — Two-factor authentication
- **What:** TOTP (RFC 6238), backup codes.
- **Why:** Second factor against credential theft.
- **How:** `otplib` for TOTP; backup codes generated 10× 16-char, Argon2id-hashed, encrypted at rest.
- **Verification:** Unit + E2E test 2FA flow.

### C3 — Session management
- **What:** Short-lived JWT (15min) + rotating refresh token (7d), bound to device fingerprint.
- **Why:** Limit impact of stolen tokens; detect reuse.
- **How:** Refresh token rotation with reuse detection; on reuse, revoke all sessions for user.
- **Verification:** Integration test reuse detection.

### C4 — API token scoping
- **What:** Opaque tokens, SHA-256 hashed at rest, scoped to `resource:action`.
- **Why:** Least privilege for automation.
- **How:** `PermissionGuard` checks each token scope against endpoint's required permissions.
- **Verification:** Integration test every endpoint rejects under-scoped tokens.

### C5 — Rate limiting
- **What:** Per-IP and per-token rate limits on all endpoints.
- **Why:** DDoS, brute force, abuse.
- **How:** Valkey-backed sliding window; documented per-endpoint limits; `Retry-After` header.
- **Verification:** Load test confirms limits trigger; integration test header presence.

### C6 — RBAC
- **What:** Roles → permission sets; enforced at API layer.
- **Why:** Prevent privilege escalation via UI manipulation.
- **How:** `@RequirePermission('site:create')` decorator on every controller method; `PermissionGuard` rejects before service layer.
- **Verification:** CI check that every controller method has a permission decorator.

### C7 — Account isolation
- **What:** Linux user, cgroup v2, per-site PHP-FPM pool, `open_basedir`.
- **Why:** Prevent cross-account file/process access.
- **How:** See §3.8 of v2.0.
- **Verification:** Integration test where account A cannot read/write/delete files in account B's home; cannot signal account B's processes; cannot exceed cgroup limits.

### C8 — Configuration injection prevention
- **What:** All template variables validated by schema; no shell interpolation.
- **Why:** Prevent template injection from user-supplied fields (domain names, aliases).
- **How:** All template variables typed; domain names match strict regex; paths resolve-confined; `exec.Command` only (never `exec.Command("sh", "-c", ...)`).
- **Verification:** Fuzz test template variables with injection payloads; integration test malicious domain name is rejected.

### C9 — Secrets at rest
- **What:** All secrets encrypted with age; master key in `/etc/nexuspanel/keys/` (root-owned, 0400).
- **Why:** Prevent plaintext secrets in DB or backups.
- **How:** `age` encryption in the service layer; decrypted only at point of use; never sent to UI.
- **Verification:** CI scans schema for any column containing `password`, `secret`, `key`, `token` — all must be `bytea` with `_enc` suffix; audit integration test confirms UI responses never contain plaintext secrets.

### C10 — Secrets in transit
- **What:** TLS 1.3 everywhere; mTLS between control plane and agent.
- **Why:** Prevent interception.
- **How:** Nginx with modern cipher suite; agent socket requires client cert.
- **Verification:** `testssl.sh` passes; integration test without mTLS cert fails.

### C11 — Audit chain
- **What:** Hash-chained audit log, tamper-evident.
- **Why:** Forensic integrity; accountability.
- **How:** Every privileged action writes to `audit_entries` with `prior_hash` + `this_hash`; `audit_chain_heads` singleton tracks head for O(1) append; verification walks the chain.
- **Verification:** Unit test hash computation; integration test that modifying a mid-chain entry breaks verification; periodic automated verification with alert on failure.

### C12 — Agent command signing
- **What:** Every command signed by control plane's Ed25519 key.
- **Why:** Prevent command injection if agent socket is compromised.
- **How:** Signature over `method || params || issued_at || expires_at`; `expires_at` max 60s in future; agent verifies before execution.
- **Verification:** Integration test with tampered command fails; unit test signature verification.

### C13 — Path confinement
- **What:** All file operations restricted to explicit path roots.
- **Why:** Prevent path traversal (e.g., `../../../etc/passwd`).
- **How:** Agent resolves paths against confined roots per operation type; rejects any resolved path outside.
- **Verification:** Fuzz test path traversal payloads; integration test all operations reject escape attempts.

### C14 — Session isolation across reseller domains
- **What:** When reseller custom domain is enabled, sessions are cookie-scoped per domain.
- **Why:** Prevent session leakage between resellers.
- **How:** Cookie `Domain` attribute set to the request's Host; session validation checks Host against `resellers.custom_domain`.
- **Verification:** Integration test session from reseller A's domain cannot access reseller B's domain.

### C15 — Backup encryption
- **What:** All backups encrypted with age before leaving the server.
- **Why:** Prevent backup exfiltration from S3 compromise.
- **How:** Age encryption at backup creation; decryption requires the installation's master key (which is not in the backup destination).
- **Verification:** Integration test backup artifact cannot be decrypted without master key; restore test confirms correct decryption.

### C16 — Fail2ban integration
- **What:** Login, API, and service-level jails.
- **Why:** Resist brute force.
- **How:** Jails configured for panel login, SSH, mail auth, web auth; ban duration and thresholds configurable; unban UI.
- **Verification:** Integration test 10 failed logins triggers ban; unban API works.

### C17 — ModSecurity WAF
- **What:** OWASP CRS at each customer site, per-site toggle.
- **Why:** Block common web attacks.
- **How:** CRS rules; per-site exclusions; paranoia level configurable.
- **Verification:** Integration test known attack payload is blocked; false-positive rate tracked.

### C18 — Malware scanning
- **What:** ClamAV scheduled + on-demand.
- **Why:** Detect hosted malware (protects customer sites and server reputation).
- **How:** Scheduled scan of `/home/`; quarantine with restore; quarantine UI.
- **Verification:** Integration test with known EICAR file.

### C19 — Dependency and supply chain
- **What:** SCA, SBOM, signed releases, pinned dependencies.
- **Why:** Prevent compromised dependency.
- **How:** Snyk/Dependabot daily; SBOM per release; release artifacts signed with cosign; lockfiles committed.
- **Verification:** CI fails on high-severity findings; release without signature rejected by auto-update.

### C20 — Panel self-update safety
- **What:** Signed updates, health-checked, auto-rollback.
- **Why:** Prevent compromised update from bricking the panel.
- **How:** Update manifest signed by project key; health checks post-update; rollback on failure.
- **Verification:** Integration test with failing update triggers rollback; tampered update rejected.

## 3. Secret Management Details

### 3.1 Master key

- Generated at install time: 256-bit random.
- Stored: `/etc/nexuspanel/keys/master.key`, mode 0400, owner root, group root.
- Access: read by the agent at startup; held in agent memory (encrypted, mlock'd); never written back.
- Rotation: `nexus rotate-master-key` command re-encrypts all secrets atomically with a new key.
- Backup: the master key must be backed up *offline* by the admin. Loss of master key = loss of all encrypted secrets.

### 3.2 Derived keys

Per-purpose keys derived via HKDF from master key: audit-signing, backup-encryption, totp, smtp-relay. This prevents a compromise of one purpose's key from affecting others, without multiplying the operational burden of managing separate master keys.

### 3.3 Secret format

All encrypted columns use:
```
bytea = version (1 byte) || nonce (12 bytes) || ciphertext
```
Version allows future algorithm rotation. Encryption: XChaCha20-Poly1305.

## 4. Audit Chain Construction

**Entry hash:**
```
this_hash = SHA-256(
  prior_hash (32 bytes)
  || occurred_at (RFC3339 UTC, 8 bytes packed)
  || actor_user_id (16 bytes; zeros if null)
  || operation (UTF-8)
  || canonical_json(parameters) (UTF-8)
  || outcome (UTF-8)
)
```

**Chain verification endpoint:** `POST /api/v1/audit/verify`
- Body: `{from_id, to_id}`
- Algorithm: fetch entries ordered by `occurred_at`, recompute each `this_hash`, verify `prior_hash` matches previous `this_hash`; verify first entry matches `audit_chain_heads` snapshot or an admin-provided known-good hash.
- Returns: `{verified: bool, broken_at: id?}`

**Periodic verification:** Cron job runs daily; on failure, alerts admin and emits `security.audit_chain_broken` event.

## 5. Isolation Profile Guarantees

| Profile | Guarantee | Tests |
|---|---|---|
| Standard | No cross-account filesystem read/write; no cross-account process signal; cgroup limits enforced; no cross-account network listening (except through shared Nginx) | Integration test suite |
| Enhanced | All of Standard + mount namespace isolation; PID namespace isolation; seccomp filter; restricted `/proc` visibility | Same suite + namespace tests |
| Container | All of Enhanced + full network namespace with isolated loopback; storage driver isolation | Full container test suite |
| Premium | Full VM isolation | Not tested in v1.0 (Delivery Advanced) |

## 6. Incident Response Playbooks (summary)

### 6.1 Suspected customer account compromise
1. Admin suspends account: `POST /api/v1/accounts/{id}/suspend`
2. Agent kills all processes, disables login.
3. Preserve state: snapshot filesystem + DB to evidence bucket.
4. Audit query: `GET /api/v1/audit?hosting_account_id={id}&since=...`
5. Notify customer with timeline.
6. Restore from verified backup; rotate all account secrets.

### 6.2 Agent compromise suspected
1. Stop agent: `systemctl stop nexuspanel-agent`
2. Panel enters read-only mode; sites continue.
3. Rotate signing keys; issue new agent cert.
4. Audit check: `POST /api/v1/audit/verify`
5. Compare agent-reported state vs. desired state; reconcile manually.
6. Restart agent with new keys; watch for drift events.

### 6.3 Master key compromise
1. Rotate master key immediately: `nexus rotate-master-key`
2. Invalidate all sessions: `nexus sessions revoke-all`
3. Rotate all agent signing keys.
4. Re-encrypt all backups with new key (old backups remain decryptable by old key; admin must decide to destroy or keep).
5. Audit any access during the suspected window.

## 7. Compliance Posture

- **GDPR:** Data export (per user/account) and deletion flows supported; audit log records data subject actions; DPA available to hosting providers.
- **SOC 2 (readiness, not certification):** Controls catalog (this document) maps to SOC 2 trust service criteria; evidence collection automated via audit chain; no formal certification in v1.0.
- **HIPAA:** Not a target; hosting providers with HIPAA obligations must run NexusPanel in a HIPAA-eligible configuration (admin responsibility).
- **PCI DSS:** NexusPanel does not store card data; hosting providers with PCI obligations handle card data in their applications, not in the panel.

---
