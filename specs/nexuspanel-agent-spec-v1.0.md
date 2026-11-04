> Source: normative specification — Batch 1 (foundation), imported 2026-11-05.
> Status: NORMATIVE. Changes require an ADR per the Engineering Constitution (§P.6).


## 1. Overview

The NexusPanel Agent is a single Go binary running as a systemd service on every node. It is the only process with privileged system access. The control plane (NestJS) never runs as root. All system mutations pass through the agent as typed, signed commands.

## 2. Process Model

- Binary: `/usr/local/bin/nexuspanel-agent`
- systemd unit: `nexuspanel-agent.service`
- Runs as user `nexusagent`, group `nexusagent`
- Capabilities: `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`, `CAP_SYS_ADMIN` (for cgroups + namespaces), `CAP_NET_BIND_SERVICE`
- Unix socket: `/run/nexuspanel/agent.sock`, mode `0600`, owned `nexusagent:nexusagent`
- Metrics endpoint: `:9101/metrics` (Prometheus, localhost only)
- Health endpoint: `:9101/health` (localhost only)

## 3. Communication Protocol

**Transport:** Unix socket with mTLS. The control plane presents a client certificate signed by the installation's CA; the agent verifies it. Every command body is additionally signed with the control plane's Ed25519 key.

**Message format:** JSON-RPC 2.0.

**Envelope:**
```json
{
  "jsonrpc": "2.0",
  "id": "req_<uuidv7>",
  "method": "<category>.<operation>",
  "params": { ... },
  "issued_at": "2026-11-15T12:00:00Z",
  "expires_at": "2026-11-15T12:01:00Z",
  "signature": "base64(ed25519(sign(method || params || issued_at || expires_at)))"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "req_<uuidv7>",
  "result": { ... },
  "error": null,
  "audit": { "entry_id": "...", "prior_hash": "...", "this_hash": "..." }
}
```

**Error codes:**
- `-32600` Invalid request (malformed)
- `-32601` Method not found
- `-32602` Invalid params
- `-32603` Internal error
- `-32000` Permission denied (method not in allowlist or signed by unknown key)
- `-32001` Precondition failed (e.g., service not running)
- `-32002` Conflict (e.g., resource exists)
- `-32003` Timeout
- `-32004` Quota exceeded
- `-32005` Control plane unreachable (write rejected)

## 4. Command Allowlist (Complete)

Every method below is a typed operation. There is **no `exec()` primitive**. Additional methods require an amendment to this document.

### 4.1 `account.*`
| Method | Params | Returns | Notes |
|---|---|---|---|
| `account.create` | `username, package_id, quotas, isolation_profile, homedir` | `{uid, gid, homedir}` | Idempotent by username |
| `account.modify` | `username, quotas?, isolation_profile?` | `{status}` | — |
| `account.suspend` | `username, reason` | `{status}` | Kills processes, disables login |
| `account.resume` | `username` | `{status}` | — |
| `account.delete` | `username, preserve_files: bool` | `{status}` | Async if `preserve_files` |
| `account.quota` | `username, quotas` | `{applied}` | cgroup v2 |
| `account.usage` | `username` | `{cpu_ns, mem_bytes, disk_bytes, procs, ...}` | Read-only |
| `account.list` | — | `[{username, status, uid}]` | Reconcile helper |

### 4.2 `isolation.*`
| Method | Params | Returns |
|---|---|---|
| `isolation.provision` | `username, profile` | `{profile, details}` |
| `isolation.apply_limits` | `username, limits` | `{applied}` |
| `isolation.read_usage` | `username` | `{usage}` |
| `isolation.destroy` | `username` | `{status}` |

### 4.3 `filesystem.*`
| Method | Params | Notes |
|---|---|---|
| `filesystem.mkdir` | `username, path, mode, owner` | Path confined to `/home/<username>/` |
| `filesystem.chown` | `username, path, uid, gid` | — |
| `filesystem.chmod` | `username, path, mode` | — |
| `filesystem.delete` | `username, path, to_trash: bool` | Trash = move to `/home/<username>/.nexus-trash/` |
| `filesystem.trash_purge` | `username, before_date` | — |
| `filesystem.quota` | `username, quota_mb, inode_quota` | Filesystem quota |
| `filesystem.usage` | `username` | `{bytes, inodes}` |

*(File content operations — upload, download, edit — go through the control plane's file service, not the agent. The agent handles metadata and permission ops.)*

### 4.4 `service.*`
| Method | Params | Notes |
|---|---|---|
| `service.start` | `name` | Allowlist of known services |
| `service.stop` | `name` | — |
| `service.restart` | `name` | — |
| `service.reload` | `name` | Graceful reload |
| `service.status` | `name` | `{status, uptime, pid}` |
| `service.list` | — | All managed services |

Allowed service names: `nginx`, `apache2`, `php8.1-fpm` … `php8.4-fpm`, `postfix`, `dovecot`, `powerdns`, `mariadb`, `fail2ban`, `nexuspanel-agent`, `nexuspanel-api`.

### 4.5 `config.*` (Configuration Engine)
| Method | Params | Notes |
|---|---|---|
| `config.render` | `target_type, target_id, template, variables` | Returns rendered string; no apply |
| `config.validate` | `target_type, content` | Syntax + semantic check |
| `config.apply` | `target_type, target_id, content, transaction_id` | Staging write + atomic swap + health check + rollback |
| `config.rollback` | `transaction_id` | Reverts to prior version |
| `config.drift_check` | `target_type, target_id` | Returns `{matches, expected_hash, actual_hash}` |
| `config.list_active` | `target_type, target_id` | Reads current active version |

### 4.6 `php.*`
| Method | Params |
|---|---|
| `php.install_version` | `version` |
| `php.create_pool` | `username, domain, version, config` |
| `php.modify_pool` | `username, domain, config` |
| `php.delete_pool` | `username, domain` |
| `php.list_versions` | — |

### 4.7 `nginx.*`
| Method | Params |
|---|---|
| `nginx.test` | — |
| `nginx.reload` | — |
| `nginx.apply_vhost` | `domain, content` (via `config.apply`) |
| `nginx.remove_vhost` | `domain` |

### 4.8 `mail.*`
| Method | Params |
|---|---|
| `mail.create_domain` | `domain` |
| `mail.delete_domain` | `domain` |
| `mail.create_mailbox` | `email, password_hash, quota_mb` |
| `mail.modify_mailbox` | `email, quota_mb?, password_hash?` |
| `mail.delete_mailbox` | `email, preserve_mail: bool` |
| `mail.create_alias` | `source, destination` |
| `mail.delete_alias` | `source` |
| `mail.create_autoresponder` | `email, subject, body, starts_at, ends_at` |
| `mail.delete_autoresponder` | `email` |
| `mail.apply_dkim` | `domain, selector, private_key_pem` |
| `mail.reload` | — |
| `mail.queue_list` | — |
| `mail.queue_flush` | `queue_id?` |
| `mail.queue_retry` | `message_id` |

### 4.9 `dns.*`
| Method | Params |
|---|---|
| `dns.create_zone` | `zone, records` |
| `dns.delete_zone` | `zone` |
| `dns.apply_records` | `zone, records[]` (full replace) |
| `dns.reload` | — |
| `dns.enable_dnssec` | `zone` |
| `dns.disable_dnssec` | `zone` |
| `dns.axfr_export` | `zone` |
| `dns.zone_check` | `zone` |

### 4.10 `database.*`
| Method | Params |
|---|---|
| `database.create` | `engine, name, user, password_hash, host` |
| `database.delete` | `engine, name, user` |
| `database.create_user` | `engine, user, password_hash, host` |
| `database.grant` | `engine, user, database, privileges` |
| `database.revoke` | `engine, user, database` |
| `database.dump` | `engine, name, output_path` |
| `database.restore` | `engine, name, input_path` |

### 4.11 `ssl.*`
| Method | Params |
|---|---|
| `ssl.issue_acme` | `domain, san[], challenge_type (http01|dns01), email` |
| `ssl.install_cert` | `domain, cert_pem, key_pem` |
| `ssl.renew` | `domain` |
| `ssl.revoke` | `domain` |
| `ssl.list` | — |

### 4.12 `firewall.*`
| Method | Params |
|---|---|
| `firewall.add_rule` | `rule` (nftables/ufw payload) |
| `firewall.remove_rule` | `rule_id` |
| `firewall.list_rules` | — |
| `firewall.apply` | — |

### 4.13 `fail2ban.*`
| Method | Params |
|---|---|
| `fail2ban.list_jails` | — |
| `fail2ban.set_jail` | `name, config` |
| `fail2ban.ban` | `ip, jail, duration` |
| `fail2ban.unban` | `ip, jail` |
| `fail2ban.status` | `jail?` |

### 4.14 `backup.*`
| Method | Params |
|---|---|
| `backup.create` | `scope, scope_id, destination, path` |
| `backup.restore_preview` | `artifact_path` |
| `backup.restore` | `artifact_path, scope, scope_id, dry_run: bool` |
| `backup.verify` | `artifact_path, checksum` |
| `backup.purge` | `before_date` |

### 4.15 `system.*`
| Method | Params |
|---|---|
| `system.health` | — |
| `system.metrics` | — |
| `system.info` | — (OS, kernel, resources) |
| `system.update_panel` | `manifest_url, expected_sha256` |
| `system.drift_check_all` | — |

## 5. Handshake and Key Management

- Installation generates: CA keypair, control-plane signing keypair (Ed25519), agent client certificate.
- Control plane holds: CA private key (encrypted), its own Ed25519 signing key (encrypted). The CA private key is only needed for agent cert issuance — it is not used for command signing.
- Agent holds: its own certificate + key, the CA public key (for verifying control-plane mTLS), the control-plane Ed25519 public key (for verifying command signatures).
- Key rotation: the installation can rotate the signing key; agents accept a window of 2 keys (current + previous) during rotation, configurable window.
- If signature verification fails on 5 consecutive commands from a given connection, the agent closes the socket and logs a security event.

## 6. WAL (Write-Ahead Log)

When the control plane is unreachable, the agent:
- Continues to serve read methods (`*.status`, `*.list`, `*.usage`, `*.health`).
- Rejects all mutation methods with `-32005`.
- Queues audit entries in `/var/lib/nexuspanel-agent/wal/` (one file per entry, fsync'd).
- Retries control-plane connection every 30s with backoff.
- On reconnection, drains WAL in order; control plane acknowledges each entry idempotently.
- WAL is capped at 100,000 entries; on overflow, oldest are dropped with a `wal_dropped` event emitted.

## 7. Drift Detection

- Runs every 15 minutes (configurable per node) via `system.drift_check_all`.
- For each managed config, compares `sha256(actual_on_disk)` against `config_versions.content` hash for the active version.
- Emits `drift_events` rows through the control plane.
- **Does not auto-reconcile.** Admins must approve reconciliation via `config.apply` with the current active version.
- If a drift is on a security-critical file (`/etc/sudoers`, `/etc/passwd` outside managed accounts), the agent emits a `security.drift_alert` event immediately.

## 8. Failure Modes and Recovery

| Failure | Behavior |
|---|---|
| Control plane unreachable | Read-only mode; sites continue serving; panel actions unavailable |
| Config apply fails validation | Rollback to prior version; audit failure; alert |
| Config apply succeeds, health check fails | Automatic rollback; audit failure; alert |
| Config apply succeeds, health check passes, service crashes within 60s | Automatic rollback; audit failure; alert |
| Agent crashes mid-operation | systemd restarts; on startup, WAL drained; incomplete operations reported for reconciliation |
| Disk full | Mutations rejected with `-32004`; reads continue; alert |
| Signature verification fails | Connection closed; security event logged; alert |
| Node agent version mismatch with control plane | Compatibility check on every connection; incompatible versions refuse non-read commands with clear error |

## 9. Versioning

- Agent and control plane each have a SemVer.
- Compatibility: agent supports control plane versions within ±1 MINOR of its own.
- Mismatch beyond that range: agent accepts read-only methods; mutations rejected with a `version_mismatch` error.
- This allows orchestrated rolling upgrades without downtime.

---
