> Source: normative specification — Batch 2 (interfaces), imported 2026-11-05.
> Status: NORMATIVE. Changes require an ADR per the Engineering Constitution (§P.6).


## 1. Purpose and Status

This document specifies the **design contract** for the NexusPanel REST API. It is the source from which:

- NestJS controllers are built.
- The generated OpenAPI 3.1 spec (`nexuspanel-openapi-v2.0.yaml`) is produced at build time.
- The CLI (`nexus`) and its SDK bindings are generated.
- The frontend's typed API client is generated.

The generated OpenAPI YAML is a **build artifact** and is not hand-edited. If the YAML and this document disagree, this document wins and the discrepancy is a bug.

## 2. Global Conventions

### 2.1 Base URL and Versioning

```
Production:  https://<panel-host>/api/v1
```

- `v1` is stable. Breaking changes require `v2` (per §9.1 of v2.0).
- Deprecation policy: an endpoint is deprecated for at least 2 MINOR versions before removal; `Sunset` and `Deprecation` headers are set on deprecated endpoints.
- All requests and responses are `application/json; charset=utf-8` unless explicitly noted (file upload/download endpoints).

### 2.2 Authentication

Two schemes, both via `Authorization: Bearer <token>`:

| Scheme | Token type | Used by |
|---|---|---|
| `jwt` | Short-lived JWT from `/auth/login` | Web UI |
| `api_token` | Opaque token from `/tokens` | CLI, automation |

- 2FA is enforced at login for users with `totp_enabled_at`.
- JWT expiry: 15 minutes. Refresh token: 7 days, rotating, bound to device fingerprint.
- Session invalidation: on password change, 2FA disable, or explicit revoke.

### 2.3 Error Model (RFC 7807)

All non-2xx responses are RFC 7807 Problem Details:

```json
{
  "type": "https://docs.nexuspanel.io/errors/validation-failed",
  "title": "Validation Failed",
  "status": 422,
  "detail": "The 'domain' field must be a valid FQDN.",
  "instance": "/api/v1/domains",
  "errors": [
    { "field": "domain", "code": "invalid_format", "message": "..." }
  ],
  "trace_id": "01H..."
}
```

**Standard error types:**

| `status` | `type` suffix | When |
|---|---|---|
| 400 | `bad-request` | Malformed JSON, missing required field |
| 401 | `unauthenticated` | Missing/invalid token |
| 403 | `forbidden` | Authenticated but lacking permission |
| 404 | `not-found` | Resource doesn't exist or is not visible to caller |
| 409 | `conflict` | Uniqueness violation, state conflict |
| 422 | `validation-failed` | Field-level validation failures |
| 429 | `rate-limited` | Rate limit exceeded; `Retry-After` header set |
| 500 | `internal-error` | Unexpected; `trace_id` for support |
| 503 | `service-unavailable` | Agent unreachable, service down |

`trace_id` is present on every error and every response header (`X-Trace-Id`), enabling support correlation.

### 2.4 Pagination

Cursor-based, mandatory on all list endpoints:

```
GET /api/v1/domains?limit=50&cursor=eyJpZCI6IjAxSC4uLiJ9
```

Response:

```json
{
  "data": [ ... ],
  "pagination": {
    "next_cursor": "eyJpZCI6IjAxSC4uLiJ9",
    "has_more": true,
    "limit": 50
  }
}
```

- `limit`: 1–200, default 50.
- Cursor is opaque (base64url JSON). Clients must not parse it.
- Sorting is by `created_at DESC, id DESC` by default; cursor encodes both.

### 2.5 Filtering and Sorting

```
GET /api/v1/domains?status=active&php_version=8.3&sort=name:asc
```

- Filter fields are documented per endpoint.
- `sort` accepts `field:asc` or `field:desc`; allowed fields documented per endpoint.
- Unknown filter/sort field → `400 bad-request`.

### 2.6 Idempotency

All non-GET endpoints accept:

```
Idempotency-Key: <client-generated UUID v4>
```

- Same key + same body within 24h → returns the original response (including status and body).
- Same key + different body → `409 conflict`.
- Successful and failed responses are both cached (a failed operation should not be retried with a different key by accident).

### 2.7 Rate Limiting

Limits documented per endpoint. Defaults:

| Category | Limit |
|---|---|
| `auth.*` | 10/min/IP |
| `GET` on most resources | 300/min/token |
| `POST/PUT/PATCH` on most resources | 60/min/token |
| File upload | 5 concurrent/token |
| Agent-backed mutations | per-endpoint; typically 30/min/token |

Headers on every response: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

### 2.8 Request/Response Conventions

- **Field naming:** `snake_case` in JSON (matches DB, simplifies mapping). Consistent across all endpoints.
- **Timestamps:** ISO 8601 with UTC (`2026-11-15T12:00:00.123Z`).
- **IDs:** UUID v7 strings.
- **Booleans:** `true` / `false`, never `0`/`1`/`"yes"`.
- **Nulls:** explicit `null`, never omitted for optional fields in *responses*. Omitted in *requests* means "not provided / no change".
- **Enums:** lowercase strings (`"active"`, `"suspended"`).

### 2.9 Common Response Envelope

Single-resource endpoints return the resource directly:

```json
{ "id": "...", "name": "...", ... }
```

List endpoints return `{data: [...], pagination: {...}}`.

Mutation endpoints return the updated resource (same shape as GET).

Bulk operations return:

```json
{
  "results": [
    { "id": "...", "status": "success", "resource": {...} },
    { "id": "...", "status": "failed", "error": {...} }
  ],
  "summary": { "succeeded": 8, "failed": 2 }
}
```

Status code is `207 Multi-Status` if any failed, `200` if all succeeded.

## 3. Resource Model

Every resource follows the same envelope conventions. The full resource shapes are defined in §4. Below is the cross-cutting model.

### 3.1 Standard fields on every resource

```json
{
  "id": "uuidv7",
  "created_at": "ISO8601",
  "updated_at": "ISO8601",
  "deleted_at": null | "ISO8601"
}
```

### 3.2 Ownership scoping

Every resource is owned by exactly one of:

- `hosting_account_id` — a customer resource
- `user_id` — a user-scoped resource (tokens, sessions, notifications)
- `null` — a server-scoped resource (admin-only)

The API enforces visibility at the ownership boundary. A user without access to a hosting account cannot see its domains, mailboxes, databases, etc. — endpoints return `404 not-found`, not `403 forbidden` (prevents enumeration).

### 3.3 Composite resources

Some resources are always accessed through their parent:

```
/sites/{domain_id}/php
/sites/{domain_id}/ssl
/mail/domains/{mail_domain_id}/mailboxes
/dns/zones/{zone_id}/records
```

Parent IDs are validated for ownership at every request.

## 4. Endpoint Catalog

The full endpoint catalog is large. Below is the **complete catalog** with method, path, auth, required permission, and brief description. Request/response schemas for each are defined in the generated OpenAPI spec, which is produced from controllers. This catalog is the contract for *which endpoints exist and what permission they require*.

### 4.1 Authentication — `/api/v1/auth`

| Method | Path | Auth | Permission | Description |
|---|---|---|---|---|
| POST | `/auth/login` | none | — | Email + password (+ TOTP if enabled) → JWT + refresh |
| POST | `/auth/refresh` | refresh_token | — | Rotate refresh token, issue new JWT |
| POST | `/auth/logout` | jwt | — | Revoke current session |
| POST | `/auth/2fa/setup` | jwt | — | Begin TOTP enrollment; returns secret + QR URI |
| POST | `/auth/2fa/verify` | jwt | — | Confirm TOTP; enables 2FA |
| POST | `/auth/2fa/disable` | jwt + password | — | Disable 2FA (requires password re-entry) |
| GET | `/auth/2fa/backup-codes` | jwt + password | — | Regenerate backup codes (one-time view) |
| GET | `/auth/sessions` | jwt | — | List own active sessions |
| DELETE | `/auth/sessions/{id}` | jwt | — | Revoke own session |
| POST | `/auth/password/change` | jwt + old password | — | Change own password |

### 4.2 Users — `/api/v1/users`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/users` | jwt | `user:list` (admin) |
| GET | `/users/{id}` | jwt | `user:read` (admin) or self |
| PATCH | `/users/{id}` | jwt | `user:update` (admin) or self |
| POST | `/users/{id}/suspend` | jwt | `user:suspend` (admin) |
| POST | `/users/{id}/resume` | jwt | `user:resume` (admin) |

### 4.3 API Tokens — `/api/v1/tokens`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/tokens` | jwt | — (own tokens) |
| POST | `/tokens` | jwt | — (create own token) |
| DELETE | `/tokens/{id}` | jwt | — (revoke own token) |
| POST | `/tokens/{id}/rotate` | jwt | — (rotate own token) |

### 4.4 Hosting Accounts — `/api/v1/accounts`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/accounts` | jwt/token | `account:list` |
| GET | `/accounts/{id}` | jwt/token | `account:read` |
| POST | `/accounts` | jwt/token | `account:create` |
| PATCH | `/accounts/{id}` | jwt/token | `account:update` |
| POST | `/accounts/{id}/suspend` | jwt/token | `account:suspend` |
| POST | `/accounts/{id}/resume` | jwt/token | `account:resume` |
| DELETE | `/accounts/{id}` | jwt/token | `account:delete` |
| POST | `/accounts/{id}/restore` | jwt/token | `account:restore` |
| GET | `/accounts/{id}/usage` | jwt/token | `account:read` |
| GET | `/accounts/{id}/access` | jwt | `account:read` |
| POST | `/accounts/{id}/access` | jwt | `account:manage-access` |
| DELETE | `/accounts/{id}/access/{user_id}` | jwt | `account:manage-access` |
| POST | `/accounts/{id}/clone` | jwt/token | `account:create` |

### 4.5 Packages — `/api/v1/packages`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/packages` | jwt/token | `package:list` |
| GET | `/packages/{id}` | jwt/token | `package:read` |
| POST | `/packages` | jwt/token | `package:create` |
| PATCH | `/packages/{id}` | jwt/token | `package:update` |
| DELETE | `/packages/{id}` | jwt/token | `package:delete` |

### 4.6 Resellers — `/api/v1/resellers`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/resellers` | jwt | `reseller:list` |
| GET | `/resellers/{id}` | jwt | `reseller:read` |
| POST | `/resellers` | jwt | `reseller:create` |
| PATCH | `/resellers/{id}` | jwt | `reseller:update` |
| DELETE | `/resellers/{id}` | jwt | `reseller:delete` |
| GET | `/resellers/{id}/branding` | jwt | `reseller:read` |
| PATCH | `/resellers/{id}/branding` | jwt | `reseller:update` |
| POST | `/resellers/{id}/custom-domain` | jwt | `reseller:update` |
| DELETE | `/resellers/{id}/custom-domain` | jwt | `reseller:update` |

### 4.7 Domains — `/api/v1/domains`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/domains` | jwt/token | `site:list` |
| GET | `/domains/{id}` | jwt/token | `site:read` |
| POST | `/domains` | jwt/token | `site:create` |
| PATCH | `/domains/{id}` | jwt/token | `site:update` |
| DELETE | `/domains/{id}` | jwt/token | `site:delete` |
| GET | `/domains/{id}/subdomains` | jwt/token | `site:read` |
| POST | `/domains/{id}/subdomains` | jwt/token | `site:create` |
| DELETE | `/domains/{id}/subdomains/{sub_id}` | jwt/token | `site:delete` |
| GET | `/domains/{id}/aliases` | jwt/token | `site:read` |
| POST | `/domains/{id}/aliases` | jwt/token | `site:create` |
| DELETE | `/domains/{id}/aliases/{alias_id}` | jwt/token | `site:delete` |
| GET | `/domains/{id}/redirects` | jwt/token | `site:read` |
| POST | `/domains/{id}/redirects` | jwt/token | `site:update` |
| DELETE | `/domains/{id}/redirects/{rid}` | jwt/token | `site:update` |
| GET | `/domains/{id}/php` | jwt/token | `site:read` |
| PATCH | `/domains/{id}/php` | jwt/token | `php:manage` |
| GET | `/domains/{id}/ssl` | jwt/token | `ssl:read` |
| POST | `/domains/{id}/ssl/issue` | jwt/token | `ssl:issue` |
| POST | `/domains/{id}/ssl/renew` | jwt/token | `ssl:issue` |
| DELETE | `/domains/{id}/ssl` | jwt/token | `ssl:revoke` |
| GET | `/domains/{id}/logs` | jwt/token | `site:read` |
| GET | `/domains/{id}/staging` | jwt/token | `site:read` |
| POST | `/domains/{id}/staging` | jwt/token | `site:create` |
| DELETE | `/domains/{id}/staging/{sid}` | jwt/token | `site:delete` |
| GET | `/domains/{id}/git` | jwt/token | `git:read` |
| POST | `/domains/{id}/git` | jwt/token | `git:manage` |
| POST | `/domains/{id}/git/deploy` | jwt/token | `git:deploy` |
| GET | `/domains/{id}/git/deployments` | jwt/token | `git:read` |
| POST | `/domains/{id}/git/rollback` | jwt/token | `git:deploy` |

### 4.8 Email — `/api/v1/mail`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/mail/domains` | jwt/token | `mail:list` |
| POST | `/mail/domains` | jwt/token | `mail:create` |
| GET | `/mail/domains/{id}` | jwt/token | `mail:read` |
| DELETE | `/mail/domains/{id}` | jwt/token | `mail:delete` |
| GET | `/mail/domains/{id}/mailboxes` | jwt/token | `mail:read` |
| POST | `/mail/domains/{id}/mailboxes` | jwt/token | `mail:create` |
| PATCH | `/mail/domains/{id}/mailboxes/{mid}` | jwt/token | `mail:update` |
| DELETE | `/mail/domains/{id}/mailboxes/{mid}` | jwt/token | `mail:delete` |
| POST | `/mail/domains/{id}/mailboxes/{mid}/password` | jwt/token | `mail:update` |
| GET | `/mail/domains/{id}/aliases` | jwt/token | `mail:read` |
| POST | `/mail/domains/{id}/aliases` | jwt/token | `mail:create` |
| DELETE | `/mail/domains/{id}/aliases/{aid}` | jwt/token | `mail:delete` |
| GET | `/mail/domains/{id}/autoresponders` | jwt/token | `mail:read` |
| POST | `/mail/domains/{id}/autoresponders` | jwt/token | `mail:create` |
| DELETE | `/mail/domains/{id}/autoresponders/{aid}` | jwt/token | `mail:delete` |
| GET | `/mail/domains/{id}/dkim` | jwt/token | `mail:read` |
| POST | `/mail/domains/{id}/dkim` | jwt/token | `mail:manage` |
| POST | `/mail/domains/{id}/dkim/rotate` | jwt/token | `mail:manage` |
| GET | `/mail/queue` | jwt | `mail:queue:read` |
| POST | `/mail/queue/flush` | jwt | `mail:queue:manage` |
| POST | `/mail/queue/{id}/retry` | jwt | `mail:queue:manage` |
| POST | `/mail/domains/{id}/relay` | jwt | `mail:relay:manage` |
| DELETE | `/mail/domains/{id}/relay` | jwt | `mail:relay:manage` |

### 4.9 DNS — `/api/v1/dns`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/dns/zones` | jwt/token | `dns:list` |
| POST | `/dns/zones` | jwt/token | `dns:create` |
| GET | `/dns/zones/{id}` | jwt/token | `dns:read` |
| DELETE | `/dns/zones/{id}` | jwt/token | `dns:delete` |
| POST | `/dns/zones/{id}/import` | jwt/token | `dns:create` |
| GET | `/dns/zones/{id}/export` | jwt/token | `dns:read` |
| GET | `/dns/zones/{id}/records` | jwt/token | `dns:read` |
| POST | `/dns/zones/{id}/records` | jwt/token | `dns:create` |
| PATCH | `/dns/zones/{id}/records/{rid}` | jwt/token | `dns:update` |
| DELETE | `/dns/zones/{id}/records/{rid}` | jwt/token | `dns:delete` |
| POST | `/dns/zones/{id}/dnssec/enable` | jwt/token | `dns:manage` |
| POST | `/dns/zones/{id}/dnssec/disable` | jwt/token | `dns:manage` |
| GET | `/dns/zones/{id}/dnssec` | jwt/token | `dns:read` |
| GET | `/dns/templates` | jwt | `dns:list` |
| POST | `/dns/templates` | jwt | `dns:create` |
| DELETE | `/dns/templates/{id}` | jwt | `dns:delete` |
| POST | `/dns/zones/{id}/check-propagation` | jwt/token | `dns:read` |
| POST | `/dns/zones/{id}/zone-check` | jwt/token | `dns:read` |

### 4.10 Databases — `/api/v1/databases`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/databases` | jwt/token | `db:list` |
| POST | `/databases` | jwt/token | `db:create` |
| GET | `/databases/{id}` | jwt/token | `db:read` |
| DELETE | `/databases/{id}` | jwt/token | `db:delete` |
| POST | `/databases/{id}/dump` | jwt/token | `db:backup` |
| POST | `/databases/{id}/restore` | jwt/token | `db:restore` |
| GET | `/databases/{id}/users` | jwt/token | `db:read` |
| POST | `/databases/{id}/users` | jwt/token | `db:manage` |
| DELETE | `/databases/{id}/users/{uid}` | jwt/token | `db:manage` |
| POST | `/databases/{id}/phpmyadmin-sso` | jwt | `db:read` |

### 4.11 Files — `/api/v1/files`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/files` | jwt/token | `file:read` |
| POST | `/files/upload` | jwt | `file:write` |
| GET | `/files/download` | jwt | `file:read` |
| POST | `/files/mkdir` | jwt | `file:write` |
| POST | `/files/delete` | jwt | `file:delete` |
| POST | `/files/move` | jwt | `file:write` |
| POST | `/files/copy` | jwt | `file:write` |
| POST | `/files/chmod` | jwt | `file:write` |
| POST | `/files/chown` | jwt | `file:write` |
| POST | `/files/archive` | jwt | `file:write` |
| POST | `/files/extract` | jwt | `file:write` |
| GET | `/files/search` | jwt | `file:read` |
| GET | `/files/trash` | jwt | `file:read` |
| POST | `/files/trash/{id}/restore` | jwt | `file:write` |
| DELETE | `/files/trash/{id}` | jwt | `file:delete` |

### 4.12 FTP/SFTP — `/api/v1/ftp`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/ftp` | jwt/token | `ftp:list` |
| POST | `/ftp` | jwt/token | `ftp:create` |
| DELETE | `/ftp/{id}` | jwt/token | `ftp:delete` |
| POST | `/ftp/{id}/password` | jwt/token | `ftp:update` |

### 4.13 SSH Keys — `/api/v1/ssh/keys`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/ssh/keys` | jwt/token | `ssh:read` |
| POST | `/ssh/keys` | jwt/token | `ssh:manage` |
| DELETE | `/ssh/keys/{id}` | jwt/token | `ssh:manage` |

### 4.14 SSL Certificates (cross-domain) — `/api/v1/ssl/certificates`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/ssl/certificates` | jwt/token | `ssl:read` |
| POST | `/ssl/certificates` | jwt/token | `ssl:issue` |
| GET | `/ssl/certificates/{id}` | jwt/token | `ssl:read` |
| POST | `/ssl/certificates/{id}/renew` | jwt/token | `ssl:issue` |
| DELETE | `/ssl/certificates/{id}` | jwt/token | `ssl:revoke` |

### 4.15 Security — `/api/v1/security`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/security/firewall/rules` | jwt | `security:read` |
| POST | `/security/firewall/rules` | jwt | `security:manage` |
| DELETE | `/security/firewall/rules/{id}` | jwt | `security:manage` |
| POST | `/security/firewall/apply` | jwt | `security:manage` |
| GET | `/security/fail2ban/jails` | jwt | `security:read` |
| PATCH | `/security/fail2ban/jails/{name}` | jwt | `security:manage` |
| POST | `/security/fail2ban/ban` | jwt | `security:manage` |
| POST | `/security/fail2ban/unban` | jwt | `security:manage` |
| GET | `/security/fail2ban/bans` | jwt | `security:read` |
| GET | `/security/modsecurity/{domain_id}` | jwt/token | `security:read` |
| PATCH | `/security/modsecurity/{domain_id}` | jwt/token | `security:manage` |
| POST | `/security/malware/scan` | jwt | `security:manage` |
| GET | `/security/malware/quarantine` | jwt | `security:read` |
| POST | `/security/malware/quarantine/{id}/restore` | jwt | `security:manage` |
| DELETE | `/security/malware/quarantine/{id}` | jwt | `security:manage` |

### 4.16 Backups — `/api/v1/backups`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/backups/jobs` | jwt | `backup:list` |
| POST | `/backups/jobs` | jwt | `backup:create` |
| PATCH | `/backups/jobs/{id}` | jwt | `backup:update` |
| DELETE | `/backups/jobs/{id}` | jwt | `backup:delete` |
| POST | `/backups/jobs/{id}/run` | jwt | `backup:create` |
| GET | `/backups/runs` | jwt | `backup:list` |
| GET | `/backups/runs/{id}` | jwt | `backup:read` |
| POST | `/backups/runs/{id}/restore-preview` | jwt | `backup:restore` |
| POST | `/backups/runs/{id}/restore` | jwt | `backup:restore` |
| POST | `/backups/runs/{id}/verify` | jwt | `backup:verify` |
| GET | `/backups/destinations` | jwt | `backup:list` |
| POST | `/backups/destinations` | jwt | `backup:create` |
| DELETE | `/backups/destinations/{id}` | jwt | `backup:delete` |
| POST | `/backups/destinations/{id}/test` | jwt | `backup:create` |

### 4.17 Applications — `/api/v1/apps`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/apps/catalog` | jwt/token | `app:read` |
| GET | `/apps/installed` | jwt/token | `app:read` |
| POST | `/apps/install` | jwt/token | `app:install` |
| PATCH | `/apps/{id}` | jwt/token | `app:update` |
| DELETE | `/apps/{id}` | jwt/token | `app:delete` |
| POST | `/apps/{id}/update` | jwt/token | `app:update` |
| POST | `/apps/{id}/staging` | jwt/token | `app:update` |

### 4.18 Nodes — `/api/v1/nodes`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/nodes` | jwt | `node:list` (admin) |
| GET | `/nodes/{id}` | jwt | `node:read` |
| POST | `/nodes` | jwt | `node:create` |
| DELETE | `/nodes/{id}` | jwt | `node:delete` |
| GET | `/nodes/{id}/services` | jwt | `node:read` |
| POST | `/nodes/{id}/services/{name}/{action}` | jwt | `node:manage` |
| GET | `/nodes/{id}/health` | jwt | `node:read` |

### 4.19 Services — `/api/v1/services`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/services` | jwt | `service:list` |
| GET | `/services/{id}` | jwt | `service:read` |
| POST | `/services/{id}/{action}` | jwt | `service:manage` |

### 4.20 Audit — `/api/v1/audit`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/audit/entries` | jwt | `audit:list` |
| GET | `/audit/entries/{id}` | jwt | `audit:read` |
| POST | `/audit/verify` | jwt | `audit:verify` |

### 4.21 Migrations — `/api/v1/migrations`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/migrations` | jwt | `migration:list` |
| POST | `/migrations` | jwt | `migration:create` |
| GET | `/migrations/{id}` | jwt | `migration:read` |
| POST | `/migrations/{id}/analyze` | jwt | `migration:analyze` |
| POST | `/migrations/{id}/dry-run` | jwt | `migration:execute` |
| POST | `/migrations/{id}/execute` | jwt | `migration:execute` |
| GET | `/migrations/{id}/report` | jwt | `migration:read` |
| POST | `/migrations/{id}/cancel` | jwt | `migration:execute` |

### 4.22 Webhooks — `/api/v1/webhooks`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/webhooks` | jwt | `webhook:list` |
| POST | `/webhooks` | jwt | `webhook:create` |
| PATCH | `/webhooks/{id}` | jwt | `webhook:update` |
| DELETE | `/webhooks/{id}` | jwt | `webhook:delete` |
| GET | `/webhooks/{id}/deliveries` | jwt | `webhook:read` |

### 4.23 Notifications — `/api/v1/notifications`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/notifications` | jwt | — (own) |
| POST | `/notifications/{id}/read` | jwt | — (own) |
| POST | `/notifications/read-all` | jwt | — (own) |

### 4.24 Extensions — `/api/v1/extensions`

| Method | Path | Auth | Permission |
|---|---|---|---|
| GET | `/extensions` | jwt | `extension:list` (admin) |
| POST | `/extensions` | jwt | `extension:install` (admin) |
| DELETE | `/extensions/{id}` | jwt | `extension:uninstall` (admin) |
| PATCH | `/extensions/{id}` | jwt | `extension:manage` (admin) |

### 4.25 System / Meta

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | none | Liveness (no DB, no agent) |
| GET | `/ready` | none | Readiness (DB + agent) |
| GET | `/version` | none | Panel version, agent version, schema version |
| GET | `/events` (WebSocket) | jwt | Live event stream for the caller |

## 5. WebSocket Events — `/api/v1/events`

Single WebSocket connection per session. Events are JSON:

```json
{
  "type": "job.progress",
  "event_id": "uuidv7",
  "occurred_at": "ISO8601",
  "payload": { ... }
}
```

**Event categories:**
- `job.progress` — `{job_id, queue, progress, message}`
- `job.completed` — `{job_id, result}`
- `job.failed` — `{job_id, error}`
- `service.status` — `{service, node_id, status}`
- `resource.usage` — `{hosting_account_id, cpu, mem, disk, ...}` (throttled to 5s)
- `notification.new` — `{notification}`

**Subscription:** the client sends `{action:"subscribe", channels:[...]}` after connect. Channels are implicitly scoped by the connection's authenticated user — a user cannot subscribe to another user's jobs.

## 6. OpenAPI Generation

- Controllers use `@nestjs/swagger` decorators.
- A CI job runs `nest build` + `swagger:export` and diffs the generated YAML against the committed artifact.
- Any diff fails CI unless the PR explicitly updates the artifact.
- This enforces that the API contract, the implementation, and the published docs stay in sync.

## 7. SDK and CLI Generation

- TypeScript SDK: generated from OpenAPI via `openapi-typescript`; consumed by the frontend.
- CLI (`nexus`): hand-written but validated against OpenAPI in CI — every documented endpoint has a CLI command; every CLI command maps to a documented endpoint.
- Additional SDKs (Python, Go) are Delivery Expanded.

---
