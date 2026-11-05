# ADR-0015: Databases — MariaDB 11 only via a DatabaseEngineAdapter seam; unix-socket admin; panel stores recoverable encrypted credentials; SSO is a signed short-TTL token

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P4 (B09 databases)
- **Deciders:** Security review per BUILD_PLAN §2 WS7; locks resolution 5 and ADR-0001

## Context

B09 provisions customer databases on the node. Four questions needed
rulings before code:

1. The schema (`databases.engine`) carries `mariadb | mysql | postgres`, but
   ADR-0001 locked MariaDB-only for v1.0 behind a `DatabaseEngineAdapter`
   interface.
2. The spec's `database.create` params list `password_hash` — but MySQL-family
   engines verify passwords with their own native schemes; a hash the panel
   computed would be useless.
3. The DDL column `databases.db_password_hash bytea` implies a hash — but the
   batch plan names "credentials via SecretBox (ADR-0009 pattern), never in
   audit payloads", and the connection-string generator must hand the
   credential back (app installs, B14, depend on it).
4. The API spec lists `POST /databases/{id}/phpmyadmin-sso`, whose consumer
   (a bundled phpMyAdmin/Adminer) ships with the app installer (B14).

## Decision

**1. Adapter seam from day one, one implementation (ADR-0001 stands).** The
agent defines `DatabaseEngineAdapter` (create/drop database, create/drop
user, grant/revoke, dump/restore, size) with a single `mariadbAdapter` in
v1.0. The control plane accepts `engine: 'mariadb'` only and rejects
`mysql`/`postgres` with an honest message ("planned; v1.0 is MariaDB-only —
ADR-0001"). Adding MySQL 8 in v1.2 is a new adapter plus a resolver change —
no rewrite.

**2. Admin access rides the Unix socket.** The agent connects to MariaDB as
the system root via the `unix_socket` auth plugin (`mariadb` CLI with no
host/password — the installer's `mariadb_secure` setup). SQL text goes in
via stdin, never argv; customer passwords reach MariaDB through `MYSQL_PWD`
in the child environment (not the process list). The agent binary paths are
injectable for tests (fake shell scripts), matching the mail/ftp pattern.

**3. `db_password_hash` holds a SecretBox envelope, and the column is
renamed honestly.** A MySQL-family password hash is not verifiable by the
panel and not reversible by anyone — storing only it would make the panel
unable to show a connection string or seed app installs. Decision: the
column stores a **SecretBox-encrypted plaintext credential** (AES-256-GCM,
ADR-0009 envelope) and the DDL comment now says exactly that (the column
name stays `db_password_hash` to avoid a needless migration of a table no
release has shipped yet — the comment is the contract, per the divergence
precedent recorded in ADR-0009). Properties: decrypt only at point of use
(reveal + connection-string endpoints), never in audit payloads (audit
carries a key fingerprint, not material), never sent to the agent (MariaDB
keeps its own hash; the agent passes the plaintext once at user creation).

**4. Least-privilege by default.** A created user gets exactly one database
grant (`ALL PRIVILEGES ON db.*` — the practical cPanel default for a single
app database) scoped to `localhost` unless the caller passes an explicit
host. Extra users/grants are explicit `db:manage` operations, each audited.

**5. phpMyAdmin SSO is a real signed token with an honest consumer note.**
`POST /databases/{id}/phpmyadmin-sso` (session-only — a stolen automation
token must not harvest DB credentials) returns
`{url, token, expires_at}`: an HMAC-SHA256 token (PANEL_SECRET_KEY key)
binding database id + username + expiry (60s TTL, single-use by consumer
convention). The URL targets the panel's Adminer/phpMyAdmin mount; the
consumer plugin ships with the app installer (B14) — the docs chapter states
this honestly ("token issued; consumer lands with B14") instead of shipping
a dead link.

## Consequences

- Backup/restore (`database.dump`/`database.restore`) land agent-side now
  (mysqldump/mariadb-dump to confined paths) and become wired flows when
  B10's backup framework arrives; the panel exposes dump/restore endpoints
  marked as operator tools (they write under the account's own home).
- Package limits gain `db_count` and `db_size_mb` quota keys (same fail-closed
  validation as the mail keys); size reporting is live from
  `information_schema` with the panel caching the last reading.
- The dump path is confined under the owning account's home (C13 rules apply
  like every filesystem write the agent performs for an account).
