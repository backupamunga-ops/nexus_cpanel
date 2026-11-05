-- ============================================================================
-- NexusPanel Schema v2.0
-- PostgreSQL 16+
-- Source of truth. Prisma schema is generated/validated against this in CI.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- UUID v7 generator (time-ordered) — installed as an immutable function
CREATE OR REPLACE FUNCTION uuid_generate_v7() RETURNS uuid
  LANGUAGE sql VOLATILE PARALLEL SAFE AS $$
  SELECT encode(
    set_bit(set_bit(
      overlay(uuid_send(gen_random_uuid())
        PLACING substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
        FROM 1 FOR 6),
      52, 1),
      53, 1),
    'hex')::uuid;
$$;

-- ============================================================================
-- IDENTITY & ACCESS
-- ============================================================================

CREATE TABLE users (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  email               citext NOT NULL UNIQUE,
  password_hash       text NOT NULL,           -- Argon2id
  display_name        text NOT NULL,
  is_active           boolean NOT NULL DEFAULT true,
  is_super_admin      boolean NOT NULL DEFAULT false,  -- server admin flag
  email_verified_at   timestamptz,
  totp_secret_enc     bytea,                   -- age-encrypted TOTP secret
  totp_enabled_at     timestamptz,
  backup_codes_enc    bytea,                   -- age-encrypted backup codes JSON
  failed_login_count  integer NOT NULL DEFAULT 0,
  locked_until        timestamptz,
  last_login_at       timestamptz,
  last_login_ip       inet,
  preferences         jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE INDEX ON users (deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX ON users USING gin (email gin_trgm_ops);

CREATE TABLE user_sessions (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash  bytea NOT NULL UNIQUE,   -- SHA-256 of the refresh token
  device_fingerprint  text,
  ip                  inet,
  user_agent          text,
  bound_host          text,                    -- C14: Host the session was created on (host-only)
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_used_at        timestamptz NOT NULL DEFAULT now(),
  expires_at          timestamptz NOT NULL,
  revoked_at          timestamptz
);
CREATE INDEX ON user_sessions (user_id, revoked_at);

CREATE TABLE api_tokens (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name                text NOT NULL,
  token_hash          bytea NOT NULL UNIQUE,   -- SHA-256 of the token
  scopes              text[] NOT NULL,         -- e.g. ARRAY['sites:read','dns:write']
  ip_allowlist        inet[],
  expires_at          timestamptz,
  last_used_at        timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  revoked_at          timestamptz
);
CREATE INDEX ON api_tokens (user_id, revoked_at);

-- ============================================================================
-- HOSTING ACCOUNTS, PACKAGES, RESELLERS
-- ============================================================================

CREATE TABLE packages (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  owner_reseller_id   uuid,                    -- NULL = server admin-owned
  name                text NOT NULL,
  description         text,
  quotas              jsonb NOT NULL,          -- {cpu, mem_mb, disk_mb, inodes, processes, ...}
  features            jsonb NOT NULL,          -- {mail_enabled, dns_enabled, ssh_enabled, ...}
  php_versions        text[],                  -- allowed PHP versions
  isolation_profile   text NOT NULL DEFAULT 'standard',
  over_quota_policy   text NOT NULL DEFAULT 'alert', -- alert | throttle | suspend
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE hosting_accounts (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  package_id          uuid NOT NULL REFERENCES packages(id),
  reseller_id         uuid,                    -- self-ref, set after insert
  parent_account_id   uuid,                    -- for nesting (reseller hierarchy)
  username            text NOT NULL UNIQUE,    -- Linux user
  linux_uid           integer NOT NULL UNIQUE,
  primary_domain      text,
  isolation_profile   text NOT NULL DEFAULT 'standard',
  status              text NOT NULL DEFAULT 'active', -- active | suspended | terminated
  suspension_reason   text,
  homedir             text NOT NULL,
  php_default_version text,
  quotas_override     jsonb,                   -- per-account overrides of package quotas
  suspended_at        timestamptz,
  terminated_at       timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
ALTER TABLE hosting_accounts
  ADD CONSTRAINT hosting_accounts_reseller_fk
  FOREIGN KEY (reseller_id) REFERENCES hosting_accounts(id);
CREATE INDEX ON hosting_accounts (reseller_id);
CREATE INDEX ON hosting_accounts (parent_account_id);
CREATE INDEX ON hosting_accounts (status) WHERE status <> 'terminated';

CREATE TABLE user_hosting_account_access (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  role                text NOT NULL,            -- owner | admin | member | readonly
  granted_by_user_id  uuid REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  revoked_at          timestamptz
);
CREATE UNIQUE INDEX uq_user_account_access_active
  ON user_hosting_account_access (user_id, hosting_account_id)
  WHERE revoked_at IS NULL;
CREATE INDEX ON user_hosting_account_access (hosting_account_id);

CREATE TABLE resellers (
  id                    uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id    uuid NOT NULL UNIQUE REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  parent_reseller_id    uuid REFERENCES resellers(id),
  depth                 integer NOT NULL DEFAULT 1,
  branding              jsonb NOT NULL DEFAULT '{}'::jsonb,
  custom_domain         text,
  custom_domain_status  text,                   -- pending | active | error
  custom_domain_ssl     bytea,                  -- age-encrypted cert+key
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  deleted_at            timestamptz
);
CREATE INDEX ON resellers (parent_reseller_id);
CREATE INDEX ON resellers (custom_domain) WHERE custom_domain IS NOT NULL;

-- ============================================================================
-- SITES (DOMAINS, SUBDOMAINS, ALIASES, REDIRECTS)
-- ============================================================================

CREATE TABLE domains (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  name                text NOT NULL UNIQUE,     -- FQDN
  type                text NOT NULL,            -- primary | addon | parked
  document_root       text NOT NULL,
  php_version         text,
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE INDEX ON domains (hosting_account_id);

CREATE TABLE subdomains (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  name                text NOT NULL,            -- e.g. "blog" for blog.example.com
  document_root       text NOT NULL,
  php_version         text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE UNIQUE INDEX uq_subdomains_active
  ON subdomains (domain_id, name)
  WHERE deleted_at IS NULL;

CREATE TABLE domain_aliases (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  alias_name          text NOT NULL UNIQUE,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE redirects (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  source_path         text NOT NULL,
  destination_url     text NOT NULL,
  status_code         integer NOT NULL DEFAULT 301,  -- 301 | 302 | 307 | 308
  is_wildcard         boolean NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

-- ============================================================================
-- EMAIL
-- ============================================================================

CREATE TABLE mail_domains (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  name                text NOT NULL UNIQUE,
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE INDEX ON mail_domains (hosting_account_id);

CREATE TABLE mailboxes (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  mail_domain_id      uuid NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
  local_part          text NOT NULL,
  password_hash       bytea NOT NULL,           -- Dovecot SHA-512
  quota_mb            integer NOT NULL,
  used_mb             integer NOT NULL DEFAULT 0,
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE UNIQUE INDEX uq_mailboxes_active
  ON mailboxes (mail_domain_id, local_part)
  WHERE deleted_at IS NULL;

CREATE TABLE mail_aliases (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  mail_domain_id      uuid NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
  source_address      text NOT NULL,
  destination_address text NOT NULL,
  is_catchall         boolean NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE mail_domain_dkim (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  mail_domain_id      uuid NOT NULL UNIQUE REFERENCES mail_domains(id) ON DELETE CASCADE,
  selector            text NOT NULL,
  rotated_at          timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE autoresponders (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  mailbox_id          uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  subject             text NOT NULL,
  body                text NOT NULL,
  starts_at           timestamptz,
  ends_at             timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mailing_lists (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  mail_domain_id      uuid NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
  list_name           text NOT NULL,
  description         text,
  members             text[] NOT NULL DEFAULT '{}',
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE account_smtp_relay_config (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL UNIQUE REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  provider            text,                    -- ses | mailgun | postmark | custom
  credentials_enc     bytea,                   -- age-encrypted JSON
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- DNS
-- ============================================================================

CREATE TABLE dns_zones (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  name                text NOT NULL UNIQUE,
  is_active           boolean NOT NULL DEFAULT true,
  dnssec_enabled      boolean NOT NULL DEFAULT false,
  template_id         uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE INDEX ON dns_zones (hosting_account_id);

CREATE TABLE dns_zone_templates (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  name                text NOT NULL UNIQUE,
  description         text,
  records             jsonb NOT NULL,           -- array of {type, name, content, ttl, priority}
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE dns_records (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  zone_id             uuid NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
  name                text NOT NULL,
  type                text NOT NULL,
  content             text NOT NULL,
  ttl                 integer NOT NULL DEFAULT 3600,
  priority            integer,
  weight              integer,
  port                integer,
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE INDEX ON dns_records (zone_id, name, type);

CREATE TABLE dnssec_keys (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  zone_id             uuid NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
  key_type            text NOT NULL,            -- ZSK | KSK
  algorithm           integer NOT NULL,         -- 8 or 13
  private_key_enc     bytea NOT NULL,
  public_key          text NOT NULL,
  active              boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  retired_at          timestamptz
);

-- ============================================================================
-- DATABASES (customer-facing)
-- ============================================================================

CREATE TABLE databases (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  engine              text NOT NULL,            -- mariadb (v1.0; mysql|postgres planned per ADR-0001)
  name                text NOT NULL,
  db_user             text NOT NULL,
  db_password_hash    bytea NOT NULL,           -- SecretBox AES-256-GCM envelope of the credential (ADR-0009/0015) — decrypt at point of use only
  size_mb             integer NOT NULL DEFAULT 0,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE UNIQUE INDEX uq_databases_active
  ON databases (engine, name)
  WHERE deleted_at IS NULL;
CREATE INDEX ON databases (hosting_account_id);

-- ============================================================================
-- FILES, FTP, SSH
-- ============================================================================

CREATE TABLE ftp_accounts (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  username            text NOT NULL UNIQUE,
  password_hash       bytea NOT NULL,
  home_directory      text NOT NULL,
  protocol            text NOT NULL,            -- ftp | sftp
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE ssh_keys (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  name                text NOT NULL,
  public_key          text NOT NULL,
  fingerprint         text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE trash_entries (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  original_path       text NOT NULL,
  trash_path          text NOT NULL,
  size_bytes          bigint NOT NULL,
  deleted_at          timestamptz NOT NULL DEFAULT now(),
  purge_after         timestamptz NOT NULL       -- deleted_at + 30 days
);
CREATE INDEX ON trash_entries (hosting_account_id, purge_after);

-- ============================================================================
-- FTP ACCOUNTS (P4 amendment ADR-0011) — vsftpd virtual-user registry
-- ============================================================================
-- The login (username) is the vsftpd virtual-user name and is globally
-- unique: the agent keys its per-user config files and the pam_userdb
-- entries by it. Passwords NEVER live here — the agent hashes into the
-- user DB directly (SHA-512-crypt via openssl); this table is metadata
-- only. root_dir is confined to the owning account's home (C13).

CREATE TABLE file_accounts (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid NOT NULL REFERENCES hosting_accounts(id) ON DELETE CASCADE,
  username            text NOT NULL UNIQUE,        -- vsftpd virtual-user login
  root_dir            text NOT NULL,               -- confined inside the account home
  read_only           boolean NOT NULL DEFAULT false,
  status              text NOT NULL DEFAULT 'active',  -- active | suspended
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);
CREATE INDEX ON file_accounts (hosting_account_id, deleted_at);

-- ============================================================================
-- SSL, SECURITY, FIREWALL
-- ============================================================================

CREATE TABLE certificates (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  issuer              text NOT NULL,            -- letsencrypt | manual
  common_name         text NOT NULL,
  san_names           text[],
  cert_pem_enc        bytea NOT NULL,
  key_pem_enc         bytea NOT NULL,
  issued_at           timestamptz NOT NULL,
  expires_at          timestamptz NOT NULL,
  last_renewed_at     timestamptz,
  auto_renew          boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON certificates (expires_at) WHERE auto_renew = true;

CREATE TABLE firewall_rules (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  name                text NOT NULL,
  direction           text NOT NULL,            -- inbound | outbound
  protocol            text NOT NULL,            -- tcp | udp | icmp
  port_from           integer,
  port_to             integer,
  source_cidr         inet,
  action              text NOT NULL,            -- accept | reject | drop
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE fail2ban_jails (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  name                text NOT NULL UNIQUE,
  is_enabled          boolean NOT NULL DEFAULT true,
  maxretry            integer NOT NULL,
  findtime_sec        integer NOT NULL,
  bantime_sec         integer NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE fail2ban_bans (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  jail_id             uuid NOT NULL REFERENCES fail2ban_jails(id) ON DELETE CASCADE,
  ip                  inet NOT NULL,
  banned_at           timestamptz NOT NULL,
  banned_until        timestamptz,
  reason              text
);
CREATE INDEX ON fail2ban_bans (ip, banned_until);

CREATE TABLE modsecurity_policies (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  mode                text NOT NULL,            -- off | detect | block
  ruleset_version     text,
  paranoia_level      integer NOT NULL DEFAULT 1,
  exclusions          jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_modsecurity_domain
  ON modsecurity_policies (domain_id);

-- Anti-malware (B12, ADR-0017): scans and quarantine findings. The findings
-- registry mirrors what the agent quarantined; delete/restore of a
-- quarantined artifact is an audited panel flow, never a raw file op.
CREATE TABLE malware_scans (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  hosting_account_id  uuid REFERENCES hosting_accounts(id) ON DELETE CASCADE, -- NULL = server-wide
  scope               text NOT NULL,            -- server | account | site
  scope_path          text NOT NULL,
  trigger             text NOT NULL DEFAULT 'manual', -- manual | scheduled (cron = B13)
  status              text NOT NULL,            -- running | success | failed
  files_scanned       integer NOT NULL DEFAULT 0,
  infected_count      integer NOT NULL DEFAULT 0,
  quarantined_count   integer NOT NULL DEFAULT 0,
  started_at          timestamptz NOT NULL,
  completed_at        timestamptz,
  error_message       text,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON malware_scans (hosting_account_id, started_at DESC);

CREATE TABLE malware_findings (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  scan_id             uuid NOT NULL REFERENCES malware_scans(id) ON DELETE CASCADE,
  file_path           text NOT NULL,            -- original path at scan time
  signature           text NOT NULL,            -- ClamAV signature name
  quarantined         boolean NOT NULL DEFAULT false,
  quarantine_path     text,                     -- set when quarantined
  deleted_at          timestamptz,              -- audited artifact delete
  restored_at         timestamptz,              -- audited artifact restore
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON malware_findings (scan_id);
CREATE INDEX ON malware_findings (quarantined) WHERE quarantined;

-- ============================================================================
-- BACKUPS
-- ============================================================================

CREATE TABLE backup_destinations (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  name                text NOT NULL,
  type                text NOT NULL,            -- local | s3 | sftp
  config_enc          bytea NOT NULL,           -- age-encrypted config
  is_default          boolean NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE backup_jobs (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  name                text NOT NULL,
  scope               text NOT NULL,            -- server | account | site | database
  scope_id            uuid,                     -- null for server-wide
  destination_id      uuid NOT NULL REFERENCES backup_destinations(id),
  schedule            text NOT NULL,            -- cron expression (fires with the B13 job framework)
  retention_days      integer NOT NULL DEFAULT 30,
  keep_daily          integer NOT NULL DEFAULT 7,   -- GFS: daily restore points kept
  keep_weekly         integer NOT NULL DEFAULT 4,   -- GFS: weekly restore points kept
  keep_monthly        integer NOT NULL DEFAULT 6,   -- GFS: monthly restore points kept
  is_enabled          boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE backup_runs (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  job_id              uuid NOT NULL REFERENCES backup_jobs(id) ON DELETE CASCADE,
  status              text NOT NULL,            -- running | success | failed | verified
  started_at          timestamptz NOT NULL,
  completed_at        timestamptz,
  size_bytes          bigint,
  artifact_path       text,
  checksum_sha256     bytea,
  verified_at         timestamptz,
  error_message       text
);
CREATE INDEX ON backup_runs (job_id, started_at DESC);

-- ============================================================================
-- APPLICATIONS, GIT, STAGING
-- ============================================================================

CREATE TABLE installed_applications (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  app_type            text NOT NULL,            -- wordpress | joomla | drupal | laravel | ...
  version             text,
  install_path        text NOT NULL,
  admin_user          text,
  database_id         uuid REFERENCES databases(id),
  status              text NOT NULL DEFAULT 'active',
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE git_deployments (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  provider            text NOT NULL,            -- github | gitlab | bitbucket
  repo_url            text NOT NULL,
  branch              text NOT NULL DEFAULT 'main',
  deploy_path         text NOT NULL,
  webhook_secret_enc  bytea,
  last_deployed_at    timestamptz,
  last_deployed_sha   text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE staging_environments (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  source_domain_id    uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  staging_subdomain   text NOT NULL UNIQUE,
  document_root       text NOT NULL,
  cloned_at           timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

-- ============================================================================
-- NODES, SERVICES, INFRASTRUCTURE
-- ============================================================================

CREATE TABLE nodes (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  name                text NOT NULL UNIQUE,
  type                text NOT NULL,            -- control | hosting | dns | mail | backup | monitoring
  hostname            text NOT NULL,
  public_ip           inet,
  private_ip          inet,
  is_active           boolean NOT NULL DEFAULT true,
  last_seen_at        timestamptz,
  agent_version       text,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE services (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  node_id             uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  name                text NOT NULL,            -- nginx | php-fpm-8.3 | postfix | ...
  status              text NOT NULL,            -- running | stopped | failed | unknown
  last_checked_at     timestamptz,
  UNIQUE (node_id, name)
);

-- ============================================================================
-- CONFIGURATION ENGINE
-- ============================================================================

CREATE TABLE config_versions (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  target_type         text NOT NULL,            -- nginx_vhost | php_pool | postfix_main | dns_zone | panel
  target_id           uuid NOT NULL,
  version             integer NOT NULL,
  content             text NOT NULL,            -- rendered config
  rendered_by         uuid REFERENCES users(id),
  is_active           boolean NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (target_type, target_id, version)
);
CREATE INDEX ON config_versions (target_type, target_id, is_active) WHERE is_active = true;

CREATE TABLE config_transactions (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  target_type         text NOT NULL,
  target_id           uuid NOT NULL,
  from_version_id     uuid REFERENCES config_versions(id),
  to_version_id       uuid REFERENCES config_versions(id),
  status              text NOT NULL,            -- pending | applied | rolled_back | failed
  started_at          timestamptz NOT NULL DEFAULT now(),
  completed_at        timestamptz,
  error_message       text
);

CREATE TABLE drift_events (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  node_id             uuid NOT NULL REFERENCES nodes(id),
  target_type         text NOT NULL,
  target_id           uuid NOT NULL,
  expected_hash       bytea NOT NULL,
  actual_hash         bytea NOT NULL,
  detected_at         timestamptz NOT NULL DEFAULT now(),
  resolved_at         timestamptz,
  resolution          text                    -- reconciled | investigated | ignored
);
CREATE INDEX ON drift_events (resolved_at) WHERE resolved_at IS NULL;

-- ============================================================================
-- AUDIT CHAIN
-- ============================================================================

CREATE TABLE audit_entries (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  occurred_at         timestamptz NOT NULL DEFAULT now(),
  actor_user_id       uuid REFERENCES users(id),
  actor_ip            inet,
  node_id             uuid REFERENCES nodes(id),
  hosting_account_id  uuid REFERENCES hosting_accounts(id),
  operation           text NOT NULL,
  parameters          jsonb NOT NULL DEFAULT '{}'::jsonb,  -- secrets redacted
  outcome             text NOT NULL,            -- success | failure | partial
  prior_hash          bytea,
  this_hash           bytea NOT NULL,
  prev_entry_id       uuid REFERENCES audit_entries(id)
);
CREATE INDEX ON audit_entries (occurred_at DESC);
CREATE INDEX ON audit_entries (actor_user_id, occurred_at DESC);
CREATE INDEX ON audit_entries (hosting_account_id, occurred_at DESC);

CREATE TABLE audit_chain_heads (
  id                  boolean PRIMARY KEY DEFAULT true CHECK (id),  -- singleton
  last_entry_id       uuid NOT NULL REFERENCES audit_entries(id),
  last_hash           bytea NOT NULL,
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- JOBS, WEBHOOKS, NOTIFICATIONS
-- ============================================================================

CREATE TABLE jobs_metadata (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  bullmq_job_id       text NOT NULL,
  queue_name          text NOT NULL,
  job_type            text NOT NULL,
  status              text NOT NULL,            -- waiting | active | completed | failed
  payload             jsonb NOT NULL,
  result              jsonb,
  progress            integer NOT NULL DEFAULT 0,
  attempts            integer NOT NULL DEFAULT 0,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  completed_at        timestamptz
);
CREATE INDEX ON jobs_metadata (queue_name, status);
CREATE INDEX ON jobs_metadata (created_at DESC);

CREATE TABLE webhooks (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  name                text NOT NULL,
  url                 text NOT NULL,
  secret_enc          bytea NOT NULL,
  events              text[] NOT NULL,
  is_active           boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz
);

CREATE TABLE webhook_deliveries (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  webhook_id          uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_type          text NOT NULL,
  payload             jsonb NOT NULL,
  attempt             integer NOT NULL DEFAULT 1,
  status              text NOT NULL,            -- success | failed | dead
  response_status     integer,
  response_body       text,
  attempted_at        timestamptz NOT NULL DEFAULT now(),
  next_retry_at       timestamptz
);
CREATE INDEX ON webhook_deliveries (webhook_id, status);

CREATE TABLE notifications (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category            text NOT NULL,
  title               text NOT NULL,
  body                text NOT NULL,
  action_url          text,
  severity            text NOT NULL DEFAULT 'info',   -- info | warning | error
  read_at             timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON notifications (user_id, read_at) WHERE read_at IS NULL;

-- ============================================================================
-- MIGRATIONS
-- ============================================================================

CREATE TABLE migration_jobs (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  source_platform     text NOT NULL,            -- cpanel | directadmin | plesk | nexuspanel
  source_identifier   text NOT NULL,
  target_account_id   uuid REFERENCES hosting_accounts(id),
  initiated_by_user_id uuid NOT NULL REFERENCES users(id),
  status              text NOT NULL,            -- analyzing | dry_run | running | verifying | completed | failed
  analysis_report     jsonb,
  verification_report jsonb,
  started_at          timestamptz NOT NULL DEFAULT now(),
  completed_at        timestamptz,
  error_message       text
);
CREATE INDEX ON migration_jobs (status, started_at DESC);

CREATE TABLE migration_entity_mappings (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  migration_job_id    uuid NOT NULL REFERENCES migration_jobs(id) ON DELETE CASCADE,
  entity_type         text NOT NULL,            -- domain | mailbox | database | dns_zone | file_set
  source_id           text NOT NULL,
  target_id           uuid,
  status              text NOT NULL,            -- pending | migrated | skipped | failed
  checksum_source     bytea,
  checksum_target     bytea,
  notes               text
);
CREATE INDEX ON migration_entity_mappings (migration_job_id, status);

-- ============================================================================
-- EXTENSIONS
-- ============================================================================

CREATE TABLE extensions (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  slug                text NOT NULL UNIQUE,
  name                text NOT NULL,
  version             text NOT NULL,
  manifest            jsonb NOT NULL,
  granted_scopes      text[] NOT NULL,
  status              text NOT NULL,            -- enabled | disabled | errored
  installed_by_user_id uuid NOT NULL REFERENCES users(id),
  installed_at        timestamptz NOT NULL DEFAULT now(),
  last_error          text
);

CREATE TABLE extension_registrations (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  extension_id        uuid NOT NULL REFERENCES extensions(id) ON DELETE CASCADE,
  callback_url        text NOT NULL,
  shared_secret_enc   bytea NOT NULL,
  registered_at       timestamptz NOT NULL DEFAULT now(),
  last_heartbeat_at   timestamptz,
  is_active           boolean NOT NULL DEFAULT true
);

-- ============================================================================
-- SERVER SETTINGS (P2) — admin-editable platform configuration
-- ============================================================================
-- Keys are NOT open-ended: the settings module owns a whitelist of typed
-- definitions (category, type, bounds, default); unknown keys are rejected
-- fail-closed so a typo'd key can never silently enforce nothing. Values are
-- non-secret configuration only — secrets live in env/secret files, never
-- here. Every change is hash-chained into audit_entries (C11) by the service.

CREATE TABLE system_settings (
  key           text PRIMARY KEY,            -- whitelist key, e.g. 'security.lockout_minutes'
  value         jsonb NOT NULL,              -- typed scalar (string | integer | boolean)
  updated_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at    timestamptz NOT NULL DEFAULT now()
);
