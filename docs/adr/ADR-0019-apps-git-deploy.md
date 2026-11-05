# ADR-0019 — Apps & Git deploy: node-side execution as the account user, release-symlink deploys

**Status:** Accepted (B14)
**Amends:** agent spec §4 (adds `apps.*`, `git.*`), API spec §4.7a (apps endpoints live), §4.7 (git routes live)
**Builds on:** DDL `installed_applications` / `git_deployments` / `staging_environments` (v2.0, pre-provisioned), C6 permission guard, ADR-0009 SecretBox, B09 databases policy, B13 job center

## Context

B14 delivers the app installer and push-to-deploy. The original batch plan
named WP-CLI and GitHub/GitLab/Bitbucket receivers; the open design
questions were who executes (panel vs node), how deploys stay reversible,
and how push triggers authenticate.

## Decision

### 1. The node executes; the panel orchestrates and owns the registry

WordPress installs, staging clones and git deploys run ON THE NODE through
the agent; the panel owns the registries (`installed_applications`,
`git_deployments`, `staging_environments`) and the orchestration
(database provisioning through B09 `DatabasesService`, so engine lock,
package quotas and SecretBox credential handling apply unchanged).

### 2. WP-CLI always runs as the account user — never root

Agent-side, every wp-cli invocation is wrapped in
`runuser -u <account> --` on root agents (dev rigs exec directly and the
result states `executed_as` honestly, D-11). Consequences:

- Files WP creates (uploads, plugin installs) are owned by the account —
  no root-owned surprises that later break updates.
- Credential posture (C15 discipline): DB credentials ride the SIGNED
  command channel and land ONLY inside `wp-config.php` (0600,
  account-owned). The WP admin password is GENERATED on the agent (32
  chars), fed to wp-cli via STDIN (`--prompt` — never argv, never the WAL),
  returned ONCE in the command result, and never persisted anywhere.
- `apps.wp_cli` is a maintenance pass-through with a verb allowlist
  (core|plugin|theme|user|search-replace|cache|rewrite|option) —
  deliberately NOT a generic exec hatch (`eval`/`shell` refused).

### 3. One-click staging clone = fresh DB + copy + search-replace

`apps.staging_clone`: copy the install tree as the account user, rewrite
the COPIED `wp-config.php` DB constants to a fresh database (provisioned
first through B09 policy), dump/import, then `wp search-replace`
prod→staging URL (guid columns skipped). The panel publishes the clone on
`<label>.<domain>` through the standard subdomain path (vhost + registry).
The prod install is never modified; the dump file is deleted when done.

### 4. Deploys are release directories + an atomic symlink swap

Every deploy clones into
`<home>/.nexus-git/<domain>/releases/<unix-ts>-<sha7>/` and the deploy
path becomes an ATOMIC SYMLINK to the active release. The releases
directory IS the deploy history — `git.deploy_history` reads it and
`git.rollback` re-points the symlink to an older release. Nothing is
deleted by deploys; pruning is a separate explicit flow. Safety rails:
`GIT_TERMINAL_PROMPT=0` (a hung clone can never wait for input), repo
URLs must be https/ssh (no `file://`, and credential-embedded URLs are
rejected by the URL grammar), the deploy path must be absent or a symlink
(a real populated docroot is NEVER silently replaced), deploys are
best-effort chowned to the account user.

### 5. Push triggers: one receiver, provider-verified

`POST /git/webhook/{id}` is `@Public` and authenticates by signature only:
GitHub (`X-Hub-Signature-256`, timing-safe), GitLab (`X-Gitlab-Token`),
Bitbucket (`X-Hub-Signature`). The per-deployment secret is generated at
registration, shown ONCE, stored SecretBox-encrypted
(`webhook_secret_enc`, ADR-0009), and never returned or audited. Non-push
events and non-configured branches are answered honestly with
`{ status: 'ignored', reason }` — they never deploy. Pushes deploy with
the pushed sha pinned (`checkout --detach`); the same executor powers the
panel's "Deploy now" and the B13 retry handler (`git.deploy`, keyed by
deployment id).

### 6. Permissions

`apps:read`/`apps:manage` and `git:read`/`git:manage`/`git:deploy` join the
C6 vocabulary (both control-plane and web mirrors in lockstep —
`permissions:check` enforces). Route permission is the coarse gate;
account-scoped visibility is re-checked in the services (404
anti-enumeration, §3.2).

## Consequences

- Agent surface delta: `apps.install_wordpress`, `apps.update_wordpress`,
  `apps.wp_cli`, `apps.staging_clone`, `git.deploy`,
  `git.deploy_history` (read-only), `git.rollback`.
- Job center: `apps.install_wordpress` and `git.deploy` mirror into
  `jobs_metadata` (visible state); `git.deploy` retries via the explicit
  handler allowlist.
- Exit evidence (B14): WP install test with stdin-password assertion;
  staging-clone test proving prod config untouched and staging config
  0600; git deploy/rollback E2E against a real local bare repo through a
  git shim; webhook signature tests for all three providers (bad
  signature → 401, wrong branch → honest ignore); control-plane specs
  proving admin passwords and webhook secrets never appear in audits,
  storage or logs.
- Honest gaps (D-11): deploy "build logs" are the clone/checkout logs —
  there is no build-step runner in v1.0. Staging promotion (staging →
  prod) is a separate flow, not part of the clone.
