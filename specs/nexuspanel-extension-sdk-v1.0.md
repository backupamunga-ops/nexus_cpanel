> Source: normative specification — Batch 2 (interfaces), imported 2026-11-05.
> Status: NORMATIVE. Changes require an ADR per the Engineering Constitution (§P.6).


## 1. Overview

NexusPanel extensions are **out-of-process services** that communicate with the control plane over a defined protocol. Extensions cannot modify core source, cannot run in the panel process, and cannot exceed their declared permission scopes.

**Why out-of-process:** An extension that runs in-process can crash the panel, leak memory into the panel, bypass audit, and escape its scope. Out-of-process extensions are isolated at the OS process level, communicate only through a versioned protocol, and are audited at every boundary.

**Cost:** Extensions cannot intercept arbitrary internal events or monkey-patch behavior. They can only act on declared hooks. We accept this — it's the same trade-off WordPress learned the hard way (in-process plugins = inevitable security incidents).

## 2. Extension Types

| Type | Description | Example |
|---|---|---|
| **Widget** | UI component rendered in a defined slot (dashboard, site detail, mailbox detail) | Server status widget, backup-count widget |
| **Action** | User-invoked action with parameters and output | "Clone site to new domain", "Bulk-import email from CSV" |
| **Integration** | Reacts to panel events; sends to external services | Slack notifications, PagerDuty alerts, Stripe billing sync |
| **Provider** | Implements a panel interface for an external backend | External SMTP relay provider, external DNS provider |
| **Reporter** | Periodically collects data and posts to an external service | Uptime reporter, license reporter |

An extension may declare multiple types.

## 3. Extension Lifecycle

1. **Develop** — developer builds a service implementing the extension protocol; packages as OCI image (recommended) or standalone binary.
2. **Register (dev mode)** — server admin installs with `nexus extensions install --dev <manifest-url>`; the extension registers with the control plane via `/extensions/register`.
3. **Scope review** — the admin sees the extension's requested permission scopes and either approves or rejects.
4. **Enable** — upon approval, the extension receives its `extension_id` and shared secret, and its callback URL is registered.
5. **Operate** — the control plane calls the extension's endpoints on hooks and widget requests; the extension calls back to the control plane via `/api/v1/ext/*` endpoints (scoped to its token).
6. **Disable/Uninstall** — the control plane revokes the token, deregisters callbacks; the extension's data (in its own storage namespace) is retained or purged per the admin's choice.

## 4. Extension Manifest

Every extension provides a manifest at `<extension-url>/nexuspanel-manifest.json`:

```json
{
  "name": "Acme Backup Reporter",
  "slug": "acme-backup-reporter",
  "version": "1.2.0",
  "author": "Acme Inc <support@acme.example>",
  "description": "Reports backup success/failure to Acme's monitoring.",
  "license": "MIT",
  "homepage": "https://acme.example/nexus-backup-reporter",
  "nexuspanel_compat": { "min": "1.0.0", "max": "1.99.99" },
  "types": ["integration", "widget"],
  "permissions": [
    "backup:read",
    "account:read"
  ],
  "endpoints": {
    "register": "/register",
    "heartbeat": "/heartbeat",
    "widgets": {
      "backup-status": { "slot": "dashboard.main", "entry": "/widgets/backup-status" }
    },
    "hooks": {
      "backup.completed": "/hooks/backup-completed",
      "backup.failed": "/hooks/backup-failed"
    }
  },
  "ui": {
    "settings_url": "/ui/settings"
  }
}
```

**Manifest rules:**
- `slug` is the unique identifier; must match `[a-z0-9][a-z0-9-]{2,63}`.
- `version` is SemVer.
- `nexuspanel_compat` declares the panel versions the extension supports; the panel refuses to enable an incompatible extension.
- `permissions` must be from the closed list in §6. Unknown scopes → registration rejected.
- `endpoints` are URLs the extension will respond to. The panel calls these.
- `ui.settings_url` (optional) is a URL the panel will embed in an iframe in the extension's settings page.

## 5. Extension Protocol

### 5.1 Registration

Extension → Panel:

```
POST /api/v1/extensions/register
Content-Type: application/json

{
  "manifest": { ... },
  "callback_base_url": "https://acme.example/ext/nexuspanel",
  "health_check_url": "https://acme.example/ext/nexuspanel/health"
}
```

Panel responds with:

```json
{
  "extension_id": "uuidv7",
  "shared_secret": "<one-time, base64>",
  "panel_base_url": "https://panel.example.com/api/v1/ext",
  "issued_at": "ISO8601"
}
```

The extension stores `shared_secret` securely. Every callback the panel makes to the extension includes:

```
X-Nexuspanel-Extension-Id: <uuidv7>
X-Nexuspanel-Timestamp: <unix seconds>
X-Nexuspanel-Signature: base64(hmac_sha256(shared_secret, method + path + body + timestamp))
```

The extension must verify the signature and reject if `|now - timestamp| > 60s`.

### 5.2 Panel → Extension Calls

| Call | When | Payload |
|---|---|---|
| `GET <register>` | Registration confirmation | `{extension_id, panel_version, panel_base_url}` |
| `GET <health_check_url>` | Every 60s | Expects `200` with `{status:"ok"}` |
| `POST <hooks.<event>>` | When a subscribed event fires | `{event_type, event_id, occurred_at, payload}` |
| `GET <widgets.<id>.entry>` | When the panel renders a widget slot | `{user_id, hosting_account_id?, context}` |
| `GET <ui.settings_url>` | When the admin opens extension settings (iframe) | N/A (rendered in browser) |

Panel → extension calls all use the standard signature headers.

### 5.3 Extension → Panel Calls

The extension can call the panel using its scoped API token (derived from `shared_secret` at registration time and rotated on uninstall/re-register). Scoped calls go to `/api/v1/ext/*` — a namespaced version of the API that enforces the extension's scopes and audit-logs every call.

**Example:** an extension with `backup:read` scope calls:

```
GET /api/v1/ext/backups/runs
Authorization: Bearer <derived-token>
```

The panel:
1. Validates the token.
2. Confirms the endpoint is within the extension's declared scopes.
3. Confirms the extension is enabled.
4. Rate-limits per extension (default: 60/min).
5. Writes an audit entry attributed to `extension:<slug>`.
6. Returns the response.

Extensions **cannot** call the main `/api/v1/*` API endpoints. Only `/api/v1/ext/*`. This is enforced at the routing layer.

## 6. Permission Scopes

Closed list. Extensions may only request from this set. Adding a scope requires a panel version bump and re-review.

| Scope | Grants |
|---|---|
| `account:read` | List and read hosting accounts (own reseller's scope) |
| `site:read` | Read domains, subdomains, PHP config |
| `site:write` | Create/update/delete domains (requires admin confirmation of each call in v1.0) |
| `mail:read` | Read mail domains, mailboxes |
| `mail:write` | Create/update mailboxes (same confirmation rule) |
| `dns:read` | Read zones and records |
| `dns:write` | Modify DNS (same confirmation rule) |
| `db:read` | Read databases |
| `ssl:read` | Read certificates |
| `backup:read` | Read backup jobs and runs |
| `backup:write` | Trigger backups, restores (same confirmation rule) |
| `audit:read` | Read audit entries |
| `notification:write` | Create in-panel notifications |
| `user:read` | Read user accounts (never passwords/2FA) |
| `events:subscribe` | Subscribe to webhook-style events |

**Write scopes** are marked "requires confirmation" — in v1.0, every write performed by an extension requires an admin approval per call (via a confirmation queue). v1.x relaxes this to per-extension trust levels after the extension has demonstrated trustworthiness. This is deliberate; write access by third-party code is the highest-risk surface.

**Forbidden:** `password:read`, `2fa:read`, any scope granting direct access to secrets.

## 7. Widget Rendering

Widgets are rendered in an **iframe** inside the panel. The iframe:

- Is sandboxed: `sandbox="allow-scripts allow-same-origin"` (no `allow-top-navigation`, no `allow-popups` by default).
- Sends `postMessage` to the panel to request context (user_id, hosting_account_id, panel theme tokens).
- Receives `postMessage` from the panel with context on ready.
- Renders using its own styles (no panel CSS injection) but should respect the theme tokens passed via `postMessage`.

**Theme tokens passed to widget:**
```json
{
  "mode": "dark",
  "primary": "#6366f1",
  "background": "#0a0a0a",
  "foreground": "#fafafa",
  "font_family": "Inter",
  "border_radius": "8px"
}
```

Widgets cannot set cookies, cannot access panel storage, cannot read the panel's DOM.

## 8. Extension Storage

Extensions cannot access the panel's PostgreSQL. They declare in their manifest whether they need storage:

```json
"storage": {
  "type": "postgres_namespace",
  "name": "acme_backup_reporter"
}
```

The panel provisions a dedicated PostgreSQL schema (not database) named exactly as declared, owned by a dedicated role. The extension receives connection credentials at registration. Extensions that don't declare storage get none — they must persist their own state externally.

**Isolation:** the extension's role has no access to any other schema. `REVOKE ALL ON SCHEMA public` from extension roles.

## 9. Extension Updates

An extension update requires:

1. New manifest with a higher `version`.
2. Version-compatibility check: the new version's `nexuspanel_compat` must still include the running panel version.
3. Scope diff review: if the new version requests *new* scopes, the admin must re-approve those scopes. If it drops scopes, no re-approval needed.
4. Registration refresh: the panel re-issues the shared secret and the extension re-registers.

## 10. Distribution and Marketplace (Delivery Advanced)

In v1.0, extensions are installed by pointing at a manifest URL. There is no marketplace. v2.0 adds:

- A marketplace index (reviewed extensions).
- Signing of manifests by the marketplace.
- Rating, install counts, changelogs.
- Revenue share for paid extensions.

The v1.0 protocol is designed to be forward-compatible: a marketplace is an index of manifest URLs plus metadata, not a new protocol.

## 11. Reference Example Extension

An example extension is delivered as part of the SDK: `nexus-example-reporter`, a `integration` type that:

- Subscribes to `backup.completed` and `backup.failed`.
- Posts a summary to a user-configured webhook URL.
- Renders a "Last backup" widget on the dashboard.

Its full source (~300 lines of Node.js) is the acceptance test for the SDK — it must run end-to-end against a fresh panel install with no panel modification.

## 12. Extension Compatibility Promise

An extension built against SDK v1.0 will continue working across:

- All NexusPanel v1.x releases (MINOR and PATCH).
- The first MAJOR release after v1.x — with a deprecation period of at least 2 MINOR releases and a migration guide.

The SDK is versioned separately from the panel: `sdk:v1.0`. A panel running v1.5 accepts extensions declaring `sdk_compat: ">=1.0.0 <2.0.0"`.

---
