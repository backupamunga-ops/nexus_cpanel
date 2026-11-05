# ADR-0010: `ssh.*` agent category — authorized_keys managed-line reconciliation

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P3→P4 amendment (SSH key deployment)
- **Deciders:** Backend #2 (agent), Backend #1 (control plane), Tech Lead review per BUILD_PLAN §1

## Context

SSH keys are imported panel-side (API spec §4.13): strict key-type
allowlist, OpenSSH SHA-256 fingerprint computed at import. Until now they
were **stored only** — the UI and docs label them "stored — not yet
deployed to the node" (D-11 honesty), and the master doc's gap register
records the deployment step as a *P4 amendment*. That amendment is this
ADR: the agent spec §4 has no `ssh.*` category, and deployment is a
privileged node-side write — it must join the signed-command allowlist,
not bypass it.

Two constraints shape the design:

1. A user may keep hand-added keys in `~/.ssh/authorized_keys`. A panel
   that rewrites the whole file would delete them on every deploy —
   unacceptable.
2. The panel must never *claim* a key it did not deploy (and must be able
   to observe the node's actual state, not a database flag that can rot).

## Decision

Agent spec §4 is amended with an `ssh.*` category (this ADR is the
amendment record), implemented under the same rules as every existing
command:

| Method | Params | Notes |
|---|---|---|
| `ssh.deploy_keys` | `username, keys[{fingerprint, public_key}]` | Reconciles the **managed lines** of `~/.ssh/authorized_keys` (full replace of managed set, foreign lines preserved verbatim); ≤ 50 keys; key-type allowlist mirrors the panel import; `~/.ssh` 0700, file 0600, ownership via the standard best-effort policy with reported skip |
| `ssh.list_deployed` | `username` | Read-only (§6): returns `{file, exists, managed[{fingerprint, public_key}], foreign_count, ownership}` parsed from the live file |

**Managed-key convention:** every line the panel writes ends with a
` nexus-managed:<fingerprint>` comment token. `deploy_keys` drops exactly
the lines carrying that marker and replaces them with the requested set
(sorted by fingerprint); a line without the marker is foreign and is
never touched. An empty `keys` array therefore removes only panel-managed
keys — a hand-added key survives every reconcile.

**Consequences:**

- Deployment state is not cached in the database. The panel derives "on
  node" truth live from `ssh.list_deployed` matched against imported
  fingerprints — nothing can rot, and the UI badge is honest by
  construction (D-11).
- A user who manually copies a panel-managed line (marker included) makes
  it panel-managed on the next reconcile — documented, intended: the
  marker means "the panel owns this line".
- The fingerprint is opaque to the agent (single whitespace-free token);
  the control plane owns the `SHA256:...` format from the import flow.
- `authorized_keys` itself is not a drift-tracked config target: it is
  user data inside the account home, reconciled explicitly, not rendered
  by the panel.

Alternatives rejected: reusing `filesystem.read/write` from the control
plane (no managed-line semantics — the whole-file rewrite footgun above),
and a database `deployed_at` flag (cached state that lies after any
out-of-band edit).
