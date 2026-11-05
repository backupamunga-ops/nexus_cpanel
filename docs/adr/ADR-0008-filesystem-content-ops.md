# ADR-0008: Filesystem content operations live in the agent, specified as an explicit §4.3 amendment

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P3 (sites, files, SSL, config engine)
- **Deciders:** Backend #1 (control plane), Backend #2 (agent), Tech Lead review per BUILD_PLAN §1

## Context

Agent spec §4.3 defines `filesystem.mkdir/chown/chmod/delete/trash_purge/quota/usage`
and adds a note: *"File content operations — upload, download, edit — go
through the control plane's file service, not the agent. The agent handles
metadata and permission ops."*

The P3 file manager needs those content operations. The note as written is
physically impossible: file bytes live on the hosting node, the control
plane has no filesystem access to them, and the agent is the only I/O path
into a hosting account (that is the whole point of the privileged-agent
architecture, master spec §7). Reading the note charitably — "the control
plane's *file service* orchestrates" — still leaves the agent-side methods
unspecified, and unspecified methods cannot join a signed-command allowlist.

## Decision

Agent spec §4.3 is amended (this ADR is the amendment record) with five
content/read methods, implemented under the same rules as every existing
command:

| Method | Params | Notes |
|---|---|---|
| `filesystem.list` | `username, path` | Confined; dirs-first sort; 2 000-entry cap with total count |
| `filesystem.read` | `username, path` | Regular files only; base64; 10 MiB cap with explicit `truncated` flag |
| `filesystem.write` | `username, path, content_b64, mode?, overwrite` | Parent must exist; opt-in overwrite; atomic swap; ownership best-effort with reported skip on non-root agents |
| `filesystem.move` | `username, from, to, overwrite?` | Rename within confinement; powers `/files/move` and trash restore |
| `filesystem.trash_purge` | (§4.3, behavior specified) | Removes `.nexus-trash/<timestamp>-<name>` entries older than `before_date`; returns the removed list for ledger reconciliation |

Not amended, deliberately:

- `filesystem.chown` (§4.3) is **still unimplemented** — handing arbitrary
  uid/gid values to a signed command needs its own privilege story (P4).
- `filesystem.quota` (§4.3) lands with disk-quota enforcement (P4).

All methods remain path-confined (`C13` round-2 confinement, symlink-aware),
size-capped, WAL-audited, and read-only methods (`list`, `read`, `usage`)
join the control-plane-unreachable read set per agent spec §6.

## Consequences

- The file manager ships as a vertical slice: control-plane file service
  (permissions, ownership checks, trash ledger) + agent execution.
- The agent registry stays an explicit allowlist; no generic read/write
  escape hatch exists.
- Trash ledger reconciliation: the control plane stores `trash_entries`
  rows; the agent's purge return value is authoritative for what actually
  left the disk, and the ledger is reconciled against it.
- The web UI labels SSH keys and any other DB-only records honestly
  ("stored — not yet deployed to the node", D-11) until their agent
  deployment paths land.
