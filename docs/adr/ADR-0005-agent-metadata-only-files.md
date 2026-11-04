# ADR-0005: Agent filesystem commands are metadata-only; file content flows through the control plane

- **Status:** Accepted (Batch 1 sign-off item, confirmed by owner default D-3)
- **Phase:** P0

## Context

The agent spec's `filesystem.*` category covers mkdir/chown/chmod/delete/quota/usage —
metadata and permission operations. Upload/download/edit of file **content** is not in
the agent allowlist.

## Decision

Confirmed split: the **agent** performs confined metadata operations; the **control
plane** serves file content (uploads, downloads, editor) under its own permission and
audit regime. The agent gains no generic read/write primitive — preserving the
"typed allowlist, no exec()" guarantee.

## Consequences

- Large file transfer performance is a control-plane concern (streaming, chunking).
- Agent attack surface stays minimal; content handlers get their own security review.
- Fuzzing (C13) applies to both surfaces independently.
