# NexusPanel

A self-hosted, security-first hosting control panel — a "hosting OS." An unprivileged
NestJS control plane, a single privileged Go agent per node (typed, signed commands —
no `exec()` primitive), a Next.js UI, out-of-process extensions, and a tamper-evident
hash-chained audit log.

**Status:** P0 — Foundations (see [docs/plan/BUILD_PLAN.md](docs/plan/BUILD_PLAN.md))

## Repository layout

| Path | What it is |
|---|---|
| `specs/` | **Normative specification set** — governs all implementation |
| `apps/control-plane/` | NestJS API (never runs as root) |
| `apps/agent/` | Go privileged agent (the only process with system access) |
| `apps/web/` | Next.js web UI |
| `packages/sdk-ts/` | Generated TypeScript SDK (from OpenAPI) |
| `packages/cli/` | `nexus` CLI |
| `infra/` | Installer, cloud-init, provisioning |
| `docs/` | Build plan, ADRs, user documentation portal |
| `e2e/` | End-to-end test suites |

## Quick start (development)

```bash
# 1. Dev databases (PostgreSQL 16 + Valkey; schema auto-loads from specs/)
docker compose -f docker-compose.dev.yml up -d

# 2. Control plane (port 3000)
npm install --workspace apps/control-plane
npm run dev --workspace apps/control-plane

# 3. Agent (dev mode — unsigned commands allowed only with NEXUSAGENT_DEV_MODE=1)
cd apps/agent && go build -o bin/nexuspanel-agent ./cmd/agent
sudo NEXUSAGENT_DEV_MODE=1 ./bin/nexuspanel-agent --socket /tmp/nexuspanel-agent.sock

# 4. Web UI (port 5173)
npm install --workspace apps/web
npm run dev --workspace apps/web
```

## Specification set

Everything in `specs/` is normative. Code that contradicts it is a bug; changes
require an ADR per the Engineering Constitution (§P.6). Start with
[specs/README.md](specs/README.md).

## Security model in one paragraph

The control plane never touches the system. Every mutation is a typed command on a
closed allowlist, sent as JSON-RPC 2.0 over a Unix socket with mTLS, signed with the
control plane's Ed25519 key (60-second validity window). Secrets are age-encrypted at
rest (XChaCha20-Poly1305, HKDF-derived per-purpose keys). Every privileged action lands
in a SHA-256 hash-chained audit log with daily verification. See
[specs/nexuspanel-security-model-v1.0.md](specs/nexuspanel-security-model-v1.0.md).

## License

Not yet chosen — owner decision pending (D-9). All rights reserved until then.
