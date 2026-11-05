# Runbook — M0 vertical slice on a fresh VM (M0 scope §2, A1)

End-to-end bring-up of the M0 thread: **login → create hosting account →
signed command → agent creates the Linux user + cgroup v2 slice →
hash-chained audit entry → UI shows live usage**.

Every command below is copy-pasteable. Nothing in this file is speculative:
flags, ports and env names are taken from the code as of `b598bee`.

## 0. Prerequisites

| Requirement | Notes |
|---|---|
| Ubuntu 22.04+ / Debian 12 VM | 2 vCPU / 4 GB RAM is enough for M0 |
| Root or passwordless sudo | The **agent** runs as root; the control plane must NOT |
| Docker + compose plugin | `docker compose version` must work |
| Node.js ≥ 20 | control plane + web (npm workspaces) |
| Go ≥ 1.23 | only to build the agent |
| git | to clone the repo |

## 1. Clone and boot the data stack

```bash
git clone https://github.com/backupamunga-ops/nexus_cpanel.git
cd nexus_cpanel

make db-up        # PostgreSQL 16 + Valkey 8 (docker-compose.dev.yml)
```

The compose file bind-mounts `specs/nexuspanel-schema-v2.0.sql` into
`/docker-entrypoint-initdb.d/`, so the **first** boot applies the canonical
38-table DDL automatically. The DDL is the single source of truth
(ADR-0004); Prisma is generated from it and CI checks the drift
(`npm run prisma:check`).

> Resetting later: `make db-down && docker volume rm nexuspanel_nexuspanel_pgdata`
> (volume name as printed by `docker volume ls`), then `make db-up` again —
> init scripts only run on an empty data directory.

## 2. Configure the control plane

```bash
cp .env.example .env
```

Edit `.env`:

- `DATABASE_URL` — the compose default
  `postgresql://nexuspanel:nexuspanel-dev-only@localhost:5432/nexuspanel`
  works unchanged.
- `DEV_ADMIN_EMAIL` / `DEV_ADMIN_PASSWORD` — set both; the control plane
  seeds this super-admin into `users` on boot (dev only, leave unset in
  production).
- `CP_SIGNING_KEY_PATH` — leave the default
  `./dev-keys/control-plane-signing.key`; step 3 creates that file.
- `CP_SECRETS_KEY_PATH` — leave the default `./dev-keys/secrets.key`; step 3
  creates that file too. It encrypts 2FA secrets and backup codes at rest
  (C9 seam). Without it the panel boots fine, but `/auth/2fa/*` returns 503.
- `AUTH_JWT_SECRET` — set a ≥ 32-char random string so issued sessions
  survive control-plane restarts (absent = ephemeral per-boot secret).

The control plane reads `process.env` directly (no dotenv shim), so export
the file into your shell before starting it:

```bash
set -a; source .env; set +a
```

## 3. Provision the Ed25519 command-signing keypair

```bash
npm install                     # workspaces: control-plane, web, packages
npm run keys:generate --workspace apps/control-plane
```

This writes `dev-keys/control-plane-signing.key` (mode 0600, used by the
control plane via `CP_SIGNING_KEY_PATH`),
`dev-keys/secrets.key` (base64 master key for the SecretBox, via
`CP_SECRETS_KEY_PATH`; existing keys are never overwritten) and
`dev-keys/control-plane-signing.pub` (raw base64, given to the agent).
**Never commit `dev-keys/`** — it is already gitignored.

## 4. Run the control plane

```bash
make cp-dev                     # ts-node src/main.ts, port 3000
```

Health check (public, no auth):

```bash
curl -s http://localhost:3000/api/v1/health | head -c 200
```

Expected: a JSON health body. The API prefix is `/api/v1`; authenticated
WebSocket events are served at `ws://localhost:3000/events`.

## 5. Build and run the agent (root, signatures ON)

```bash
make agent                      # go build -o bin/nexuspanel-agent ./cmd/agent
sudo ./bin/nexuspanel-agent \
  --socket /tmp/nexuspanel-agent.sock \
  --signing-pubkey "$(pwd)/dev-keys/control-plane-signing.pub"
```

- Run as **root without `--dev`**: creating users and cgroup slices needs
  privileges, and `--dev` (unsigned commands) refuses to start as root
  unless `NEXUSAGENT_DEV_MODE_ROOT_OK=1` is also set — do not do that on a
  VM you care about.
- The socket path must match `AGENT_SOCKET_PATH` in the control plane env
  (`/tmp/nexuspanel-agent.sock`).
- The agent serves reads (`account.usage`, `account.list`, `system.health`,
  `system.info`) even when the control plane is down; while offline it
  queues audit entries in its WAL (`--wal-dir`) and drains them on
  reconnect. Mutations while offline are rejected with `-32005`.

## 6. Run the web UI

```bash
make web-install
make web-dev                    # next dev -p 5173
```

Open `http://localhost:5173`, log in with the dev admin from step 2, go to
**Accounts**, and create a username (policy: `^[a-z][a-z0-9-]{0,31}$`,
reserved system names rejected).

## 7. Verify the flow on the node

After creating `alice` in the UI:

```bash
id alice                                        # OS user exists (agent did useradd)
ls /sys/fs/cgroup/nexuspanel/                   # cgroup v2 slice (isolation.provision)
cat /sys/fs/cgroup/nexuspanel/alice/memory.current
```

Audit chain verification (authenticated):

```bash
TOKEN=$(curl -s http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"'"$DEV_ADMIN_EMAIL"'","password":"'"$DEV_ADMIN_PASSWORD"'"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -s -X POST http://localhost:3000/api/v1/audit/verify \
  -H "Authorization: Bearer $TOKEN"
```

Expected: `{"verified": true, ...}` — the hash chain covers
`account.create` and `isolation.provision` entries. The UI's Accounts view
shows live usage for the account, sampled by the server from the agent's
`account.usage` and pushed over `/events`.

## 8. Negative checks mapped to acceptance criteria

| Criterion | Check |
|---|---|
| A2 tamper → `-32000` | Covered by `apps/agent/internal/auth` unit tests (CI); on-VM: modify any byte of a captured command body and replay → rejected, agent logs a security event |
| A3 expiry → `-32003` | Covered by the same suite (`expires_at` window); the control plane signs with a 30 s window |
| A4 offline WAL | Stop the control plane (Ctrl-C) → agent keeps serving reads, rejects `account.create` with `-32005`; restart the control plane → WAL drains |
| A5 mid-chain tamper | UPDATE any `audit_entries` row in PostgreSQL → `POST /audit/verify` reports `verified: false` with the failing entry index |
| A6 real usage | Run something as `alice` (`sudo -u alice dd if=/dev/zero of=/home/alice/f bs=1M count=64`) → usage moves in the UI / `GET /api/v1/accounts/:id/usage` |

## 9. What M0 deliberately does not do

Sites, mail, DNS, databases, SSL, backups, apps, resellers, the drift
detection loop and multi-node are P2+ (M0 scope §4). `account.modify` and
`account.quota` are registered but return "not implemented until a later
milestone".
