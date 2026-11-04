# infra/ — Installer & provisioning

Owned by WS1 (DevOps/SRE). The installer spec (`nexuspanel-installer-spec-v1.0.md`)
is authored during P0/P1 against the proven installation path — deliberately
deferred until implementation choices are real (spec set §"Where We Are").

Planned contents:

| Path | Purpose |
|---|---|
| `install.sh` | Single-node installer: deps, hardening baseline, panel DB, keys, systemd units |
| `cloud-init/` | Fresh-Ubuntu-LTS → installer automation (gap G-15) |
| `systemd/nexuspanel-agent.service` | Unit per agent spec §2 (capabilities, hardening) |
| `systemd/nexuspanel-api.service` | Control-plane unit (unprivileged user) |
| `observability/` | Optional Prometheus + Grafana profile (gap G-16, lands v0.5) |

Non-negotiables carried into the installer spec:

- Control plane runs unprivileged; the agent is the ONLY root-adjacent process
  (explicit capability set, no auto-root).
- Master key generated at install, `/etc/nexuspanel/keys/` 0400 root, offline
  backup prompt (security model §3.1).
- Self-update only from cosign-signed manifests (C19/C20).
