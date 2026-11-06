# NexusPanel — Step-by-Step Installation Guide

**Audience:** anyone who can open a terminal — you do not need to be a system
administrator. Every command below was executed verbatim on a real server
(Ubuntu 26.04.1 LTS, 4 vCPU / 6 GB / 100 GB, November 2026) during the
live-VM acceptance run; the "you should see" outputs are the real ones.

| Time | ~10–15 minutes (plus ~2 min of prompts) |
|---|---|
| You need | A fresh server, its root SSH login, a terminal |
| You get | A running panel: web UI + API + node agent, hardened baseline |

## 0. Get a server

Any provider works (the acceptance host is a Leaseweb KVM VPS). Requirements
per `docs/release/SUPPORT_MATRIX.md`:

- **OS:** Ubuntu 22.04 / 24.04 / 26.04 LTS or Debian 12/13 (amd64)
- **Size:** 2 vCPU, **4 GB RAM minimum** (the web build is memory-hungry),
  40 GB disk — more if you will host sites
- Fresh/empty — the installer expects to own the box

## 1. Connect to the server

From your own computer:

```bash
ssh root@YOUR_SERVER_IP
```

(Your provider shows you the IP and the initial root password. If you use a
cloud provider's web console, open a root shell there instead.)

## 2. Get the code

```bash
apt-get update -qq && apt-get install -y -qq git
mkdir -p /opt && git clone https://github.com/backupamunga-ops/nexus_cpanel.git /opt/nexuspanel
cd /opt/nexuspanel
```

You should see the clone progress and end with `Receiving objects: 100%`.

## 3. Run the installer

```bash
sudo infra/install.sh 2>&1 | tee /root/install.log
```

(You are root if you logged in as root — `sudo` is then harmless.)

The installer runs 8 steps and prints one `✓` line per step. What it is
doing, in plain words:

| Step | What happens | You see |
|---|---|---|
| 1/8 | Installs PostgreSQL (≥16), Node.js, Go, firewall, fail2ban, auto-updates | `packages installed: 18.6, v22.22.1, go version …` |
| 2/8 | Creates the panel database, applies the 56-table schema | `DDL applied (56 tables)` |
| 3/8 | Generates the signing key + master key (root-owned, service-readable) | `keys written` |
| 4/8 | Writes the environment file `/etc/nexuspanel/nexuspanel.env` (0640) | `environment written` |
| 5/8 | Builds control plane, web UI, agent binary (this is the quiet part — 3–8 min) | `built: control-plane dist, web .next, …` |
| 6/8 | Installs and starts the four systemd services, waits for each to answer | `units active — health gate passed` |
| 7/8 | **Asks you for the first admin login** (see below) | `super admin created and verified` |
| 8/8 | Enables the firewall, fail2ban, auto-updates; verifies the audit chain | `{"verified":true,…}` then `NexusPanel is installed.` |

**The two prompts you must answer:**

1. `admin email:` and `admin password (min 12 chars):` — this becomes the
   login you use in the browser. Pick something you will remember; the
   password is never written to any file. You type the password twice.
2. `Confirm you have backed it up [y/N]:` — see step 5 below before answering.

> Notes you don't need to act on: on brand-new Ubuntu releases the installer
> automatically uses the distro's own PostgreSQL when the PostgreSQL project
> hasn't published packages for it yet (`PGDG has no … dist — using the
> distro archive PostgreSQL` is normal), and the Go compiler likewise comes
> from your distro when new enough.

## 4. Check that everything is up

```bash
systemctl is-active nexuspanel-cgroups nexuspanel-agent nexuspanel-api nexuspanel-web
curl http://127.0.0.1:3000/api/v1/health
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5173/
```

Expected: `active active active active`, then `{"status":"ok"}`, then `200`.

## 5. Back up the keys — the one thing you must not skip

`/etc/nexuspanel/keys/` holds the signing key and the master key. Encrypted
data in the database **cannot be read without these files**. Copy them to
your own computer now (from your computer, not the server):

```bash
scp -r root@YOUR_SERVER_IP:/etc/nexuspanel/keys ./nexuspanel-keys-backup
```

Store the copy somewhere safe and offline (password manager, USB stick).
Then answer `y` to the installer's backup prompt if it is still waiting.

## 6. Open the panel in your browser

The panel does **not** expose its login page to the whole internet — only
SSH (22) and web (80/443) are open. You reach the UI through an encrypted
SSH tunnel. From **your computer**:

```bash
ssh -L 5173:127.0.0.1:5173 root@YOUR_SERVER_IP
```

Keep that window open, then browse to: **http://localhost:5173**

Log in with the admin email + password you chose in step 3. You will land on
the dashboard (grouped icon sidebar, light/dark toggle, top-right).

## Day-2 operations

```bash
cd /opt/nexuspanel
sudo infra/install.sh upgrade     # pull, rebuild, restart, health-gated
sudo infra/install.sh uninstall   # removes services; database+keys stay, you decide
```

## If something goes wrong

| Symptom | Where to look |
|---|---|
| Installer dies in step 5 (build) | The installer names the exact log: `/tmp/nexuspanel-npmci.log`, `/tmp/nexuspanel-prisma.log`, `/tmp/nexuspanel-build.log` |
| A service is not `active` | `journalctl -u nexuspanel-agent -e` (or `-api`, `-web`) |
| "keys already exist" on re-run | A previous install left keys — this is deliberate (never silent rotation). Use `upgrade`, or move `/etc/nexuspanel` away if you truly want a fresh start |
| "unsupported OS" | See the support matrix above; the installer is honest about what it tested |
| Web page won't load through the tunnel | Check the tunnel window is still connected and `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5173/` on the server says `200` |

## What the installer does NOT do (on purpose)

- No TLS certificate on 80/443 yet — the web/API stay loopback-only until
  you put your own reverse proxy in front (planned installer phase).
- No DNS/mail/backup stacks — the panel **manages** those once installed
  (the panel's DNS, Email, Backups pages drive them); see
  `docs/runbooks/acceptance-p4-p7.md` for the operator prep of each.

## Honest status of this guide

| Item | Status |
|---|---|
| Install path end-to-end | **proven on live hardware** 2026-11-06 (Ubuntu 26.04.1, 10 findings found & fixed during the run — they are the troubleshooting table above) |
| Reboot survival (all 4 units + cgroup root) | **proven** |
| Ubuntu 22.04 / 24.04 / Debian 12 | expected to work (same steps) — not yet acceptance-run |
