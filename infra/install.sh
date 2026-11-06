#!/usr/bin/env bash
# =============================================================================
# NexusPanel single-node installer v1.0
# Implements docs/release/INSTALLER_V1.md (NORMATIVE) — each step maps 1:1 to
# the proven path in docs/runbooks/m0-fresh-vm.md, with native PostgreSQL 16
# instead of the dev compose stack.
#
#   sudo infra/install.sh            # fresh install
#   sudo infra/install.sh upgrade    # §5: pull, rebuild, restart, verify
#   sudo infra/install.sh uninstall  # §4: remove units; data decisions stay yours
#
# Non-negotiables (installer spec §1):
#   - the control plane NEVER runs as root — every privileged operation is a
#     signed Ed25519 command to the agent;
#   - the agent is the ONLY root-adjacent process;
#   - keys are generated once, /etc/nexuspanel/keys/ 0400 root — the installer
#     FAILS LOUDLY if keys already exist, it never rotates silently;
#   - the first super admin is created interactively, written nowhere.
# =============================================================================
set -euo pipefail

NEXUS_HOME="${NEXUS_HOME:-/opt/nexuspanel}"
NP_ETC=/etc/nexuspanel
NP_KEYS="$NP_ETC/keys"
NP_ENV_FILE="$NP_ETC/nexuspanel.env"
NP_SVC_USER=nexuspanel
NP_DB_NAME=nexuspanel
NP_DB_USER=nexuspanel
GO_VERSION=1.23.4
NODE_MAJOR=20

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ✓ \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

repo_root() {
  [ -d "$NEXUS_HOME/specs" ] && [ -d "$NEXUS_HOME/apps/control-plane" ] || die "
the installer must run from a checkout at $NEXUS_HOME:
  sudo mkdir -p $NEXUS_HOME && sudo chown \"\$USER\" $NEXUS_HOME
  git clone https://github.com/backupamunga-ops/nexus_cpanel.git $NEXUS_HOME
  cd $NEXUS_HOME && sudo infra/install.sh"
  echo "$NEXUS_HOME"
}

# --- step 0: preflight -------------------------------------------------------
preflight() {
  require_root
  REPO_DIR="$(repo_root)"
  if ! command -v lsb_release >/dev/null; then
    apt-get update -qq && apt-get install -y -qq lsb-release >/dev/null
  fi
  local distro ver
  distro="$(lsb_release -is)"; ver="$(lsb_release -rs)"
  case "$distro:$ver" in
    Ubuntu:22.*|Ubuntu:24.*|Ubuntu:26.*|Debian:12*|Debian:13*) ;; # supported per installer spec §1
    *) die "unsupported OS: $distro $ver (need Ubuntu 22.04+/Debian 12+)" ;;
  esac
  CODENAME="$(lsb_release -cs)"
  if [ -e "$NP_KEYS/control-plane-signing.key" ] || [ -e "$NP_KEYS/secrets.key" ]; then
    die "keys already exist under $NP_KEYS — refusing to rotate silently (installer spec §2.3).
Re-run only after moving them away deliberately, or use '$0 upgrade'."
  fi
  if getent passwd "$NP_SVC_USER" >/dev/null; then
    die "user $NP_SVC_USER already exists — a previous install may be present; uninstall first."
  fi
  ok "preflight: $distro $ver ($CODENAME), repo at $REPO_DIR"
}

# --- step 1: packages --------------------------------------------------------
install_packages() {
  log "step 1/8 — packages (postgresql ≥16, node ${NODE_MAJOR}, go ${GO_VERSION}, git, hardening)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg openssl git lsb-release >/dev/null

  # PostgreSQL — PGDG 16 when the codename is published; the distro archive
  # otherwise. PGDG lags brand-new Ubuntu releases (no resolute/26.04 dist at
  # the time of the live-VM acceptance run, whose archive ships PG 18) —
  # finding of that run; the DDL and Prisma target PostgreSQL ≥ 16 (ADR-0004).
  if curl -fsSI --max-time 20 \
      "https://apt.postgresql.org/pub/repos/dists/${CODENAME}-pgdg/Release" >/dev/null 2>&1; then
    PG_PKG=postgresql-16
    curl -fsSL "https://www.postgresql.org/media/keys/ACCC4CF8.asc" -o /usr/share/keyrings/postgresql.gpg
    echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt ${CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list
  else
    PG_PKG=postgresql
    log "  (PGDG has no ${CODENAME} dist — using the distro archive PostgreSQL)"
  fi
  # Node.js ${NODE_MAJOR} — NodeSource repo (manual keyring setup)
  curl -fsSL "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key" \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq
  apt-get install -y -qq "$PG_PKG" nodejs ufw fail2ban unattended-upgrades >/dev/null
  local pg_major
  pg_major="$(psql --version | sed -E 's/.*\) ([0-9]+).*/\1/')"
  [ "${pg_major:-0}" -ge 16 ] || die "PostgreSQL ≥ 16 required — archive offered ${pg_major:-unknown}"

  # Go toolchain — only for building the agent. Debian/Ubuntu archive versions
  # are too old for go.mod (go 1.23); use the official tarball. Verify the
  # sha256 against https://go.dev/dl/ — automated pin-verification arrives
  # with the cosign-signed updater (C19/C20), not before.
  if ! command -v go >/dev/null || ! go version | grep -q "go${GO_VERSION%%.*}"; then
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz
    echo "go tarball sha256: $(sha256sum /tmp/go.tgz | cut -d' ' -f1)  (compare with https://go.dev/dl/)"
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  fi
  ok "packages installed: $(psql --version | awk '{print $3}'), $(node --version), $(go version)"
}

# --- step 2: database --------------------------------------------------------
create_database() {
  log "step 2/8 — database role ${NP_DB_USER} + db ${NP_DB_NAME} + canonical DDL (ADR-0004)"
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  NP_DB_PASSWORD="$(openssl rand -hex 24)"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -qc "
    CREATE ROLE ${NP_DB_USER} LOGIN PASSWORD '${NP_DB_PASSWORD}';"
  sudo -u postgres createdb -O "$NP_DB_USER" "$NP_DB_NAME"
  # Apply the canonical DDL AS the service role: pgcrypto/citext/pg_trgm are
  # trusted extensions in PG13+, so the DB owner can create them; tables end
  # up owned by ${NP_DB_USER} — no grant choreography needed.
  PGPASSWORD="$NP_DB_PASSWORD" psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$NP_DB_USER" \
    -d "$NP_DB_NAME" -f "$REPO_DIR/specs/nexuspanel-schema-v2.0.sql" >/dev/null
  ok "DDL applied ($(PGPASSWORD="$NP_DB_PASSWORD" psql -h 127.0.0.1 -U "$NP_DB_USER" -d "$NP_DB_NAME" -tc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null | tr -d ' ') tables)"
}

# --- step 3: keys (never overwrite) ------------------------------------------
create_keys() {
  log "step 3/8 — keys under $NP_KEYS (Ed25519 signing pair + SecretBox master key)"
  install -d -m 0700 -o root -g root "$NP_KEYS"
  umask 077
  openssl genpkey -algorithm ed25519 -out "$NP_KEYS/control-plane-signing.key" 2>/dev/null
  # Raw base64 of the last 32 SPKI bytes — the exact format the agent's
  # --signing-pubkey flag consumes (same as the dev generator).
  openssl pkey -in "$NP_KEYS/control-plane-signing.key" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | base64 -w0 > "$NP_KEYS/control-plane-signing.pub"
  openssl rand -base64 32 > "$NP_KEYS/secrets.key"
  chmod 0600 "$NP_KEYS/control-plane-signing.key" "$NP_KEYS/secrets.key"
  chmod 0444 "$NP_KEYS/control-plane-signing.pub"
  umask 022
  ok "keys written (back them up offline — prompt at the end)"
}

# --- step 4: environment file -------------------------------------------------
write_env_file() {
  log "step 4/8 — $NP_ENV_FILE (0640 root:$NP_SVC_USER, sourced by both Node units)"
  getent group "$NP_SVC_USER" >/dev/null || groupadd --system "$NP_SVC_USER"
  useradd --system --gid "$NP_SVC_USER" --home-dir /var/lib/$NP_SVC_USER \
    --shell /usr/sbin/nologin --comment "NexusPanel services" "$NP_SVC_USER"
  install -d -m 0750 -o root -g "$NP_SVC_USER" "$NP_ETC"
  umask 027
  cat > "$NP_ENV_FILE" <<EOF
NODE_ENV=production
PORT=3000
GLOBAL_PREFIX=api/v1
DATABASE_URL=postgresql://${NP_DB_USER}:${NP_DB_PASSWORD}@127.0.0.1:5432/${NP_DB_NAME}
CP_SIGNING_KEY_PATH=${NP_KEYS}/control-plane-signing.key
CP_SECRETS_KEY_PATH=${NP_KEYS}/secrets.key
AUTH_JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')
AGENT_SOCKET_PATH=/run/nexuspanel/agent.sock
EOF
  umask 022
  chown root:"$NP_SVC_USER" "$NP_ENV_FILE"; chmod 0640 "$NP_ENV_FILE"
  ok "environment written (DEV_ADMIN_* deliberately absent — dev-rig only)"
}

# --- step 5: build -------------------------------------------------------------
build_artifacts() {
  log "step 5/8 — build (npm ci → prisma generate → workspaces build → agent binary)"
  cd "$REPO_DIR"
  npm ci --no-audit --no-fund >/dev/null 2>&1
  npm run prisma:generate --workspace apps/control-plane >/dev/null
  npm run build --workspaces --if-present >/dev/null
  ( cd apps/agent && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
      -o /usr/local/bin/nexuspanel-agent ./cmd/agent )
  chmod 0755 /usr/local/bin/nexuspanel-agent
  # Code stays root-owned on purpose: the service user runs it, never edits it.
  ok "built: control-plane dist, web .next, /usr/local/bin/nexuspanel-agent"
}

# --- step 6: units + cgroup delegation -----------------------------------------
install_units() {
  log "step 6/8 — systemd units (agent → api → web) + delegated cgroup root"
  install -m 0644 "$REPO_DIR/infra/systemd/nexuspanel-cgroups.service" /etc/systemd/system/
  install -m 0644 "$REPO_DIR/infra/systemd/nexuspanel-agent.service"   /etc/systemd/system/
  install -m 0644 "$REPO_DIR/infra/systemd/nexuspanel-api.service"     /etc/systemd/system/
  install -m 0644 "$REPO_DIR/infra/systemd/nexuspanel-web.service"     /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now nexuspanel-cgroups.service >/dev/null 2>&1
  systemctl enable --now nexuspanel-agent.service >/dev/null
  systemctl enable --now nexuspanel-api.service   >/dev/null
  systemctl enable --now nexuspanel-web.service   >/dev/null
  wait_health "agent socket" \
    [ -S /run/nexuspanel/agent.sock ]
  wait_health "control plane" \
    curl -fsS http://127.0.0.1:3000/api/v1/health >/dev/null
  ok "units active — health gate passed"
}

wait_health() { # name, test-command — 60s budget
  local i=0
  until eval "${2:-true}"; do
    i=$((i+1)); [ "$i" -ge 60 ] && die "$1 did not become healthy within 60s (journalctl -u <unit> -e)"
    sleep 1
  done
}

# --- step 7: first super admin (interactive, written nowhere) -------------------
create_first_admin() {
  log "step 7/8 — first super admin (one-time prompt; never written to disk)"
  local email pass pass2
  read -rp "admin email: " email
  [[ "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "not an email address"
  while :; do
    read -rsp "admin password (min 12 chars): " pass; echo
    read -rsp "confirm: " pass2; echo
    [ "$pass" = "$pass2" ] || { echo "passwords differ — retry"; continue; }
    [ "${#pass}" -ge 12 ] || { echo "too short — min 12 chars"; continue; }
    break
  done
  # Boot the control plane ONCE with the seed vars injected by the systemd
  # manager (transient unit, --collect garbage-collects it). The values live
  # in the manager's environment only — not in a file, not in a cmdline.
  systemctl stop nexuspanel-api.service >/dev/null 2>&1 || true
  systemd-run --collect --unit=nexuspanel-bootstrap \
    --property=EnvironmentFile="$NP_ENV_FILE" \
    --property=WorkingDirectory="$REPO_DIR/apps/control-plane" \
    --property=NoNewPrivileges=true \
    --setenv=DEV_ADMIN_EMAIL="$email" \
    --setenv=DEV_ADMIN_PASSWORD="$pass" \
    /usr/bin/node dist/main.js >/dev/null
  wait_health "bootstrap control plane" \
    curl -fsS http://127.0.0.1:3000/api/v1/health >/dev/null
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$pass\"}")"
  [ "$code" = "200" ] || { systemctl stop nexuspanel-bootstrap || true; die "admin login failed (HTTP $code)"; }
  systemctl stop nexuspanel-bootstrap >/dev/null
  systemctl start nexuspanel-api.service
  wait_health "control plane (final)" \
    curl -fsS http://127.0.0.1:3000/api/v1/health >/dev/null
  NP_ADMIN_EMAIL="$email" NP_ADMIN_PASSWORD="$pass"
  ok "super admin created and verified (seed env discarded with the transient unit)"
}

# --- step 8: hardening baseline (§3) + verification ------------------------------
harden_and_verify() {
  log "step 8/8 — hardening baseline (C10) + verification"
  local ssh_port; ssh_port="$(sshd -T 2>/dev/null | awk '/^port/{print $2; exit}' || echo 22)"
  ufw allow "${ssh_port:-22}"/tcp  >/dev/null
  [ "${ssh_port:-22}" != "22" ] && ufw allow 22/tcp >/dev/null || true
  ufw allow 80/tcp  >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw --force enable >/dev/null
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' \
    | debconf-set-selections
  dpkg-reconfigure -f noninteractive -plow unattended-upgrades >/dev/null 2>&1 || true
  ok "ufw: ${ssh_port:-22}/80/443 only — API :3000 and web :5173 stay loopback-reachable"
  ok "fail2ban sshd jail: $(fail2ban-client status sshd >/dev/null 2>&1 && echo active || echo 'check journalctl -u fail2ban')"
  ok "unattended-upgrades: enabled"

  # Final verification: login once, verify the hash chain, print the head.
  log "verification — audit chain"
  local token
  token="$(curl -fsS http://127.0.0.1:3000/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$NP_ADMIN_EMAIL\",\"password\":\"$NP_ADMIN_PASSWORD\"}" \
    | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d).access_token))')"
  curl -fsS -X POST http://127.0.0.1:3000/api/v1/audit/verify \
    -H "Authorization: Bearer $token" | head -c 300; echo
}

# --- offline key backup prompt ---------------------------------------------------
backup_prompt() {
  echo
  printf '\033[1;33m ⚠ OFFLINE BACKUP:\033[0m /etc/nexuspanel/keys/ holds the signing key and the\n'
  echo   '   SecretBox master key. Ciphertext in the database is unreadable without it.'
  echo   '   Copy the directory to offline storage NOW (the 0600 modes travel with it).'
  read -rp "   Confirm you have backed it up [y/N]: " a
  [ "$a" = "y" ] || echo "   WARNING: proceeding without an offline key backup — this is your only reminder."
  echo
  echo "NexusPanel is installed."
  echo "  panel (web):   ssh -L 5173:127.0.0.1:5173 -L 3000:127.0.0.1:3000 <user>@<host>  → http://localhost:5173"
  echo "  health:        curl http://127.0.0.1:3000/api/v1/health"
  echo "  units:         systemctl status nexuspanel-{agent,api,web}"
  echo "  acceptance:    docs/runbooks/acceptance-p4-p7.md"
}

# --- upgrade (§5) ------------------------------------------------------------------
do_upgrade() {
  require_root; REPO_DIR="$(repo_root)"
  log "upgrade — stop Node units, pull, rebuild, restart, verify (§5)"
  local old_rev; old_rev="$(git -C "$REPO_DIR" rev-parse HEAD)"
  systemctl stop nexuspanel-api.service nexuspanel-web.service
  git -C "$REPO_DIR" pull --ff-only
  cd "$REPO_DIR"
  npm ci --no-audit --no-fund >/dev/null 2>&1
  npm run prisma:generate --workspace apps/control-plane >/dev/null
  npm run build --workspaces --if-present >/dev/null
  if git -C "$REPO_DIR" diff --name-only "$old_rev" HEAD | grep -q '^apps/agent/'; then
    ( cd apps/agent && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
        -o /usr/local/bin/nexuspanel-agent ./cmd/agent )
    systemctl restart nexuspanel-agent.service
    ok "agent binary changed — rebuilt and restarted (WAL drains on reconnect)"
  fi
  echo "note: forward-only DDL migrations are applied by hand when shipped (ADR-0004); none pending at v1.0."
  systemctl start nexuspanel-api.service nexuspanel-web.service
  wait_health "control plane" curl -fsS http://127.0.0.1:3000/api/v1/health >/dev/null
  ok "upgrade complete — run POST /api/v1/audit/verify to confirm the chain"
}

# --- uninstall (§4) -----------------------------------------------------------------
do_uninstall() {
  require_root
  log "uninstall — stops and removes units; DATA DECISIONS STAY YOURS (§4)"
  systemctl stop nexuspanel-web.service nexuspanel-api.service nexuspanel-agent.service 2>/dev/null || true
  systemctl disable nexuspanel-web.service nexuspanel-api.service nexuspanel-agent.service nexuspanel-cgroups.service 2>/dev/null || true
  rm -f /etc/systemd/system/nexuspanel-{web,api,agent,cgroups}.service
  systemctl daemon-reload
  rm -f /usr/local/bin/nexuspanel-agent
  ok "units and binary removed"
  echo "left in place ON PURPOSE (the operator decides, never the installer):"
  echo "  - database '$NP_DB_NAME' (drop: sudo -u postgres dropdb $NP_DB_NAME && sudo -u postgres psql -c \"DROP ROLE ${NP_DB_USER}\")"
  echo "  - keys $NP_KEYS  (destroy: rm -rf $NP_KEYS — only after confirming no ciphertext will ever need reading)"
  echo "  - repo $NEXUS_HOME and the $NP_SVC_USER account"
}

# --- main -----------------------------------------------------------------------------
case "${1:-install}" in
  install)   preflight; install_packages; create_database; create_keys; write_env_file; build_artifacts; install_units; create_first_admin; harden_and_verify; backup_prompt ;;
  upgrade)   do_upgrade ;;
  uninstall) do_uninstall ;;
  *) die "usage: $0 [install|upgrade|uninstall]" ;;
esac
