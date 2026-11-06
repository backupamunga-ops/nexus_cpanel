# Runbook — P4–P7 live-VM acceptance (closes the AS-BUILT §3 pending rows)

Everything through B15 and P7 is **dev-rig verified**. This runbook is the
**live-VM acceptance run** that upgrades those rows to *proven on real
hardware*: real PowerDNS, real mail delivery on the public internet, real S3
round trips, real nftables, real CRS fires, a real WordPress install under 5
minutes, a real cPanel `cpmove` import, and the k6 SLO pass on reference
hardware. It doubles as the **first drive of `infra/install.sh`** — if the
installer fails here, that IS an acceptance finding.

Verdict rules (same honesty contract as AS-BUILT §3):

- **PASS** — every check below produced the expected evidence on this VM.
- **FAIL** — any check deviated; file the finding (command, output, expected)
  and stop: do not soften a FAIL to a PARTIAL in the register.
- **N/A** — only for operator-resource reasons (e.g. no relay provider), and
  the register row must name the missing resource.
- Evidence lands in `/root/acceptance-evidence/` — one `.log` per check via
  `tee`, plus screenshots of every panel step you touch.

## 0. Prerequisites

| Requirement | Notes |
|---|---|
| Fresh Ubuntu 22.04+ / Debian 12 VM | 2 vCPU / **4 GB RAM** (next build is memory-hungry), 40 GB disk, root |
| A domain you control DNS for | `example.com` below; you will delegate `host.example.com` to this VM's PowerDNS (NS + glue at your registrar) — this is what makes propagation/DNSSEC/DMARC checks REAL |
| An S3 bucket + access keys | B10; any S3-compatible provider works |
| An outbound relay account | B08 relay profile (any SMTP relay with credentials) |
| A source cPanel server | B15: enough access to run `/scripts/pkgacct` for one test account |
| A second machine/IP | B11 self-lockout negative test and fail2ban ban test (do NOT ban your only way in) |
| k6 CLI | P7 SLO suite (https://grafana.com/docs/k6/latest/set-up/install-k6/) |

```bash
mkdir -p /root/acceptance-evidence && cd /root/acceptance-evidence
```

## 1. Install — first drive of `infra/install.sh`

```bash
cd /opt && git clone https://github.com/backupamunga-ops/nexus_cpanel.git nexuspanel
cd nexuspanel
sudo infra/install.sh 2>&1 | tee /root/acceptance-evidence/01-install.log
```

The installer runs the 8 steps of `docs/release/INSTALLER_V1.md` and ends by
prompting for the first super admin and the offline key-backup confirmation.

| Check | Expected |
|---|---|
| Exit | `NexusPanel is installed.` with no FATAL lines |
| Units | `systemctl is-active nexuspanel-{cgroups,agent,api,web}` → all `active` |
| Agent socket | `ls -l /run/nexuspanel/agent.sock` → `root:nexuspanel`, mode `0660` |
| Health | `curl -fsS http://127.0.0.1:3000/api/v1/health` → JSON body |
| Web | `curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:5173` → `200` |
| Firewall | `ufw status` → only your SSH port + 80/443 |
| Audit | the installer's final `POST /audit/verify` output → `"verified":true` |

Log into the panel: `ssh -L 5173:127.0.0.1:5173 -L 3000:127.0.0.1:3000 user@vm`
→ `http://localhost:5173` with the admin credentials you set. **Reboot the VM
once now** and re-check the units — the cgroup preparer (`nexuspanel-cgroups`)
must survive the reboot (that is exactly why it is a oneshot unit, not an
install-time-only command).

```bash
reboot  # then:
systemctl is-active nexuspanel-{cgroups,agent,api,web}
ls -ld /sys/fs/cgroup/nexuspanel   # root:nexuspanel, 0750
```

## 2. B06 — DNS on real PowerDNS (ADR-0012)

Prepare PowerDNS (packages are the operator's job; the panel manages config):

```bash
apt-get install -y pdns-server pdns-backend-pgsql
# /etc/powerdns/pdns.conf — minimal API posture (adapt credentials):
#   launch=gpgsql  gpgsql-host=127.0.0.1  gpgsql-user=nexuspanel
#   gpgsql-password=<NP_DB_PASSWORD>  gpgsql-dbname=nexuspanel
#   api=yes  api-key=<STRONG_KEY>  webserver=no
systemctl restart pdns
```

Point the agent at it, then restart the agent:

```bash
mkdir -p /etc/systemd/system/nexuspanel-agent.service.d
cat > /etc/systemd/system/nexuspanel-agent.service.d/pdns.conf <<EOF
[Service]
Environment=NEXUSAGENT_PDNS_API_URL=http://127.0.0.1:8081/api/v1
Environment=NEXUSAGENT_PDNS_API_KEY=<STRONG_KEY>
Environment=NEXUSAGENT_PDNS_SERVER_ID=localhost
EOF
systemctl daemon-reload && systemctl restart nexuspanel-agent
```

Delegate `host.example.com` to this VM at your registrar (NS + glue A record),
then in the panel (DNS → Add zone) create `host.example.com` and add records
(`www` A, `mail` A, MX). Screenshot the zone editor.

| Check | Command | Expected |
|---|---|---|
| Zone serves | `dig +short @127.0.0.1 www.host.example.com A` | the record |
| Public propagation | `dig +short @1.1.1.1 www.host.example.com A` | the record (after delegation TTL) |
| Zone check | panel DNS → Run zone check (or `POST /api/v1/dns/zones/:id/zone-check`) | no errors |
| DNSSEC on | panel DNS → Enable DNSSEC → copy the DS | `POST .../dnssec/enable` returns the DS tuple |
| DS at registrar | add the DS at your registrar, wait for TTL | — |
| Chain validates | `dig +dnssec @1.1.1.1 www.host.example.com A` + `delv @1.1.1.1 www.host.example.com A` | `ad` flag / `fully validated` |
| Wildcard cert | panel Sites → the site → SSL → issue `*.host.example.com` | cert issued; `openssl x509 -text` shows the wildcard SAN |

**PASS B06** = zone serves publicly, DNSSEC chain validates via a public
resolver, wildcard certificate issued.

## 3. B07 + B08 — real mail delivery, DKIM/SPF/DMARC (ADR-0013/0014)

```bash
apt-get install -y postfix dovecot-core dovecot-pgsql dovecot-lmtpd \
  dovecot-sieve opendkim opendkim-tools
groupadd -g 5000 vmail && useradd -g vmail -u 5000 vmail -d /var/vmail -m
mkdir -p /etc/postfix/nexuspanel   # the agent's map dir (NEXUSAGENT_POSTFIX_MAP_DIR)
cat > /etc/systemd/system/nexuspanel-agent.service.d/mail.conf <<EOF
[Service]
Environment=NEXUSAGENT_POSTFIX_MAP_DIR=/etc/postfix/nexuspanel
Environment=NEXUSAGENT_VMAIL_ROOT=/var/vmail
EOF
systemctl daemon-reload && systemctl restart nexuspanel-agent
```

Open relay port 25 (and 587/993 for submissions/IMAP) in your cloud firewall,
then in the panel:

1. **Email → Add domain** `host.example.com`; create mailbox `hello@` (quota
   bar visible), one alias, one autoresponder.
2. **Deliverability wizard** (Email → Deliverability): generate DKIM — the
   panel writes the key via the agent AND creates the DKIM TXT record in
   PowerDNS automatically (B06 makes this real). Complete SPF and DMARC in the
   wizard the same way.
3. **Relay profile** (Email → Relay): configure your relay provider; send the
   test ping.

Verify DNS records publicly, then do the REAL delivery test:

```bash
dig +short TXT default._domainkey.host.example.com @1.1.1.1   # DKIM
dig +short TXT host.example.com @1.1.1.1                       # SPF
dig +short TXT _dmarc.host.example.com @1.1.1.1                # DMARC
```

- **Inbound:** from an external mailbox (Gmail), send to `hello@host.example.com`.
  Evidence: `find /var/vmail/host.example.com/hello -name '*.'` shows the
  Maildir file; `cat` it to see `Delivered-To` via Dovecot LMTP.
- **Outbound:** reply from the panel mailbox (or `sendmail` as the account)
  to your Gmail. Evidence: the Gmail message source shows
  `DKIM-Signature: d=host.example.com`, `spf=pass`, `dmarc=pass`.
- **Queue tools:** `GET /api/v1/mail/queue` shows the (honestly parsed) queue;
  flush it with the panel button.
- **Autoresponder/alias:** mail the alias, observe the autoresponder reply.

**PASS B07/B08** = inbound AND outbound delivered on the public internet, and
an external receiver (Gmail) shows DKIM **and** SPF **and** DMARC as pass.

## 4. B09 — live MariaDB round trip (ADR-0015)

```bash
apt-get install -y mariadb-server   # MariaDB 11.x per the MariaDB repo if the
                                    # archive is older — the panel targets 11
```

In the panel (Databases): create database `shop`, user `shop_user`, note the
generated credential (reveal is audited). Evidence, on the VM:

```bash
mysql -u shop_user -p -h 127.0.0.1 shop \
  -e "CREATE TABLE t1(id INT PRIMARY KEY, v TEXT); INSERT INTO t1 VALUES (1,'live'); SELECT * FROM t1;"
```

Panel actions → **Dump** the database; confirm the dump file exists in the
account's space and `grep -c 'INSERT INTO' <dump> > 0`. **Size** shows
non-zero after `POST /databases/:id/size`.

**PASS B09** = create/use/dump all succeeded through the panel-issued
credential (no root, no shared creds).

## 5. B10 — real S3 backup, age-encrypted, restored (C15)

In the panel (Backups → Destinations): add the S3 destination (bucket, keys,
envelope config; enable age encryption), press **Test** — a real round trip
must succeed. Create a job (daily, GFS retention), press **Run now**.

| Check | How | Expected |
|---|---|---|
| Run completes | Backups → Runs | `succeeded` |
| Proof-earned verify | Runs → the run → Verify | `verified` badge (byte-for-byte, from manifest) |
| Restore preview | Runs → Restore preview | file list matches the source tree |
| Real restore | Restore → alternate path | `diff -r` restored vs source → empty |
| Envelope honesty | download the artifact from S3 and try to list the tar without the age key | impossible (encrypted blob) |
| GFS retention | set keep_daily=2, fabricate 3 dailies, run retention | 3rd daily pruned, audit entry written |

**PASS B10** = round trip + verify-from-proof + real restore + encrypted-at-rest
all on the live bucket.

## 6. B11 — nftables + fail2ban on the live host (ADR-0016)

In the panel (Security → Firewall): add a rule (e.g. allow 8080/tcp), **Apply**.

```bash
nft list ruleset | grep -A5 nexuspanel     # managed table exists, rule present
```

Negative (the guard that matters): add a rule that would block your own SSH
source IP → the panel must **refuse** (self-lockout guard). Jails:
`GET /api/v1/firewall/fail2ban/jails` shows `sshd` live. Deliberate ban test
(from the SECOND machine, or a throwaway IP):

```bash
fail2ban-client set sshd banip 203.0.113.9
curl -s -X POST http://127.0.0.1:3000/api/v1/firewall/fail2ban/unban \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ip":"203.0.113.9"}'          # audited unban
fail2ban-client status sshd          # IP gone
```

**PASS B11** = managed table live after apply, self-lockout refused, jail
health visible, ban→unban round trip audited.

## 7. B12 — ModSecurity detect-vs-block + ClamAV EICAR (ADR-0017)

```bash
apt-get install -y libnginx-mod-http-modsecurity clamav clamav-daemon
freshclam   # update signatures before judging any scan result
```

In the panel (Sites → the site → WAF): set **Detect**; from outside:

```bash
curl -si "http://<site>/?id=1%20OR%201%3D1" | head -1   # 200 — logged, not blocked
```

Switch the same site to **Block** in the panel, repeat → `403`. That is
detect-vs-block proven on a real CRS install.

Then ClamAV: place the EICAR test file in the account's webroot and run
**Scan** in the panel (Threat protection). The string is written split so
this runbook itself never trips an AV scan of the repo:

```bash
printf '%s%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICA' \
  'R-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /home/<user>/<site>/public/eicar.txt
```

Scan finds it → quarantine listing shows the file → **Delete** it (audited);
repeat with a second EICAR and **Restore** instead. Both flows must appear in
the audit view.

**PASS B12** = CRS fires differently in detect vs block; EICAR quarantined,
then deleted AND restored through audited flows.

## 8. B14 — WordPress under 5 minutes + push-to-deploy rollback (ADR-0019)

Create a fresh hosting account and site (`wp.host.example.com`, PHP 8.x pool),
then **Apps → Install WordPress**. Stop the clock at install start; the clock
stops when the site answers:

```bash
time curl -fsS -o /dev/null http://wp.host.example.com/   # after install completes
```

| Check | Expected |
|---|---|
| Install wall clock | **< 5 min** (plan B14 exit criterion) |
| Ownership | `ls -l /home/<user>/<site>` → files owned by the ACCOUNT user (never root) |
| wp-cli | panel → Apps → WP-CLI: `wp core version` runs, output shown |
| Staging clone | one click → `staging.wp.host.example.com` serves a copy |

Git deploy: create a repo with a trivial `index.html`, point **Git deploys**
at it (webhook URL + secret shown by the panel), push to the tracked branch →
deploy appears in history; edit + push again → second release; **Rollback** →
the site serves release 1's content again. Build/deploy log visible either way.

**PASS B14** = sub-5-minute WP install as the account user, staging clone,
push → deploy → rollback all real.

## 9. B15 — a real cPanel `cpmove` import (ADR-0020)

On the SOURCE cPanel server: `/scripts/pkgacct <user>` → `/home/cpmove-<user>.tar.gz`.
Copy it to the VM **into the agent's migration staging root** (the artifact
reference is confined to it — basename only):

```bash
install -d -m 0750 /var/lib/nexuspanel-agent/migrations
scp you@cpanel:/home/cpmove-<user>.tar.gz /var/lib/nexuspanel-agent/migrations/
```

In the panel (**Migrations** — the four plain steps): pick the artifact →
**Look inside** (analyze: per-entity inventory; SKIPs must be explicit and
reason-coded) → **Show the plan** (zero-write dry-run) → **Move it** →
**Report**.

| Check | Expected |
|---|---|
| Analyze | zones/mail/databases/… inventories; any SKIP has a reason code |
| Dry run | states the exact write plan, writes NOTHING (`git`-less check: no new zones/mailboxes yet) |
| Execute | resumable; mailboxes/DB users get FRESH panel-generated credentials (cpmove secrets are never imported) |
| Verify | per-entity table, byte-for-byte; ONE failed check fails the job |
| Report | checksum pairs + the DNS cutover/rollback plan |
| Spot check | `dig` the imported zone via PowerDNS; log into one imported mailbox with the NEW password |

**PASS B15** = a real cpmove imported with a fully-verified report.

## 10. P7 — extension E2E + SLO pass (ADR-0021)

Extensions: in the panel (**Extensions**), register the example extension —
run it on the VM first (`cd examples/nexus-example-reporter && npm start`,
listens on `:8800`), then install with
`manifest_url = http://127.0.0.1:8800/nexuspanel-manifest.json`
(`POST /api/v1/extensions`). Walk the trust ladder: install (disabled,
zero scopes) → review → **approve → credentials shown EXACTLY ONCE** (copy
them; no endpoint ever shows them again) → the widget renders on the
dashboard; the signed hook/heartbeat arrives (extension log). Negative: a
write-scope call beyond the granted scopes is refused by the closed
`/api/v1/ext/*` route table.

SLO (reference hardware = this VM, idle):

```bash
BASE_URL=http://127.0.0.1:3000/api/v1 k6 run e2e/load/k6-api-slo.js 2>&1 | \
  tee /root/acceptance-evidence/10-k6-api.log
BASE_URL=http://127.0.0.1:3000/api/v1 ADMIN_EMAIL=... ADMIN_PASSWORD=... \
  ACCOUNT_ID=<uuid from step 8> k6 run e2e/load/k6-agent-op.js 2>&1 | \
  tee /root/acceptance-evidence/11-k6-agent.log
```

**PASS P7** = example extension through the full ladder + `http_req_duration
p(95)≤300ms` and agent-op `p(95)≤1s` thresholds pass inside k6 (it exits
non-zero on breach — that is the harness enforcing the SLO).

## 11. Close the run

Fill the verdict table (copy into the PR / register PR description):

| Row | Verdict | Evidence file(s) |
|---|---|---|
| install.sh first drive | | 01-install.log |
| B06 DNS/DNSSEC/wildcard | | |
| B07/B08 mail + deliverability | | |
| B09 MariaDB round trip | | |
| B10 S3 backup + restore | | |
| B11 firewall/fail2ban | | |
| B12 WAF/ClamAV | | |
| B14 WP < 5 min + git | | |
| B15 real cpmove | | |
| P7 extension + SLO | | |

Then update `docs/plan/AS-BUILT.md` §3: rows move from *dev-rig verified —
live-VM acceptance pending* to *accepted on <date>, evidence in the run
journal* — FAILs stay FAILs and become the next batch's first items. Any
installer/unit finding becomes a fix commit referencing this runbook.
