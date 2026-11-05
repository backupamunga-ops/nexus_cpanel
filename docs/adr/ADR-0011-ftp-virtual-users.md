# ADR-0011: `ftp.*` agent category — vsftpd virtual users with pam_userdb

- **Status:** Accepted
- **Date:** 2026-11-05
- **Phase:** P4 (mail, DNS, databases, backups) — FTP accounts gap closure
- **Deciders:** Backend #2 (agent), Backend #1 (control plane), Tech Lead review per BUILD_PLAN §1

## Context

FTP accounts are Delivery-Core scope (master spec delivery table: "FTP
accounts | Delivery Core | Plus SFTP"), but the agent spec §4 has no
`ftp.*` category, the DDL had no `file_accounts` table (master spec §
"data model" lists it; it was never written), and the gap register has
marked FTP deferred since P3. Closing this needs BOTH schema and agent
amendments.

Constraints that shape the design:

1. FTP logins must not be system users — a shared hosting node accumulates
   FTP logins by the dozen, and /etc/passwd is not a tenant database.
2. Passwords must never exist in the panel's database, and must never be
   logged or WAL-recorded anywhere on the agent side.
3. Hand-rolled password hashing is where panels historically break C1
   (weak parameters, broken salts). The node already ships a certified
   crypt implementation: openssl.

## Decision

### DDL amendment (ADR-0004 process)

`specs/nexuspanel-schema-v2.0.sql` gains `file_accounts` (uuid PK,
hosting_account_id FK, globally-unique `username`, confined `root_dir`,
`read_only`, `status`, timestamps, soft delete). It is the panel-side
registry; passwords never touch it.

### Agent spec §4 amendment — `ftp.*`

| Method | Params | Notes |
|---|---|---|
| `ftp.create_account` | `owner_username, ftp_username, password, root_dir, read_only` | Writes the per-user vsftpd config (`user_config_dir` convention: `local_root` confined to the account home via the standard fsTarget, `write_enable`, `local_umask`), hashes the password to SHA-512-crypt via `openssl passwd -6` (fresh random salt per call), upserts the pam_userdb source file and rebuilds the BerkeleyDB via `db_load -T -t hash`. Conflict on existing login; precondition when `openssl` is missing |
| `ftp.set_password` | `ftp_username, password` | Hash + userdb rebuild only |
| `ftp.delete_account` | `ftp_username` | Removes config + userdb entry; absent is a success |
| `ftp.list_accounts` | — | Read-only (§6): parses the managed per-user configs |

**Honest degradation (D-11):** a node without `db_load` reports
`userdb: {rebuilt: false, skipped: reason}` and the command still
succeeds — the account is provisioned but **cannot authenticate until the
DB is rebuilt**, and the response states exactly that. A failed
`db_load` (real error) fails the command: the config file is removed, the
source file remains as the recovery artifact, and the panel gets a loud
precondition error.

**Why openssl + db_load, not a Go crypt implementation:** the agent
deliberately imports no third-party crypto; $6$ hand-rolling is exactly
the kind of code a security review fails. Both binaries are precondition-
checked, and test rigs inject fakes.

**Deployment contract (runbook item):** vsftpd is configured once per
node with `pam_userdb` pointing at the panel's userdb and
`user_config_dir` at the panel's config dir; both paths are agent Deps
and default to `/etc/vsftpd/nexuspanel-*`. Until that node configuration
exists, accounts provision but do not authenticate — the same honest
"stored, not yet enforced" semantics as SSH keys before ADR-0010.

**Rejected alternatives:** system users with nologin shells (pollutes
/etc/passwd, breaks per-login chroot ergonomics), storing password hashes
in the panel DB (moves the secret off the node and out of reach of the
PAM stack), and MySQL-based PAM auth (couples FTP auth to the customer
database engine — D-1 exists for customer data, not panel auth).
