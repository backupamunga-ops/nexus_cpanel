package commands

import (
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "sort"
        "strings"

        "github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// Mail map + file plumbing (agent spec §4.8, amended by ADR-0013) — P4.
//
// Per ADR-0013 the agent owns everything that is a file on the node and
// nothing that is a credential:
//
//   - Postfix flat maps under one managed dir: virtual_domains_map (one
//     domain per line), virtual_mailboxes_map ("email maildir" pairs),
//     virtual_aliases_map ("source destination" pairs). Every mutation
//     rewrites the affected map atomically from full desired state and
//     re-runs postmap; a missing postmap is an honest skip in the response,
//     never a silent success (ftp userdb precedent).
//   - Maildirs under the vmail root: <root>/<domain>/<local>/ with the
//     cur/new/tmp scaffold; a maildirsize file carries the quota. Ownership
//     is the vmail uid/gid from deps (0 = skip chown honestly, dev rigs).
//   - Autoresponders as Sieve vacation scripts (<maildir>/.dovecot.sieve).
//
// Passwords never reach the agent: Dovecot authenticates against the panel
// DB (SQL userdb, ADR-0013), so password hashing and rotation are entirely
// control-plane work. mail.modify_mailbox therefore handles quota only —
// the spec's password_hash param is dropped by amendment.

const (
        maxMailboxQuotaMB = 1 << 20 // 1 TiB per mailbox, integer MB
        vmailDirMode      = 0o700
        vmailFileMode     = 0o600
        mapFileMode       = 0o644 // read by postfix running as root
        sieveFileMode     = 0o600
        mailErrDetailCap  = 300
)

// mailMapsResult reports whether the postfix maps were rebuilt (honest skip
// when postmap is absent — routing cannot work until they are).
type mailMapsResult struct {
        Built   bool   `json:"built"`
        Skipped string `json:"skipped,omitempty"`
}

// mailOwnershipResult reports the chown outcome honestly.
type mailOwnershipResult struct {
        Applied bool   `json:"applied"`
        Skipped string `json:"skipped,omitempty"`
}

func (r *Registry) mailMapsDir() string {
        if r.deps.PostfixMapDir == "" {
                return "/etc/postfix/nexuspanel"
        }
        return r.deps.PostfixMapDir
}

func (r *Registry) mailVmailRoot() string {
        if r.deps.VmailRoot == "" {
                return "/srv/vmail"
        }
        return r.deps.VmailRoot
}

// mailReadMap returns the trimmed, non-comment lines of a managed map file.
func mailReadMap(path string) []string {
        b, err := os.ReadFile(path)
        if err != nil {
                return nil
        }
        var out []string
        for _, line := range strings.Split(string(b), "\n") {
                line = strings.TrimSpace(line)
                if line != "" && !strings.HasPrefix(line, "#") {
                        out = append(out, line)
                }
        }
        return out
}

func mailInternalError(what string, err error) *rpc.RPCError {
        return &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("%s: %v", what, err)}
}

// mailWriteMap rewrites one map file atomically (staged rename) from the
// sorted desired lines, then postmaps it.
func (r *Registry) mailWriteMap(name string, lines []string) (mailMapsResult, error) {
        dir := r.mailMapsDir()
        if err := os.MkdirAll(dir, 0o755); err != nil {
                return mailMapsResult{}, mailInternalError("map dir create failed", err)
        }
        sort.Strings(lines)
        var b strings.Builder
        b.WriteString("# managed by nexuspanel — do not edit\n")
        for _, l := range lines {
                b.WriteString(l)
                b.WriteByte('\n')
        }
        path := dir + "/" + name
        staging := path + ".nexus-staging"
        if err := os.WriteFile(staging, []byte(b.String()), mapFileMode); err != nil {
                return mailMapsResult{}, mailInternalError("staging write failed", err)
        }
        if err := os.Rename(staging, path); err != nil {
                _ = os.Remove(staging)
                return mailMapsResult{}, mailInternalError("atomic swap failed", err)
        }
        return r.mailPostmap(name)
}

// mailPostmap runs postmap over one map (honest skip when absent).
func (r *Registry) mailPostmap(name string) (mailMapsResult, error) {
        bin := r.deps.PostmapBinary
        if bin == "" {
                found, err := exec.LookPath("postmap")
                if err != nil {
                        return mailMapsResult{Built: false, Skipped: "postmap binary not found — map not rebuilt; routing cannot use it until it is"}, nil
                }
                bin = found
        }
        out, err := exec.Command(bin, r.mailMapsDir()+"/"+name).CombinedOutput()
        if err != nil {
                trimmed := strings.TrimSpace(string(out))
                if len(trimmed) > mailErrDetailCap {
                        trimmed = trimmed[:mailErrDetailCap-3] + "..."
                }
                return mailMapsResult{}, &rpc.RPCError{
                        Code:    rpc.CodePrecondition,
                        Message: fmt.Sprintf("postmap %s failed: %s", name, trimmed),
                }
        }
        return mailMapsResult{Built: true}, nil
}

// mailDomainInMap reports whether the exact domain line exists.
func mailDomainInMap(lines []string, domain string) bool {
        for _, l := range lines {
                if l == domain {
                        return true
                }
        }
        return false
}

// mailFilterByDomain keeps only lines NOT belonging to the domain.
// virtual_domains_map lines are exactly the domain; mailbox/alias lines
// carry "<local>@<domain>" (or "@<domain>" catch-alls) as their first field.
func mailFilterByDomain(lines []string, domain string) []string {
        out := make([]string, 0, len(lines))
        for _, l := range lines {
                fields := strings.Fields(l)
                if len(fields) == 0 {
                        continue
                }
                key := fields[0]
                if key == domain || strings.HasSuffix(key, "@"+domain) {
                        continue
                }
                out = append(out, l)
        }
        return out
}

// mailMaildirPath resolves the maildir for an email (components are
// validated by the callers — no user input reaches here unfiltered).
func (r *Registry) mailMaildirPath(domain, local string) string {
        return fmt.Sprintf("%s/%s/%s", r.mailVmailRoot(), domain, local)
}

// mailCreateMaildir scaffolds cur/new/tmp + maildirsize and applies
// ownership. Existing maildirs are left untouched (idempotent recovery).
func (r *Registry) mailCreateMaildir(maildir string, quotaMB int) (mailOwnershipResult, error) {
        for _, sub := range []string{"cur", "new", "tmp"} {
                if err := os.MkdirAll(maildir+"/"+sub, vmailDirMode); err != nil {
                        return mailOwnershipResult{}, mailInternalError("maildir scaffold failed", err)
                }
        }
        sizeLine := fmt.Sprintf("%dS\n", quotaMB*1024*1024)
        sizePath := maildir + "/maildirsize"
        if _, err := os.Stat(sizePath); os.IsNotExist(err) {
                if err := os.WriteFile(sizePath, []byte(sizeLine), vmailFileMode); err != nil {
                        return mailOwnershipResult{}, mailInternalError("maildirsize write failed", err)
                }
        }
        return r.mailApplyOwnership(maildir)
}

// mailApplyOwnership chowns the tree to the vmail uid/gid when configured.
// Zero uid/gid (dev rigs) is an honest skip in the response.
func (r *Registry) mailApplyOwnership(maildir string) (mailOwnershipResult, error) {
        uid, gid := r.deps.VmailUID, r.deps.VmailGID
        if uid == 0 && gid == 0 {
                return mailOwnershipResult{Applied: false, Skipped: "vmail uid/gid not configured — maildir left unowned; delivery fails until chown"}, nil
        }
        err := filepath.Walk(maildir, func(path string, info os.FileInfo, walkErr error) error {
                if walkErr != nil {
                        return walkErr
                }
                return os.Chown(path, uid, gid)
        })
        if err != nil {
                return mailOwnershipResult{}, mailInternalError("chown failed", err)
        }
        return mailOwnershipResult{Applied: true}, nil
}

// mailUpdateQuota rewrites the maildirsize first line (maildir++ convention).
func mailUpdateQuota(maildir string, quotaMB int) error {
        sizeLine := fmt.Sprintf("%dS\n", quotaMB*1024*1024)
        staging := maildir + "/maildirsize.nexus-staging"
        if err := os.WriteFile(staging, []byte(sizeLine), vmailFileMode); err != nil {
                return mailInternalError("maildirsize staging failed", err)
        }
        if err := os.Rename(staging, maildir+"/maildirsize"); err != nil {
                _ = os.Remove(staging)
                return mailInternalError("maildirsize swap failed", err)
        }
        return nil
}

// mailSieveScript renders the vacation Sieve. Body uses the text: block so
// arbitrary multi-line content survives; leading dots are dot-stuffed.
func mailSieveScript(subject, body string) string {
        var b strings.Builder
        b.WriteString("# managed by nexuspanel — do not edit\n")
        b.WriteString("require [\"vacation\"];\n")
        b.WriteString("vacation :days 1 :subject " + sieveString(subject) + " text:\n")
        for _, line := range strings.Split(body, "\n") {
                if strings.HasPrefix(line, ".") {
                        b.WriteByte('.')
                }
                b.WriteString(line)
                b.WriteByte('\n')
        }
        b.WriteString(".\n;\n")
        return b.String()
}

func sieveString(s string) string {
        return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(s) + "\""
}
