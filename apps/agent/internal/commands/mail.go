package commands

import (
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "regexp"
        "strings"
        "time"

        "github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// mail.* (agent spec §4.8, amended by ADR-0013) — P4: email core.
//
// The panel owns the registry (mail_domains / mailboxes / mail_aliases /
// autoresponders, DDL-first) and all credentials; the agent owns the node
// files that make those rows real (Postfix maps, maildirs, Sieve scripts —
// see mail_maps.go). Provisioning is agent-first everywhere: a failed agent
// call leaves NO panel row.
//
// Address validation is strict on both halves because the local part
// becomes a directory name under the vmail root and a map key: no slashes,
// no leading/trailing dots, no ".." (regex-enforced), lowercase.

var (
        mailLocalRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9._+-]{0,62}[a-z0-9])?$`)
        mailDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

type mailStatusResult struct {
        Status      string              `json:"status"` // created | updated | removed | absent
        Domain      string              `json:"domain,omitempty"`
        Email       string              `json:"email,omitempty"`
        Maildir     string              `json:"maildir,omitempty"`
        QuotaMB     int                 `json:"quota_mb,omitempty"`
        PreservedAs string              `json:"preserved_as,omitempty"`
        Ownership   *mailOwnershipResult `json:"ownership,omitempty"`
        Maps        *mailMapsResult     `json:"maps,omitempty"`
}

// mailValidateEmail splits and validates "local@domain".
func mailValidateEmail(email string) (local, domain string, err error) {
        parts := strings.Split(email, "@")
        if len(parts) != 2 {
                return "", "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "email must be local@domain"}
        }
        local, domain = parts[0], parts[1]
        if len(email) > 254 || !mailLocalRe.MatchString(local) {
                return "", "", &rpc.RPCError{Code: rpc.CodeInvalidParams,
                        Message: "invalid local part (lowercase letters, digits, dot, dash, underscore, plus; no leading/trailing dot)"}
        }
        if len(domain) > 253 || !mailDomainRe.MatchString(domain) {
                return "", "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid mail domain"}
        }
        return local, domain, nil
}

func mailValidateQuota(quotaMB int) error {
        if quotaMB < 1 || quotaMB > maxMailboxQuotaMB {
                return &rpc.RPCError{Code: rpc.CodeInvalidParams,
                        Message: fmt.Sprintf("quota_mb must be 1-%d MB", maxMailboxQuotaMB)}
        }
        return nil
}

// ---- domains -----------------------------------------------------------------

// mailCreateDomain registers a mail domain in the Postfix virtual domain map.
func (r *Registry) mailCreateDomain(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Domain string `json:"domain"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
        if len(domain) > 253 || !mailDomainRe.MatchString(domain) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid mail domain (lowercase FQDN, at least two labels)"}
        }

        domainLines := mailReadMap(r.mailMapsDir() + "/virtual_domains_map")
        if mailDomainInMap(domainLines, domain) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "mail domain already exists on the node"}
        }
        maps, err := r.mailWriteMap("virtual_domains_map", append(domainLines, domain))
        if err != nil {
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("mail.create_domain", map[string]any{"domain": domain})
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "created", Domain: domain, Maps: &maps}, auditQueued(entry), nil
}

// mailDeleteDomain removes the domain and every map line belonging to it.
// Absent is a success (desired state already met) and still WAL-audited.
func (r *Registry) mailDeleteDomain(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Domain string `json:"domain"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
        if domain == "" {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "domain is required"}
        }

        dir := r.mailMapsDir()
        domainLines := mailReadMap(dir + "/virtual_domains_map")
        boxLines := mailReadMap(dir + "/virtual_mailboxes_map")
        aliasLines := mailReadMap(dir + "/virtual_aliases_map")

        present := mailDomainInMap(domainLines, domain)
        boxesBefore, aliasesBefore := len(boxLines), len(aliasLines)
        boxLines = mailFilterByDomain(boxLines, domain)
        aliasLines = mailFilterByDomain(aliasLines, domain)
        if !present && len(boxLines) == boxesBefore && len(aliasLines) == aliasesBefore {
                entry := r.deps.WAL.NewEntry("mail.delete_domain", map[string]any{"domain": domain, "absent": true})
                _ = r.deps.WAL.Append(entry)
                return mailStatusResult{Status: "absent", Domain: domain}, auditQueued(entry), nil
        }

        // Build order: aliases first, then mailboxes, then the domain line —
        // a failure half-way leaves routing narrower, never wider (no open relay
        // windows, no orphan deliveries to a removed domain).
        aliasMaps, err := r.mailWriteMap("virtual_aliases_map", aliasLines)
        if err != nil {
                return nil, nil, err
        }
        boxMaps, err := r.mailWriteMap("virtual_mailboxes_map", boxLines)
        if err != nil {
                return nil, nil, err
        }
        domainMaps, err := r.mailWriteMap("virtual_domains_map", mailFilterByDomain(domainLines, domain))
        if err != nil {
                return nil, nil, err
        }
        maps := worstMaps(domainMaps, boxMaps, aliasMaps)

        entry := r.deps.WAL.NewEntry("mail.delete_domain", map[string]any{
                "domain":           domain,
                "mailbox_lines":    boxesBefore - len(boxLines),
                "alias_lines":      aliasesBefore - len(aliasLines),
                "maps_built":       maps.Built,
        })
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "removed", Domain: domain, Maps: &maps}, auditQueued(entry), nil
}

func worstMaps(results ...mailMapsResult) mailMapsResult {
        worst := mailMapsResult{Built: true}
        for _, m := range results {
                if !m.Built {
                        return mailMapsResult{Built: false, Skipped: m.Skipped}
                }
        }
        return worst
}

// ---- mailboxes ---------------------------------------------------------------

// mailCreateMailbox provisions the maildir + map entry for one mailbox.
func (r *Registry) mailCreateMailbox(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Email   string `json:"email"`
                QuotaMB int    `json:"quota_mb"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        local, domain, err := mailValidateEmail(strings.ToLower(strings.TrimSpace(p.Email)))
        if err != nil {
                return nil, nil, err
        }
        if err := mailValidateQuota(p.QuotaMB); err != nil {
                return nil, nil, err
        }

        dir := r.mailMapsDir()
        if !mailDomainInMap(mailReadMap(dir+"/virtual_domains_map"), domain) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "mail domain is not provisioned on the node (create it first)"}
        }
        boxLines := mailReadMap(dir + "/virtual_mailboxes_map")
        email := local + "@" + domain
        for _, l := range boxLines {
                if strings.Fields(l)[0] == email {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "mailbox already exists on the node"}
                }
        }

        maildir := r.mailMaildirPath(domain, local)
        ownership, err := r.mailCreateMaildir(maildir, p.QuotaMB)
        if err != nil {
                return nil, nil, err
        }
        maps, err := r.mailWriteMap("virtual_mailboxes_map", append(boxLines, email+" "+maildir+"/"))
        if err != nil {
                _ = os.RemoveAll(maildir) // no maildir for a mailbox that is not on the maps
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("mail.create_mailbox", map[string]any{
                "email": email, "quota_mb": p.QuotaMB, "maildir": safePathSummary(maildir),
                "ownership_applied": ownership.Applied,
        })
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "created", Email: email, Maildir: maildir, QuotaMB: p.QuotaMB, Ownership: &ownership, Maps: &maps}, auditQueued(entry), nil
}

// mailModifyMailbox updates the quota (map value unchanged — the maildir
// path never moves). Passwords are not part of this method (ADR-0013).
func (r *Registry) mailModifyMailbox(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Email   string `json:"email"`
                QuotaMB int    `json:"quota_mb"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        local, domain, err := mailValidateEmail(strings.ToLower(strings.TrimSpace(p.Email)))
        if err != nil {
                return nil, nil, err
        }
        if err := mailValidateQuota(p.QuotaMB); err != nil {
                return nil, nil, err
        }

        maildir := r.mailMaildirPath(domain, local)
        if fi, statErr := os.Stat(maildir); statErr != nil || !fi.IsDir() {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "mailbox does not exist on the node"}
        }
        if err := mailUpdateQuota(maildir, p.QuotaMB); err != nil {
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("mail.modify_mailbox", map[string]any{
                "email": local + "@" + domain, "quota_mb": p.QuotaMB,
        })
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "updated", Email: local + "@" + domain, QuotaMB: p.QuotaMB, Maildir: maildir}, auditQueued(entry), nil
}

// mailDeleteMailbox removes the mailbox map line and the maildir (or
// preserves it under <vmail>/.trash/<email>-<unixts> when preserve_mail).
// Absent is a success.
func (r *Registry) mailDeleteMailbox(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Email        string `json:"email"`
                PreserveMail bool   `json:"preserve_mail"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        local, domain, err := mailValidateEmail(strings.ToLower(strings.TrimSpace(p.Email)))
        if err != nil {
                return nil, nil, err
        }
        email := local + "@" + domain

        dir := r.mailMapsDir()
        boxLines := mailReadMap(dir + "/virtual_mailboxes_map")
        aliasLines := mailReadMap(dir + "/virtual_aliases_map")

        kept := make([]string, 0, len(boxLines))
        found := false
        for _, l := range boxLines {
                fields := strings.Fields(l)
                if len(fields) > 0 && fields[0] == email {
                        found = true
                        continue
                }
                kept = append(kept, l)
        }
        // Aliases pointing at the mailbox die with it (they are registry rows
        // too; the panel removes them first — this is the node-side mop-up).
        keptAliases := make([]string, 0, len(aliasLines))
        aliasDrops := 0
        for _, l := range aliasLines {
                fields := strings.Fields(l)
                if len(fields) == 2 && fields[1] == email {
                        aliasDrops++
                        continue
                }
                keptAliases = append(keptAliases, l)
        }

        maildir := r.mailMaildirPath(domain, local)
        preservedAs := ""
        if found {
                if p.PreserveMail {
                        trash := fmt.Sprintf("%s/.trash/%s-%d", r.mailVmailRoot(), email, time.Now().Unix())
                        if err := os.MkdirAll(filepath.Dir(trash), 0o755); err != nil {
                                return nil, nil, mailInternalError("trash dir create failed", err)
                        }
                        if err := os.Rename(maildir, trash); err != nil {
                                return nil, nil, mailInternalError("maildir preserve failed", err)
                        }
                        preservedAs = trash
                } else if err := os.RemoveAll(maildir); err != nil {
                        return nil, nil, mailInternalError("maildir remove failed", err)
                }
        }

        var maps mailMapsResult
        if !found && aliasDrops == 0 {
                entry := r.deps.WAL.NewEntry("mail.delete_mailbox", map[string]any{"email": email, "absent": true})
                _ = r.deps.WAL.Append(entry)
                return mailStatusResult{Status: "absent", Email: email}, auditQueued(entry), nil
        }
        boxMaps, err := r.mailWriteMap("virtual_mailboxes_map", kept)
        if err != nil {
                return nil, nil, err
        }
        aliasMaps, err2 := r.mailWriteMap("virtual_aliases_map", keptAliases)
        if err2 != nil {
                return nil, nil, err2
        }
        maps = worstMaps(boxMaps, aliasMaps)

        entry := r.deps.WAL.NewEntry("mail.delete_mailbox", map[string]any{
                "email": email, "preserve_mail": p.PreserveMail, "preserved": preservedAs != "", "alias_drops": aliasDrops,
        })
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "removed", Email: email, PreservedAs: preservedAs, Maps: &maps}, auditQueued(entry), nil
}

// ---- aliases -----------------------------------------------------------------

// mailCreateAlias adds "source destination" to the alias map. A source of
// "@domain" is the catch-all.
func (r *Registry) mailCreateAlias(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Source      string `json:"source"`
                Destination string `json:"destination"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        source := strings.ToLower(strings.TrimSpace(p.Source))
        destination := strings.ToLower(strings.TrimSpace(p.Destination))

        var domain string
        if strings.HasPrefix(source, "@") {
                domain = strings.TrimPrefix(source, "@")
                if len(domain) > 253 || !mailDomainRe.MatchString(domain) {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid catch-all domain"}
                }
        } else {
                _, d, err := mailValidateEmail(source)
                if err != nil {
                        return nil, nil, err
                }
                domain = d
        }
        if _, _, err := mailValidateEmail(destination); err != nil {
                return nil, nil, err
        }
        if source == destination {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "alias source and destination must differ (that would loop)"}
        }

        dir := r.mailMapsDir()
        if !mailDomainInMap(mailReadMap(dir+"/virtual_domains_map"), domain) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "mail domain is not provisioned on the node (create it first)"}
        }
        aliasLines := mailReadMap(dir + "/virtual_aliases_map")
        for _, l := range aliasLines {
                if strings.Fields(l)[0] == source {
                        return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "alias source already exists on the node"}
                }
        }
        maps, err := r.mailWriteMap("virtual_aliases_map", append(aliasLines, source+" "+destination))
        if err != nil {
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("mail.create_alias", map[string]any{"source": source, "destination": destination})
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "created", Domain: domain, Maps: &maps}, auditQueued(entry), nil
}

// mailDeleteAlias removes the alias's first map line. Absent is a success.
func (r *Registry) mailDeleteAlias(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Source string `json:"source"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        source := strings.ToLower(strings.TrimSpace(p.Source))
        if source == "" {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "source is required"}
        }

        aliasLines := mailReadMap(r.mailMapsDir() + "/virtual_aliases_map")
        kept := make([]string, 0, len(aliasLines))
        found := false
        for _, l := range aliasLines {
                fields := strings.Fields(l)
                if len(fields) > 0 && fields[0] == source {
                        found = true
                        continue
                }
                kept = append(kept, l)
        }
        if !found {
                entry := r.deps.WAL.NewEntry("mail.delete_alias", map[string]any{"source": source, "absent": true})
                _ = r.deps.WAL.Append(entry)
                return mailStatusResult{Status: "absent"}, auditQueued(entry), nil
        }
        maps, err := r.mailWriteMap("virtual_aliases_map", kept)
        if err != nil {
                return nil, nil, err
        }

        entry := r.deps.WAL.NewEntry("mail.delete_alias", map[string]any{"source": source})
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "removed", Maps: &maps}, auditQueued(entry), nil
}

// ---- autoresponders -----------------------------------------------------------

// mailCreateAutoresponder writes the mailbox's Sieve vacation script.
// The scheduling window is panel-side truth (ADR-0013): the CP decides
// whether the responder should be active and calls create/delete
// accordingly; the agent writes or removes the file.
func (r *Registry) mailCreateAutoresponder(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Email   string `json:"email"`
                Subject string `json:"subject"`
                Body    string `json:"body"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        local, domain, err := mailValidateEmail(strings.ToLower(strings.TrimSpace(p.Email)))
        if err != nil {
                return nil, nil, err
        }
        if strings.TrimSpace(p.Subject) == "" || len(p.Subject) > 255 {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "subject must be 1-255 chars"}
        }
        if strings.TrimSpace(p.Body) == "" || len(p.Body) > 8192 || strings.ContainsRune(p.Body, 0) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "body must be 1-8192 bytes without NUL"}
        }

        maildir := r.mailMaildirPath(domain, local)
        if fi, statErr := os.Stat(maildir); statErr != nil || !fi.IsDir() {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "mailbox does not exist on the node (create it first)"}
        }
        script := maildir + "/.dovecot.sieve"
        staging := script + ".nexus-staging"
        if err := os.WriteFile(staging, []byte(mailSieveScript(p.Subject, p.Body)), sieveFileMode); err != nil {
                return nil, nil, mailInternalError("sieve staging write failed", err)
        }
        if err := os.Rename(staging, script); err != nil {
                _ = os.Remove(staging)
                return nil, nil, mailInternalError("sieve atomic swap failed", err)
        }
        _, _ = r.mailApplyOwnership(maildir)

        entry := r.deps.WAL.NewEntry("mail.create_autoresponder", map[string]any{"email": local + "@" + domain})
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "created", Email: local + "@" + domain, Maildir: maildir}, auditQueued(entry), nil
}

// mailDeleteAutoresponder removes the Sieve script. Absent is a success.
func (r *Registry) mailDeleteAutoresponder(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Email string `json:"email"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        local, domain, err := mailValidateEmail(strings.ToLower(strings.TrimSpace(p.Email)))
        if err != nil {
                return nil, nil, err
        }
        script := r.mailMaildirPath(domain, local) + "/.dovecot.sieve"
        if err := os.Remove(script); err != nil && !os.IsNotExist(err) {
                return nil, nil, mailInternalError("sieve remove failed", err)
        }

        entry := r.deps.WAL.NewEntry("mail.delete_autoresponder", map[string]any{"email": local + "@" + domain})
        _ = r.deps.WAL.Append(entry)
        return mailStatusResult{Status: "removed", Email: local + "@" + domain}, auditQueued(entry), nil
}

// ---- reload --------------------------------------------------------------------

// mailServiceResult is the per-daemon reload outcome (honest skips stated).
type mailServiceResult struct {
        Service string `json:"service"`
        Applied bool   `json:"applied"`
        Skipped string `json:"skipped,omitempty"`
        Detail  string `json:"detail,omitempty"`
}

// mailReload asks Postfix and Dovecot to pick up changes. Each service is
// reported separately; a missing binary is an honest skip (the maps/DB are
// already correct — the running daemon just has not reloaded).
func (r *Registry) mailReload(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        results := []mailServiceResult{}

        for _, svc := range []struct {
                name   string
                binary string
                args   []string
        }{
                {"postfix", r.deps.PostfixBinary, []string{"reload"}},
                {"dovecot", r.deps.DoveadmBinary, []string{"reload"}},
        } {
                bin := svc.binary
                if bin == "" {
                        probe := "postfix"
                        if svc.name != "postfix" {
                                probe = "doveadm"
                        }
                        found, err := exec.LookPath(probe)
                        if err != nil {
                                results = append(results, mailServiceResult{Service: svc.name, Skipped: svc.name + " binary not found — running daemon not reloaded (applied state is on disk)"})
                                continue
                        }
                        bin = found
                }
                out, err := exec.Command(bin, svc.args...).CombinedOutput()
                if err != nil {
                        trimmed := strings.TrimSpace(string(out))
                        if len(trimmed) > mailErrDetailCap {
                                trimmed = trimmed[:mailErrDetailCap-3] + "..."
                        }
                        results = append(results, mailServiceResult{Service: svc.name, Detail: trimmed})
                        continue
                }
                results = append(results, mailServiceResult{Service: svc.name, Applied: true})
        }

        entry := r.deps.WAL.NewEntry("mail.reload", map[string]any{"services": len(results)})
        _ = r.deps.WAL.Append(entry)
        return map[string]any{"status": "done", "services": results}, auditQueued(entry), nil
}
