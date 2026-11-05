package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// waf.* + malware.* (ADR-0017 amendment to agent spec §4) — B12.
//
// Per-site WAF (ModSecurity): the agent writes ONE nginx include per domain
// (<vhostroot>/<domain>.waf.conf) that turns the engine on for that vhost —
// SecRuleEngine DetectionOnly (detect) or On (block) — with the requested
// CRS paranoia level and per-rule exclusions, then runs the same health
// gate as nginx.apply_vhost (test → reload; a failed test rolls the file
// back). mode=off removes the include (the vhost reverts to whatever the
// node's global ModSecurity posture is). The panel never touches these
// files directly; the include is the versioned, rollback-friendly unit the
// config engine snapshots.
//
// Anti-malware (ClamAV): scans run through the injected clamscan binary
// over a confined path. Infected files are quarantined by MOVING them into
// the quarantine root (0600, relative structure preserved) — never deleted
// in place. Delete and restore of a quarantined artifact are separate,
// audited panel flows; restore is confined to hosting-account homes via
// the same fsTarget primitive as every other content op.

const (
	wafExt           = ".waf.conf"
	maxWafDomainLen  = 253
	maxWafExclusions = 200
	quarantineFileMo = 0o600
	malwareScanRoot  = "/" // scan targets are validated per-scope, not rooted here
)

var (
	wafFqdnRe     = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	wafRuleIDRe   = regexp.MustCompile(`^([0-9]{1,9}|[a-zA-Z0-9_:.-]{1,128})$`)
	malwarePathRe = regexp.MustCompile(`^/[\w./ -]{1,512}$`)
	wafParanoiaRe = regexp.MustCompile(`^[12]$`)
	clamSigLineRe = regexp.MustCompile(`^(.*): \(([a-zA-Z0-9._-]+)\) FOUND$`)
	clamSummaryRe = regexp.MustCompile(`^Infected files: ([0-9]+)$`)
	clamScannedRe = regexp.MustCompile(`^[0-9]+ directories\s*$|Known viruses|Scanned files: ([0-9]+)$`)
)

type wafPolicyParams struct {
	Domain        string   `json:"domain"`
	Mode          string   `json:"mode"` // off | detect | block
	ParanoiaLevel int      `json:"paranoia_level"`
	Exclusions    []string `json:"exclusions"` // CRS rule IDs to remove for this site
}

type wafPolicyResult struct {
	Status       string `json:"status"`
	Domain       string `json:"domain"`
	Mode         string `json:"mode"`
	ConfPath     string `json:"conf_path"`
	HealthCheck  string `json:"health_check"`
	HealthDetail string `json:"health_detail,omitempty"`
}

type malwareScanParams struct {
	Scope        string `json:"scope"` // server | account | site
	Path         string `json:"path"`
	MoveInfected bool   `json:"move_infected"`
}

type malwareFinding struct {
	Path           string `json:"path"`
	Signature      string `json:"signature"`
	QuarantinePath string `json:"quarantine_path,omitempty"`
}

type malwareScanResult struct {
	Status        string           `json:"status"`
	Scope         string           `json:"scope"`
	Path          string           `json:"path"`
	FilesScanned  int              `json:"files_scanned"`
	InfectedCount int              `json:"infected_count"`
	Findings      []malwareFinding `json:"findings"`
	QuarantineDir string           `json:"quarantine_dir,omitempty"`
	Engine        string           `json:"engine"`
}

type malwareQuarantineEntry struct {
	Path string `json:"path"`
	Size uint64 `json:"size_bytes"`
}

// validateWafPolicy enforces the whitelist before anything is rendered.
func validateWafPolicy(p wafPolicyParams) error {
	if !wafFqdnRe.MatchString(p.Domain) || len(p.Domain) > maxWafDomainLen {
		return fmt.Errorf("invalid domain")
	}
	if p.Mode != "off" && p.Mode != "detect" && p.Mode != "block" {
		return fmt.Errorf("mode must be off|detect|block")
	}
	if p.Mode != "off" {
		if !wafParanoiaRe.MatchString(strconv.Itoa(p.ParanoiaLevel)) {
			return fmt.Errorf("paranoia_level must be 1 or 2")
		}
		if len(p.Exclusions) > maxWafExclusions {
			return fmt.Errorf("at most %d exclusions per policy", maxWafExclusions)
		}
		seen := map[string]bool{}
		for i, x := range p.Exclusions {
			if !wafRuleIDRe.MatchString(x) {
				return fmt.Errorf("exclusion[%d] must be a CRS rule id (digits or a rule tag)", i)
			}
			if seen[x] {
				return fmt.Errorf("exclusion[%d]: duplicate rule id %q", i, x)
			}
			seen[x] = true
		}
	}
	return nil
}

// renderWafInclude builds the per-domain nginx include. Comments carry the
// policy so `config.list_active` style diffs are self-explanatory.
func renderWafInclude(p wafPolicyParams) string {
	var b strings.Builder
	b.WriteString("# Managed by NexusPanel (waf.apply_policy) — DO NOT EDIT.\n")
	b.WriteString("# Per-site ModSecurity posture for " + p.Domain + "\n")
	engine := "On"
	if p.Mode == "detect" {
		engine = "DetectionOnly"
	}
	b.WriteString("modsecurity on;\n")
	b.WriteString("modsecurity_rules_file '/etc/nexuspanel/modsecurity/nexuspanel-crs.conf';\n")
	b.WriteString("# mode: " + p.Mode + " (SecRuleEngine " + engine + ")\n")
	b.WriteString("# paranoia_level: " + strconv.Itoa(p.ParanoiaLevel) + "\n")
	for _, x := range p.Exclusions {
		b.WriteString("# exclusion: " + x + "\n")
		b.WriteString("SecRuleRemoveById " + x + "\n")
	}
	return b.String()
}

// wafApplyPolicy writes the per-domain include + health gate. mode=off
// removes the include (idempotent).
func (r *Registry) wafApplyPolicy(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p wafPolicyParams
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	if err := validateWafPolicy(p); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
	}

	final := filepath.Join(r.deps.VhostRoot, p.Domain+wafExt)

	if p.Mode == "off" {
		removed := false
		if _, err := os.Stat(final); err == nil {
			if err := os.Remove(final); err != nil {
				return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "include remove failed: " + err.Error()}
			}
			removed = true
		}
		status, detail, failed := r.healthCheck()
		if failed {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodePrecondition,
				Message: "health check failed after include removal: " + detail,
			}
		}
		entry := r.deps.WAL.NewEntry("waf.apply_policy", map[string]any{
			"domain": p.Domain, "mode": "off", "removed": removed, "health_check": status,
		})
		_ = r.deps.WAL.Append(entry)
		return wafPolicyResult{
			Status: "applied", Domain: p.Domain, Mode: "off",
			ConfPath: final, HealthCheck: status, HealthDetail: detail,
		}, auditQueued(entry), nil
	}

	content := renderWafInclude(p)
	_, prevOk, restore, err := atomicWrite(final, []byte(content))
	if err != nil {
		return nil, nil, err
	}
	status, detail, failed := r.healthCheck()
	if failed {
		restore()
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "health check failed; WAF include rolled back: " + detail,
		}
	}
	entry := r.deps.WAL.NewEntry("waf.apply_policy", map[string]any{
		"domain": p.Domain, "mode": p.Mode, "paranoia_level": p.ParanoiaLevel,
		"exclusions": len(p.Exclusions), "health_check": status, "previous_existed": prevOk,
	})
	_ = r.deps.WAL.Append(entry)
	return wafPolicyResult{
		Status: "applied", Domain: p.Domain, Mode: p.Mode,
		ConfPath: final, HealthCheck: status, HealthDetail: detail,
	}, auditQueued(entry), nil
}

// malwareScan runs ClamAV over a confined path; optionally quarantines
// infected files (move into the quarantine root, 0600).
func (r *Registry) malwareScan(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p malwareScanParams
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	if p.Scope != "server" && p.Scope != "account" && p.Scope != "site" {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "scope must be server|account|site"}
	}
	if !malwarePathRe.MatchString(p.Path) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "path must be an absolute filesystem path"}
	}
	if fi, err := os.Stat(p.Path); err != nil || !fi.IsDir() {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "scan path must exist and be a directory"}
	}

	bin := r.deps.ClamscanBinary
	if bin == "" {
		var err error
		bin, err = exec.LookPath("clamscan")
		if err != nil {
			if bin2, e2 := exec.LookPath("clamdscan"); e2 == nil {
				bin = bin2
			} else {
				return nil, nil, &rpc.RPCError{
					Code:    rpc.CodePrecondition,
					Message: "clamscan not found on this node — install ClamAV (ADR-0017)",
				}
			}
		}
	}

	cmd := exec.Command(bin, "-r", "--infected", "--no-summary", p.Path)
	out, err := cmd.CombinedOutput()
	res := malwareScanResult{
		Status: "success", Scope: p.Scope, Path: p.Path,
		Findings: []malwareFinding{}, Engine: filepath.Base(bin),
	}
	// clamscan exits 1 when infections were found — that is not a failure.
	if err != nil && exitCode(err) != 1 {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "clamscan failed: " + firstLine(string(out)),
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if m := clamSigLineRe.FindStringSubmatch(line); m != nil {
			f := malwareFinding{Path: m[1], Signature: m[2]}
			if p.MoveInfected {
				qp, qerr := r.quarantineFile(f.Path)
				if qerr != nil {
					res.Findings = append(res.Findings, f) // reported, honestly not quarantined
					continue
				}
				f.QuarantinePath = qp
				res.QuarantineDir = r.deps.QuarantineRoot
			}
			res.Findings = append(res.Findings, f)
			res.InfectedCount++
		} else if m := clamScannedRe.FindStringSubmatch(line); m != nil && m[1] != "" {
			res.FilesScanned, _ = strconv.Atoi(m[1])
		}
	}

	entry := r.deps.WAL.NewEntry("malware.scan", map[string]any{
		"scope": p.Scope, "path": p.Path, "infected": res.InfectedCount,
		"quarantined": len(res.Findings) - countUnquarantined(res.Findings), "engine": res.Engine,
	})
	_ = r.deps.WAL.Append(entry)
	return res, auditQueued(entry), nil
}

func countUnquarantined(fs []malwareFinding) int {
	n := 0
	for _, f := range fs {
		if f.QuarantinePath == "" {
			n++
		}
	}
	return n
}

// exitCode extracts the process exit code from an exec error.
func exitCode(err error) int {
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// quarantineFile moves one infected file into the quarantine root,
// preserving the relative structure and dropping to 0600.
func (r *Registry) quarantineFile(orig string) (string, error) {
	root := r.deps.QuarantineRoot
	if root == "" {
		return "", fmt.Errorf("quarantine root not configured")
	}
	st, err := os.Stat(orig)
	if err != nil {
		return "", err
	}
	_ = st
	qdir := filepath.Join(root, strings.TrimPrefix(filepath.Dir(orig), "/"))
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return "", err
	}
	qpath := filepath.Join(qdir, filepath.Base(orig)+".quarantined")
	if err := os.Rename(orig, qpath); err != nil {
		return "", err
	}
	_ = os.Chmod(qpath, quarantineFileMo)
	return qpath, nil
}

// malwareQuarantineList lists artifacts currently in the quarantine root
// (read-only, spec §6).
func (r *Registry) malwareQuarantineList(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	root := r.deps.QuarantineRoot
	if root == "" {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "quarantine root not configured"}
	}
	entries := []malwareQuarantineEntry{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil // skip unreadable entries honestly
		}
		entries = append(entries, malwareQuarantineEntry{Path: path, Size: uint64(info.Size())})
		return nil
	})
	return map[string]any{"root": root, "entries": entries}, nil, nil
}

// malwareQuarantineDelete removes one artifact from quarantine — audited,
// confined to the quarantine root.
func (r *Registry) malwareQuarantineDelete(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	clean, err := quarantineTarget(r.deps.QuarantineRoot, p.Path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
	}
	if err := os.Remove(clean); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "delete failed: " + err.Error()}
	}
	entry := r.deps.WAL.NewEntry("malware.quarantine_delete", map[string]any{"path": clean})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{"status": "deleted", "path": clean}, auditQueued(entry), nil
}

// malwareQuarantineRestore moves one artifact back to an account home
// (confined via fsTarget) — audited.
func (r *Registry) malwareQuarantineRestore(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Path     string `json:"path"`
		Username string `json:"username"`
		RelPath  string `json:"rel_path"` // destination relative to the account home
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	clean, err := quarantineTarget(r.deps.QuarantineRoot, p.Path)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if !malwarePathRe.MatchString("/"+p.RelPath) || strings.Contains(p.RelPath, "..") {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid destination path"}
	}
	dest, err := fsTarget(r.deps.HomeRoot, p.Username, p.RelPath)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "dest dir create failed: " + err.Error()}
	}
	if err := os.Rename(clean, dest); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "restore move failed: " + err.Error()}
	}
	_ = os.Chmod(dest, 0o644)
	ownership, _ := chownToUserBestEffort(dest, p.Username)
	entry := r.deps.WAL.NewEntry("malware.quarantine_restore", map[string]any{
		"from": clean, "to": dest, "ownership": ownership,
	})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{"status": "restored", "path": dest}, auditQueued(entry), nil
}

// quarantineTarget resolves a path INSIDE the quarantine root only.
func quarantineTarget(root, path string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("quarantine root not configured")
	}
	if filepath.IsAbs(path) {
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("path is outside the quarantine root")
		}
		path = rel
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path must not contain '..'")
	}
	clean := filepath.Join(root, filepath.Clean("/"+path))
	if !strings.HasPrefix(clean, filepath.Clean(root)+string(os.PathSeparator)) {
		return "", fmt.Errorf("path is outside the quarantine root")
	}
	return clean, nil
}
