package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// firewall.* + fail2ban.* (ADR-0016 amendment to agent spec §4) — B11.
//
// The agent is the ONLY writer of firewall state on the node. The panel owns
// the registry (firewall_rules, DDL-first) and mirrors what the agent applied;
// a failed nft run leaves the panel row unwritten (agent-first, like dns.*).
//
// Design invariants:
//
//   - Whitelist model: the desired state is a closed rule set rendered into
//     ONE managed nftables table (inet nexuspanel). Nothing outside the
//     managed table is ever touched, and unknown params are rejected
//     (DisallowUnknownFields, server-settings pattern).
//   - Fail-closed validation: a render that fails `nft -c` never reaches the
//     kernel (check → delete-if-exists → apply, in that order, each an
//     observable step). The previous ruleset keeps running on any failure.
//   - Self-lockout guard: the panel cannot sever the operator's management
//     path. A drop/reject that covers SSH (22) or the panel's own HTTP
//     surfaces (3000 control plane, 5173 web) from an unfiltered source is
//     rejected at the agent REGARDLESS of what the panel validates — the
//     agent is the last line of defense, not a rubber stamp (server-settings
//     fail-closed pattern). allow_unsafe_management_lockout must be true to
//     override, and the override is audited verbatim.
//   - fail2ban integration is read-mostly: jails/bans are parsed live from
//     fail2ban-client (never from the panel DB — D-11 honesty); unban is a
//     narrow, audited mutation. There is deliberately no ban command: banning
//     is fail2ban's job, not the panel's.
//
// All external binaries are injectable for tests (fake sh scripts that
// record argv, the established pattern in this package).

const (
	maxFirewallRules    = 100
	maxFirewallNameLen  = 64
	maxRulesetReport    = 8 << 10
	firewallCommentSize = 120
)

var (
	firewallNameRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 ._:-]{0,63}$`)
	fail2banJailRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	defaultAnyV4    = "0.0.0.0/0"
	defaultAnyV6    = "::/0"
	managementPorts = map[int]string{
		22:   "ssh",
		3000: "control plane HTTP",
		5173: "panel web",
	}
)

type fwRule struct {
	Name       string `json:"name"`
	Direction  string `json:"direction"` // inbound | outbound
	Protocol   string `json:"protocol"`  // tcp | udp | icmp
	PortFrom   *int   `json:"port_from"` // null = any port
	PortTo     *int   `json:"port_to"`   // null = single/from only
	SourceCidr string `json:"source_cidr"`
	Action     string `json:"action"` // accept | drop | reject
}

type fwApplyParams struct {
	Rules                        []fwRule `json:"rules"`
	AllowUnsafeManagementLockout bool     `json:"allow_unsafe_management_lockout"`
}

type fwApplyResult struct {
	Status    string `json:"status"`
	RuleCount int    `json:"rule_count"`
	ConfPath  string `json:"conf_path"`
	Checked   bool   `json:"checked"`
}

type fwStatusResult struct {
	Configured bool   `json:"configured"`
	Table      string `json:"table"`
	Ruleset    string `json:"ruleset"`
}

type f2bJailStatus struct {
	Name            string   `json:"name"`
	CurrentlyBanned int      `json:"currently_banned"`
	TotalBanned     int      `json:"total_banned"`
	BannedIPs       []string `json:"banned_ips"`
	Note            string   `json:"note,omitempty"`
}

type f2bJailsResult struct {
	Jails      []f2bJailStatus `json:"jails"`
	JailClient string          `json:"fail2ban_client"`
}

type f2bUnbanResult struct {
	Jail     string `json:"jail"`
	IP       string `json:"ip"`
	Unbanned bool   `json:"unbanned"`
}

// ---- validation -------------------------------------------------------------

func normalizeCIDR(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q", s)
		}
		return s, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", s)
	}
	if ip.To4() != nil {
		return s + "/32", nil
	}
	return s + "/128", nil
}

func cidrIsAny(cidr string) bool {
	return cidr == "" || cidr == defaultAnyV4 || cidr == defaultAnyV6
}

func portRangeCovers(r fwRule, port int) bool {
	if r.PortFrom == nil {
		return true // no port filter = all ports
	}
	from := *r.PortFrom
	to := from
	if r.PortTo != nil {
		to = *r.PortTo
	}
	return port >= from && port <= to
}

// validateRules enforces the whitelist: enums, port sanity, CIDR sanity and
// the self-lockout guard. It returns the rules with normalized CIDRs.
func validateRules(params fwApplyParams) ([]fwRule, error) {
	if len(params.Rules) > maxFirewallRules {
		return nil, fmt.Errorf("at most %d rules per apply (got %d)", maxFirewallRules, len(params.Rules))
	}
	seenNames := map[string]bool{}
	out := make([]fwRule, 0, len(params.Rules))
	for i, r := range params.Rules {
		label := fmt.Sprintf("rule[%d]", i)
		if !firewallNameRe.MatchString(r.Name) {
			return nil, fmt.Errorf("%s.name must be 1-64 chars of letters, digits, space, dot, dash, colon, underscore", label)
		}
		if seenNames[r.Name] {
			return nil, fmt.Errorf("%s: duplicate name %q", label, r.Name)
		}
		seenNames[r.Name] = true
		if r.Direction != "inbound" && r.Direction != "outbound" {
			return nil, fmt.Errorf("%s.direction must be inbound|outbound", label)
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" {
			return nil, fmt.Errorf("%s.protocol must be tcp|udp|icmp", label)
		}
		if r.Action != "accept" && r.Action != "drop" && r.Action != "reject" {
			return nil, fmt.Errorf("%s.action must be accept|drop|reject", label)
		}
		if r.Protocol == "icmp" && (r.PortFrom != nil || r.PortTo != nil) {
			return nil, fmt.Errorf("%s: icmp rules carry no ports", label)
		}
		if r.PortFrom != nil {
			p := *r.PortFrom
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("%s.port_from out of range (1-65535)", label)
			}
			if r.PortTo != nil {
				if *r.PortTo < p || *r.PortTo > 65535 {
					return nil, fmt.Errorf("%s.port_to must be >= port_from and <= 65535", label)
				}
			}
		} else if r.PortTo != nil {
			return nil, fmt.Errorf("%s: port_to without port_from", label)
		}
		cidr, err := normalizeCIDR(r.SourceCidr)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", label, err)
		}
		r.SourceCidr = cidr

		// Self-lockout guard (fail-closed, server-settings pattern).
		if !params.AllowUnsafeManagementLockout && r.Action != "accept" && cidrIsAny(cidr) {
			if r.Direction == "inbound" && r.Protocol == "tcp" {
				for port, what := range managementPorts {
					if portRangeCovers(r, port) {
						return nil, fmt.Errorf(
							"%s would block the management path (%s, tcp/%d) from any source — refused (self-lockout guard, ADR-0016)",
							label, what, port)
					}
				}
			}
			if r.PortFrom == nil && (r.Direction == "outbound" || r.Protocol == "icmp") {
				return nil, fmt.Errorf(
					"%s would drop/reject ALL %s traffic — refused (total-lockout guard, ADR-0016)",
					label, r.Direction)
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// ---- render -----------------------------------------------------------------

// renderNftScript renders the managed table. `delete table` before `table`
// makes re-apply idempotent; a missing table on first apply is fine because
// the apply step runs delete-if-exists separately before this file.
func renderNftScript(rules []fwRule) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Managed by NexusPanel (firewall.apply_rules) — DO NOT EDIT.\n")
	b.WriteString("# Rendered from the panel registry; hand edits are overwritten on next apply.\n")
	b.WriteString("table inet nexuspanel\n")
	b.WriteString("delete table inet nexuspanel\n")
	b.WriteString("table inet nexuspanel {\n")
	for _, chain := range []string{"input", "output"} {
		dir := "inbound"
		if chain == "output" {
			dir = "outbound"
		}
		b.WriteString("  chain " + chain + " {\n")
		b.WriteString("    type filter hook " + chain + " priority 0; policy accept;\n")
		for _, r := range rules {
			if r.Direction != dir {
				continue
			}
			b.WriteString("    " + renderRuleLine(r) + "\n")
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func renderRuleLine(r fwRule) string {
	var parts []string
	comment := ""
	if r.Name != "" && len(r.Name) <= firewallCommentSize {
		comment = " # " + r.Name
	}
	family := "ip"
	if strings.Contains(r.SourceCidr, ":") {
		family = "ip6"
	}
	if r.SourceCidr != "" {
		if r.Direction == "inbound" {
			parts = append(parts, family+" saddr "+r.SourceCidr)
		} else {
			parts = append(parts, family+" daddr "+r.SourceCidr)
		}
	}
	switch r.Protocol {
	case "tcp", "udp":
		parts = append(parts, r.Protocol+" dport "+portSpec(r))
	case "icmp":
		parts = append(parts, "ip protocol icmp")
	}
	parts = append(parts, r.Action)
	return strings.Join(parts, " ") + comment
}

func portSpec(r fwRule) string {
	if r.PortFrom == nil {
		return "1-65535" // explicit span keeps `nft -c` honest about intent
	}
	if r.PortTo != nil && *r.PortTo != *r.PortFrom {
		return strconv.Itoa(*r.PortFrom) + "-" + strconv.Itoa(*r.PortTo)
	}
	return strconv.Itoa(*r.PortFrom)
}

// ---- commands ---------------------------------------------------------------

// firewallApplyRules reconciles the managed nftables table with the desired
// rule set. Order is fail-closed: compile-check → delete-if-exists → apply.
func (r *Registry) firewallApplyRules(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p fwApplyParams
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	rules, err := validateRules(p)
	if err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
	}

	bin := r.deps.NftBinary
	if bin == "" {
		var err error
		bin, err = exec.LookPath("nft")
		if err != nil {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodePrecondition,
				Message: "nft not found on this node — install nftables (ADR-0016)",
			}
		}
	}
	confPath := r.deps.NftConfPath
	if confPath == "" {
		confPath = "/etc/nexuspanel/firewall.conf"
	}
	script := renderNftScript(rules)

	if dir := filepath.Dir(confPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "conf dir create failed: " + err.Error()}
		}
	}
	staging := confPath + ".nexus-staging"
	if err := os.WriteFile(staging, []byte(script), 0o644); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "staging write failed: " + err.Error()}
	}

	// 1. compile-check — a broken ruleset never reaches the kernel.
	check, err := exec.Command(bin, "-c", "-f", staging).CombinedOutput()
	if err != nil {
		_ = os.Remove(staging)
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: fmt.Sprintf("nft check failed: %s", firstLine(string(check))),
		}
	}
	_ = check

	// 2. remove the previous generation (missing table on first apply is fine).
	if out, derr := exec.Command(bin, "list", "table", "inet", "nexuspanel").CombinedOutput(); derr == nil {
		_ = out
		if out2, derr2 := exec.Command(bin, "delete", "table", "inet", "nexuspanel").CombinedOutput(); derr2 != nil {
			_ = os.Remove(staging)
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeInternalError,
				Message: fmt.Sprintf("nft delete failed: %s", firstLine(string(out2))),
			}
		}
	}

	// 3. apply.
	apply, err := exec.Command(bin, "-f", staging).CombinedOutput()
	if err != nil {
		_ = os.Remove(staging)
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: fmt.Sprintf("nft apply failed: %s", firstLine(string(apply))),
		}
	}
	if err := os.Rename(staging, confPath); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "conf swap failed: " + err.Error()}
	}

	entry := r.deps.WAL.NewEntry("firewall.apply_rules", map[string]any{
		"rule_count": len(rules), "conf": confPath,
		"unsafe_lockout_override": p.AllowUnsafeManagementLockout,
	})
	_ = r.deps.WAL.Append(entry)
	return fwApplyResult{
		Status:    "applied",
		RuleCount: len(rules),
		ConfPath:  confPath,
		Checked:   true,
	}, auditQueued(entry), nil
}

// firewallStatus reports the live managed table (read-only, spec §6).
func (r *Registry) firewallStatus(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	bin := r.deps.NftBinary
	if bin == "" {
		var err error
		bin, err = exec.LookPath("nft")
		if err != nil {
			return fwStatusResult{Configured: false, Table: "inet nexuspanel",
				Ruleset: "nft not installed on this node"}, nil, nil
		}
	}
	out, err := exec.Command(bin, "list", "table", "inet", "nexuspanel").CombinedOutput()
	if err != nil {
		// Missing table = the panel simply hasn't applied rules yet (honest).
		return fwStatusResult{Configured: false, Table: "inet nexuspanel", Ruleset: ""}, nil, nil
	}
	ruleset := string(out)
	if len(ruleset) > maxRulesetReport {
		ruleset = ruleset[:maxRulesetReport] + "\n… (truncated)"
	}
	return fwStatusResult{Configured: true, Table: "inet nexuspanel", Ruleset: ruleset}, nil, nil
}

// fail2banJails parses live jail health from fail2ban-client (read-only).
func (r *Registry) fail2banJails(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	bin := r.deps.Fail2banClientBinary
	if bin == "" {
		var err error
		bin, err = exec.LookPath("fail2ban-client")
		if err != nil {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodePrecondition,
				Message: "fail2ban-client not found on this node — install fail2ban (ADR-0016)",
			}
		}
	}
	out, err := exec.Command(bin, "status").CombinedOutput()
	if err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: fmt.Sprintf("fail2ban status failed: %s", firstLine(string(out))),
		}
	}
	jailNames := parseFail2banJailList(string(out))
	res := f2bJailsResult{Jails: []f2bJailStatus{}, JailClient: bin}
	for _, name := range jailNames {
		js := f2bJailStatus{Name: name, BannedIPs: []string{}}
		jout, jerr := exec.Command(bin, "status", name).CombinedOutput()
		if jerr != nil {
			js.Note = "status failed: " + firstLine(string(jout))
			res.Jails = append(res.Jails, js)
			continue
		}
		parseJailStatus(string(jout), &js)
		res.Jails = append(res.Jails, js)
	}
	return res, nil, nil
}

// fail2banUnban lifts one ban (audited mutation).
func (r *Registry) fail2banUnban(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p struct {
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	if !fail2banJailRe.MatchString(p.Jail) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid jail name"}
	}
	ip := net.ParseIP(strings.TrimSpace(p.IP))
	if ip == nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid IP"}
	}
	bin := r.deps.Fail2banClientBinary
	if bin == "" {
		var err error
		bin, err = exec.LookPath("fail2ban-client")
		if err != nil {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodePrecondition,
				Message: "fail2ban-client not found on this node — install fail2ban (ADR-0016)",
			}
		}
	}
	out, err := exec.Command(bin, "set", p.Jail, "unbanip", ip.String()).CombinedOutput()
	if err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: fmt.Sprintf("unban failed: %s", firstLine(string(out))),
		}
	}
	unbanned := strings.TrimSpace(string(out)) == "1"
	entry := r.deps.WAL.NewEntry("fail2ban.unban", map[string]any{
		"jail": p.Jail, "ip": ip.String(), "unbanned": unbanned,
	})
	_ = r.deps.WAL.Append(entry)
	return f2bUnbanResult{Jail: p.Jail, IP: ip.String(), Unbanned: unbanned}, auditQueued(entry), nil
}

// ---- parsing helpers --------------------------------------------------------

// parseFail2banJailList extracts the names from `fail2ban-client status`
// output: the last "Jail list:" line, comma-separated.
func parseFail2banJailList(out string) []string {
	names := []string{}
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, "Jail list:")
		if idx < 0 {
			continue
		}
		for _, n := range strings.Split(line[idx+len("Jail list:"):], ",") {
			n = strings.TrimSpace(n)
			if n != "" {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names
}

// parseJailStatus fills the counters from `fail2ban-client status <jail>`.
func parseJailStatus(out string, js *f2bJailStatus) {
	for _, line := range strings.Split(out, "\n") {
		parts := splitColon(line)
		key, val := parts[0], strings.Join(parts[1:], ":")
		key = strings.Trim(strings.TrimSpace(key), "|`- ")
		switch key {
		case "Currently banned":
			js.CurrentlyBanned = atoiSafe(strings.TrimSpace(val))
		case "Total banned":
			js.TotalBanned = atoiSafe(strings.TrimSpace(val))
		case "Banned IP list":
			for _, ip := range strings.Fields(val) {
				if net.ParseIP(ip) != nil {
					js.BannedIPs = append(js.BannedIPs, ip)
				}
			}
		}
	}
}
