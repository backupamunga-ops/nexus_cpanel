package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// firewall.*/fail2ban.* tests run fully in-process against fake binaries
// (the established pattern): a fake `nft` that records argv and can fail
// stages, a fake `fail2ban-client` with canned output, a temp conf path.

// fakeRecorderBin builds a sh script that appends its argv to a log and
// prints canned output; optional fail marker exits non-zero when argv
// contains the marker.
func fakeRecorderBin(t *testing.T, name, cannedOutput, failOnArg string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, name)
	log = filepath.Join(dir, name+"-argv.log")
	script := fmt.Sprintf(`#!/bin/sh
for a in "$@"; do echo -n "%s " >> %q; echo -n "$a " >> %q; done
echo "" >> %q
%s
if [ -n %q ] && echo "$@" | grep -q -- "$0_ARGV_MARKER"; then :; fi
echo %q
exit 0
`, "", log, log, log, "", "", "'"+cannedOutput+"'")
	// Simpler, robust version below — build it explicitly.
	script = "#!/bin/sh\n" +
		"for a in \"$@\"; do echo -n \"$a \" >> " + strconvQuote(log) + "; done\n" +
		"echo \"\" >> " + strconvQuote(log) + "\n" +
		"printf '%s\\n' " + shQuote(cannedOutput) + "\n" +
		"exit 0\n"
	if failOnArg != "" {
		script = "#!/bin/sh\n" +
			"for a in \"$@\"; do echo -n \"$a \" >> " + strconvQuote(log) + "; done\n" +
			"echo \"\" >> " + strconvQuote(log) + "\n" +
			"for a in \"$@\"; do if [ \"$a\" = \"" + failOnArg + "\" ]; then echo \"boom: $a\" >&2; exit 1; fi; done\n" +
			"printf '%s\\n' " + shQuote(cannedOutput) + "\n" +
			"exit 0\n"
	}
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func strconvQuote(s string) string { return "\"" + s + "\"" }

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func newFirewallRegistry(t *testing.T, nftBin, f2bBin, confPath string) *Registry {
	t.Helper()
	return NewRegistry(Deps{
		WAL:                  newTestWAL(t),
		HomeRoot:             t.TempDir(),
		NftBinary:            nftBin,
		NftConfPath:          confPath,
		Fail2banClientBinary: f2bBin,
	})
}

func validRules() []fwRule {
	p22 := 22
	return []fwRule{
		{Name: "web http", Direction: "inbound", Protocol: "tcp", PortFrom: &p22, Action: "accept"},
	}
}

func TestFirewallApplyHappyPathOrder(t *testing.T) {
	nftBin, log := fakeRecorderBin(t, "nft", "", "")
	conf := filepath.Join(t.TempDir(), "firewall.conf")
	r := newFirewallRegistry(t, nftBin, "", conf)

	res, hint, err := r.firewallApplyRules("id", rawParams(t, fwApplyParams{Rules: validRules()}))
	if err != nil {
		t.Fatal(err)
	}
	applied := res.(fwApplyResult)
	if applied.Status != "applied" || applied.RuleCount != 1 || !applied.Checked {
		t.Fatalf("unexpected result: %+v", applied)
	}
	if hint == nil || hint.EntryID == "" {
		t.Fatalf("expected audit hint, got %+v", hint)
	}

	// Conf file rendered with the managed table + our rule.
	content, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"table inet nexuspanel", "chain input", "tcp dport 22 accept", "# web http"} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("conf missing %q:\n%s", want, content)
		}
	}

	// Fail-closed order: check runs before delete before apply.
	argv := readArgvLog(t, log)
	idxCheck, idxDelete, idxApply := -1, -1, -1
	for i, line := range argv {
		switch {
		case contains(line, "-c -f"):
			idxCheck = i
		case contains(line, "delete table inet nexuspanel"):
			idxDelete = i
		case contains(line, "-f") && !contains(line, "-c"):
			idxApply = i
		}
	}
	if idxCheck == -1 || idxDelete == -1 || idxApply == -1 {
		t.Fatalf("missing stages: check=%d delete=%d apply=%d (%v)", idxCheck, idxDelete, idxApply, argv)
	}
	if !(idxCheck < idxDelete && idxDelete < idxApply) {
		t.Fatalf("fail-closed order violated: check=%d delete=%d apply=%d", idxCheck, idxDelete, idxApply)
	}
}

func readArgvLog(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestFirewallSelfLockoutRefused(t *testing.T) {
	nftBin, _ := fakeRecorderBin(t, "nft", "", "")
	r := newFirewallRegistry(t, nftBin, "", filepath.Join(t.TempDir(), "f.conf"))

	p22 := 22
	cases := []fwRule{
		{Name: "block ssh", Direction: "inbound", Protocol: "tcp", PortFrom: &p22, Action: "drop"},
		{Name: "block panel", Direction: "inbound", Protocol: "tcp", Action: "reject"}, // all ports
	}
	for i, rule := range cases {
		_, _, err := r.firewallApplyRules("id", rawParams(t, fwApplyParams{Rules: []fwRule{rule}}))
		if err == nil {
			t.Fatalf("case %d: self-lockout rule accepted: %+v", i, rule)
		}
		rpcErr, ok := err.(*rpc.RPCError)
		if !ok {
			t.Fatalf("case %d: expected RPCError, got %T", i, err)
		}
		if !strings.Contains(rpcErr.Message, "self-lockout") && !strings.Contains(rpcErr.Message, "total-lockout") {
			t.Fatalf("case %d: unexpected message: %s", i, rpcErr.Message)
		}
	}

	// Override flag is honored (audited verbatim).
	res, hint, err := r.firewallApplyRules("id", rawParams(t, fwApplyParams{
		Rules:                        []fwRule{cases[0]},
		AllowUnsafeManagementLockout: true,
	}))
	if err != nil {
		t.Fatalf("override should be honored: %v", err)
	}
	if res.(fwApplyResult).RuleCount != 1 || hint == nil {
		t.Fatalf("unexpected override result")
	}
}

func TestFirewallCheckFailureLeavesKernelAlone(t *testing.T) {
	// The fake nft fails when argv contains "-c" (compile-check stage).
	nftBin, log := fakeRecorderBin(t, "nft", "", "-c")
	conf := filepath.Join(t.TempDir(), "firewall.conf")
	r := newFirewallRegistry(t, nftBin, "", conf)

	_, _, err := r.firewallApplyRules("id", rawParams(t, fwApplyParams{Rules: validRules()}))
	if err == nil {
		t.Fatal("expected check failure to surface")
	}
	// Apply (-f without -c) must never have run.
	argv := readArgvLog(t, log)
	for _, line := range argv {
		if contains(line, "-f") && !contains(line, "-c") {
			t.Fatalf("apply ran despite failed check: %v", argv)
		}
	}
}

func TestFirewallValidationWhitelist(t *testing.T) {
	nftBin, _ := fakeRecorderBin(t, "nft", "", "")
	r := newFirewallRegistry(t, nftBin, "", filepath.Join(t.TempDir(), "f.conf"))

	bad := []fwApplyParams{
		{Rules: []fwRule{{Name: "x", Direction: "sideways", Protocol: "tcp", Action: "accept"}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "sctp", Action: "accept"}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "tcp", Action: "tarpit"}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "icmp", Action: "accept",
			PortFrom: intPtr(1)}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "tcp", Action: "accept",
			PortFrom: intPtr(0)}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "tcp", Action: "accept",
			PortFrom: intPtr(10), PortTo: intPtr(5)}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "tcp", Action: "accept",
			SourceCidr: "10.0.0.0/99"}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "tcp", Action: "accept",
			SourceCidr: "not-an-ip"}}},
		{Rules: []fwRule{{Name: "", Direction: "inbound", Protocol: "tcp", Action: "accept"}}},
		{Rules: []fwRule{{Name: "x", Direction: "inbound", Protocol: "tcp", Action: "accept"},
			{Name: "x", Direction: "outbound", Protocol: "udp", Action: "accept"}}},
	}
	for i, p := range bad {
		if _, _, err := r.firewallApplyRules("id", rawParams(t, p)); err == nil {
			t.Fatalf("case %d: invalid params accepted", i)
		}
	}

	// Unknown top-level fields are rejected (DisallowUnknownFields).
	_, _, err := r.firewallApplyRules("id", json.RawMessage(
		`{"rules":[{"name":"x","direction":"inbound","protocol":"tcp","action":"accept","exec":"/bin/sh"}]}`))
	if err == nil {
		t.Fatal("unknown field accepted — whitelist hole")
	}
}

func TestFirewallStatusHonest(t *testing.T) {
	// Table present.
	nftBin, _ := fakeRecorderBin(t, "nft", "table ip nexuspanel {...}", "")
	r := newFirewallRegistry(t, nftBin, "", filepath.Join(t.TempDir(), "f.conf"))
	res, _, err := r.firewallStatus("id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.(fwStatusResult).Configured {
		t.Fatalf("expected configured=true: %+v", res)
	}

	// Binary missing entirely → honest unconfigured, no error.
	r2 := NewRegistry(Deps{WAL: newTestWAL(t), NftBinary: "/nonexistent/nft", NftConfPath: t.TempDir() + "/f.conf"})
	// Note: NftBinary set but not executable → exec fails → honest unconfigured.
	res2, _, err := r2.firewallStatus("id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.(fwStatusResult).Configured {
		t.Fatalf("expected honest unconfigured state: %+v", res2)
	}
}

func TestFail2banJailsParsing(t *testing.T) {
	statusOut := "Status\n|- Number of jail:      2\n`- Jail list:   sshd, vsftpd"
	jailOut := "Status for the jail: sshd\n|- Filter\n|  |- Currently failed: 0\n`- Actions\n   |- Currently banned: 2\n   |- Total banned:     5\n   `- Banned IP list:   203.0.113.9 198.51.100.7"
	f2bBin := fakeFail2ban(t, statusOut, perJailWithDefault(jailOut))
	r := newFirewallRegistry(t, "", f2bBin, "")

	res, _, err := r.fail2banJails("id", nil)
	if err != nil {
		t.Fatal(err)
	}
	jails := res.(f2bJailsResult).Jails
	if len(jails) != 2 {
		t.Fatalf("expected 2 jails, got %+v", jails)
	}
	ssh := jails[0]
	if ssh.Name != "sshd" || ssh.CurrentlyBanned != 2 || ssh.TotalBanned != 5 {
		t.Fatalf("bad parse: %+v", ssh)
	}
	if len(ssh.BannedIPs) != 2 || ssh.BannedIPs[0] != "203.0.113.9" {
		t.Fatalf("bad IP list: %+v", ssh.BannedIPs)
	}
}

func perJailWithDefault(out string) map[string]string {
	return map[string]string{"*": out}
}

// fakeFail2ban: `status` prints jailList; `status <jail>` prints perJail[jail]
// or perJail["*"]; `set <jail> unbanip <ip>` prints 1.
func fakeFail2ban(t *testing.T, jailList string, perJail map[string]string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fail2ban-client")
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("if [ \"$1\" = \"status\" ] && [ $# -eq 1 ]; then\n")
	b.WriteString("  printf '%s\\n' " + shQuote(jailList) + "\n  exit 0\nfi\n")
	b.WriteString("if [ \"$1\" = \"status\" ]; then\n")
	// per-jail: emit the default canned block (tests use one jail payload)
	b.WriteString("  printf '%s\\n' " + shQuote(firstValue(perJail)) + "\n  exit 0\nfi\n")
	b.WriteString("if [ \"$1\" = \"set\" ]; then echo 1; exit 0; fi\n")
	b.WriteString("exit 0\n")
	if err := os.WriteFile(bin, []byte(b.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func firstValue(m map[string]string) string {
	for _, v := range m {
		return v
	}
	return ""
}

func TestFail2banUnbanAudited(t *testing.T) {
	f2bBin, log := fakeRecorderBin(t, "fail2ban-client", "1", "")
	r := newFirewallRegistry(t, "", f2bBin, "")

	res, hint, err := r.fail2banUnban("id", rawParams(t, struct {
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}{Jail: "sshd", IP: "203.0.113.9"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.(f2bUnbanResult).Unbanned || hint == nil {
		t.Fatalf("unexpected: %+v hint=%+v", res, hint)
	}
	argv := readArgvLog(t, log)
	if len(argv) == 0 || !contains(argv[0], "set sshd unbanip 203.0.113.9") {
		t.Fatalf("unban argv wrong: %v", argv)
	}

	// Invalid IP / jail refused.
	if _, _, err := r.fail2banUnban("id", rawParams(t, map[string]string{"jail": "sshd", "ip": "999.1.2.3"})); err == nil {
		t.Fatal("bad IP accepted")
	}
	if _, _, err := r.fail2banUnban("id", rawParams(t, map[string]string{"jail": "bad jail!", "ip": "203.0.113.9"})); err == nil {
		t.Fatal("bad jail accepted")
	}
}

func intPtr(i int) *int { return &i }
