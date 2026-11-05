package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"bytes"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// dns.* (agent spec §4.9, amended by ADR-0012 with dns.get_dnssec).
//
// The agent is the ONLY writer of DNS state: PowerDNS is authoritative on
// the node and every mutation goes through the PowerDNS HTTP API (JSON,
// X-API-Key) or pdnsutil for DNSSEC. The panel owns the registry
// (dns_zones / dns_records, DDL-first) and mirrors what the agent applied —
// a failed API call leaves the panel row unwritten (agent-first, like ftp.*).
//
// Zone kind is Native: v1.0 is single-node (no secondaries), and the AXFR
// export endpoint serves transfer-format output for native zones too.
// soa_edit_api=DEFAULT is set at creation so full-replace patches bump the
// serial automatically; the SOA rrset itself is never deleted or replaced
// through dns.apply_records (it is created once, then serial-managed).
//
// Record names are canonicalized to FQDN-without-trailing-dot
// ("www" under "example.com" → "www.example.com"; "@" → apex). PowerDNS
// rrset names get the trailing dot re-added at the API boundary.
// MX/SRV priority (and SRV weight/port) travel as separate params and are
// composed into the wire content, which is the DNS wire convention.

const (
	maxDnsZoneLen    = 253
	maxDnsContentLen = 4096
	maxDnsRecords    = 500
	pdnsDetailCap    = 300
)

var (
	dnsLabelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsSingleLbl = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	dnsCAARe     = regexp.MustCompile(`^(0|128)\s+(issue|issuewild|iodef)\s+"[^"]*"$`)
)

// ---- PowerDNS API client ----------------------------------------------------

type pdnsClient struct {
	base     string // e.g. http://127.0.0.1:8081/api/v1
	apiKey   string
	serverID string
	http     *http.Client
}

func (r *Registry) pdns() (*pdnsClient, error) {
	if r.deps.PdnsHTTP == nil && r.deps.PdnsAPIKey == "" && r.deps.PdnsAPIURL == "" {
		return nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "PowerDNS API not configured on this node (NEXUSAGENT_PDNS_API_URL / NEXUSAGENT_PDNS_API_KEY)",
		}
	}
	base := r.deps.PdnsAPIURL
	if base == "" {
		base = "http://127.0.0.1:8081/api/v1"
	}
	serverID := r.deps.PdnsServerID
	if serverID == "" {
		serverID = "localhost"
	}
	return &pdnsClient{base: strings.TrimRight(base, "/"), apiKey: r.deps.PdnsAPIKey, serverID: serverID, http: r.deps.PdnsHTTP}, nil
}

// do performs one PowerDNS API call. Non-2xx responses become precondition
// errors carrying the API's own message (truncated) — PowerDNS's validation
// text is the actionable part, so it is surfaced verbatim.
func (c *pdnsClient) do(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "pdns request marshal: " + err.Error()}
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+"/servers/"+c.serverID+path, rd)
	if err != nil {
		return 0, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "pdns request build: " + err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	client := c.http
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "PowerDNS API unreachable: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "pdns response read: " + err.Error()}
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, raw, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: fmt.Sprintf("PowerDNS API %s %s → %d: %s", method, path, resp.StatusCode, pdnsErrText(raw)),
		}
	}
	return resp.StatusCode, raw, nil
}

func pdnsErrText(raw []byte) string {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "(no body)"
	}
	// The API returns {"error": "..."} on failures — unwrap when it parses.
	var shaped struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &shaped); err == nil && shaped.Error != "" {
		text = shaped.Error
	}
	if len(text) > pdnsDetailCap {
		text = text[:pdnsDetailCap-3] + "..."
	}
	return text
}

// zoneExists resolves a zone via the API: 200 → exists, 404 → absent.
func (c *pdnsClient) zoneExists(zone string) (bool, error) {
	code, _, err := c.do(http.MethodGet, "/zones/"+zone+".", nil)
	if err != nil {
		if code == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

type pdnsRRset struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        int          `json:"ttl"`
	Records    []pdnsRecord `json:"records"`
	ChangeType string       `json:"changetype,omitempty"`
	Priority   *int         `json:"priority,omitempty"`
}

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// ---- names & values ---------------------------------------------------------

// canonicalZone lowercases, strips the trailing dot, and shape-validates a
// zone name (≥ 2 labels, valid label charset, ≤ 253 bytes).
func canonicalZone(zone string) (string, error) {
	z := strings.ToLower(strings.TrimSpace(zone))
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "zone is required"}
	}
	if len(z) > maxDnsZoneLen {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "zone exceeds 253 bytes"}
	}
	labels := strings.Split(z, ".")
	if len(labels) < 2 {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "zone must have at least two labels (e.g. example.com)"}
	}
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("invalid zone label %q", l)}
		}
	}
	return z, nil
}

// canonicalRecordName resolves a record name against its zone. A name is
// ABSOLUTE when it carries a trailing dot (or already lands inside the zone);
// anything else is RELATIVE and gets the zone appended ("www" →
// "www.example.com", "a.b" → "a.b.example.com"). Absolute names outside the
// zone are rejected — an out-of-zone FQDN is always an operator mistake.
// Output: FQDN without trailing dot.
func canonicalRecordName(name, zone string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "@" {
		return zone, nil
	}
	absolute := strings.HasSuffix(n, ".")
	n = strings.TrimSuffix(n, ".")
	if n == zone {
		return zone, nil
	}
	if strings.HasSuffix(n, "."+zone) {
		for _, l := range strings.Split(strings.TrimSuffix(n, "."+zone), ".") {
			if l == "*" {
				continue // wildcard may appear as the leftmost label only
			}
			if !dnsLabelRe.MatchString(l) {
				return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("invalid record name %q", name)}
			}
		}
		return n, nil
	}
	if absolute {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("record %q is outside the zone (relative names like \"www\" get the zone appended)", name)}
	}
	// Relative name(s): every label except a leading wildcard must be valid.
	parts := strings.Split(n, ".")
	for i, l := range parts {
		if l == "*" && i == 0 {
			continue
		}
		if !dnsLabelRe.MatchString(l) {
			return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("invalid record name %q", name)}
		}
	}
	return n + "." + zone, nil
}

// dnsRecordInput is one desired record as sent by the control plane.
type dnsRecordInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority"`
	Weight   *int   `json:"weight"`
	Port     *int   `json:"port"`
}

var dnsRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true,
	"TXT": true, "SRV": true, "CAA": true, "NS": true,
}

// validateAndNormalizeRecord shape-validates one record and returns the
// wire content (priority/weight/port composed for MX/SRV) plus its
// canonical zone-qualified name.
func validateAndNormalizeRecord(in dnsRecordInput, zone string) (pdnsRRset, error) {
	if !dnsRecordTypes[in.Type] {
		return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("unsupported record type %q (allowed: A, AAAA, CNAME, MX, TXT, SRV, CAA, NS)", in.Type)}
	}
	name, err := canonicalRecordName(in.Name, zone)
	if err != nil {
		return pdnsRRset{}, err
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = 3600
	}
	if ttl < 60 || ttl > 604800 {
		return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("ttl for %s must be 60-604800", name)}
	}
	content := strings.TrimSpace(in.Content)
	if content == "" || len(content) > maxDnsContentLen {
		return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("content for %s must be 1-%d bytes", name, maxDnsContentLen)}
	}
	if strings.ContainsAny(content, "\n\r\x00") {
		return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("content for %s must be a single line", name)}
	}

	intRange := func(p *int, what string) error {
		if p == nil {
			return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("%s is required for %s %s", what, in.Type, name)}
		}
		if *p < 0 || *p > 65535 {
			return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("%s for %s must be 0-65535", what, name)}
		}
		return nil
	}

	switch in.Type {
	case "A":
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() == nil {
			return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("%s is not a valid IPv4 address (record %s)", content, name)}
		}
	case "AAAA":
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() != nil {
			return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("%s is not a valid IPv6 address (record %s)", content, name)}
		}
	case "CNAME":
		if name == zone {
			return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "CNAME at the zone apex is not allowed"}
		}
		if _, err := canonicalZone(content); err != nil {
			return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("CNAME target %q is not a valid hostname", content)}
		}
	case "NS":
		if _, err := canonicalZone(content); err != nil {
			return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("NS target %q is not a valid hostname", content)}
		}
	case "MX":
		if err := intRange(in.Priority, "priority"); err != nil {
			return pdnsRRset{}, err
		}
		if content != "." {
			if _, err := canonicalZone(content); err != nil {
				return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("MX target %q is not a valid hostname", content)}
			}
		}
		content = fmt.Sprintf("%d %s", *in.Priority, content)
	case "SRV":
		if err := intRange(in.Priority, "priority"); err != nil {
			return pdnsRRset{}, err
		}
		if err := intRange(in.Weight, "weight"); err != nil {
			return pdnsRRset{}, err
		}
		if err := intRange(in.Port, "port"); err != nil {
			return pdnsRRset{}, err
		}
		if content != "." {
			if _, err := canonicalZone(content); err != nil {
				return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("SRV target %q is not a valid hostname", content)}
			}
		}
		content = fmt.Sprintf("%d %d %d %s", *in.Priority, *in.Weight, *in.Port, content)
	case "TXT":
		if !strings.HasPrefix(content, `"`) && strings.ContainsAny(content, " ;") {
			content = `"` + strings.ReplaceAll(content, `"`, `\"`) + `"`
		}
	case "CAA":
		if !dnsCAARe.MatchString(content) {
			return pdnsRRset{}, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("CAA value must be `0|128 tag \"value\"` with tag in issue|issuewild|iodef (record %s)", name)}
		}
	}
	return pdnsRRset{Name: name + ".", Type: in.Type, TTL: ttl, Records: []pdnsRecord{{Content: content}}}, nil
}

// normalizeRecords validates a whole desired set and groups it by
// (name, type) — the rrset grain PowerDNS replaces on.
func normalizeRecords(zone string, inputs []dnsRecordInput) ([]pdnsRRset, error) {
	if len(inputs) > maxDnsRecords {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("a zone carries at most %d records", maxDnsRecords)}
	}
	grouped := map[string]*pdnsRRset{}
	order := []string{}
	for _, in := range inputs {
		rr, err := validateAndNormalizeRecord(in, zone)
		if err != nil {
			return nil, err
		}
		key := rr.Name + "|" + rr.Type
		g, ok := grouped[key]
		if !ok {
			rr.Records = append([]pdnsRecord(nil), rr.Records...)
			grouped[key] = &rr
			order = append(order, key)
			continue
		}
		g.Records = append(g.Records, rr.Records[0])
	}
	out := make([]pdnsRRset, 0, len(order))
	for _, k := range order {
		out = append(out, *grouped[k])
	}
	return out, nil
}

// ---- pdnsutil (DNSSEC + zone check) ------------------------------------------

const dnsShowOutputCap = 64 << 10

func (r *Registry) pdnsutilBinary() (string, error) {
	if r.deps.PdnsutilBinary != "" {
		return r.deps.PdnsutilBinary, nil
	}
	found, err := exec.LookPath("pdnsutil")
	if err != nil {
		return "", &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: "pdnsutil binary not found on this node — DNSSEC and zone-check operations require it",
		}
	}
	return found, nil
}

func (r *Registry) runPdnsutil(args ...string) (string, error) {
	bin, err := r.pdnsutilBinary()
	if err != nil {
		return "", err
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if ee, ok := err.(*exec.ExitError); ok && len(trimmed) == 0 {
			trimmed = strings.TrimSpace(ee.Error())
		}
		if len(trimmed) > pdnsDetailCap {
			trimmed = trimmed[:pdnsDetailCap-3] + "..."
		}
		return "", &rpc.RPCError{Code: rpc.CodePrecondition, Message: fmt.Sprintf("pdnsutil %s failed: %s", args[0], trimmed)}
	}
	return string(out), nil
}

// parseDnssecShow extracts DS, DNSKEY and key rows from `pdnsutil show-zone`.
// A zone without DNSSEC prints "Zone is not actively setup for DNSSEC" (or
// simply lacks the DNSSEC block) — both map to enabled=false.
func parseDnssecShow(out string) (enabled bool, ds, dnskey []string, keys []map[string]any) {
	ds, dnskey, keys = []string{}, []string{}, []map[string]any{}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "DS = "):
			enabled = true
			v := strings.TrimPrefix(l, "DS = ")
			if i := strings.Index(v, ";"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			ds = append(ds, v)
		case strings.HasPrefix(l, "DNSKEY = "):
			enabled = true
			v := strings.TrimPrefix(l, "DNSKEY = ")
			if i := strings.Index(v, ";"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			dnskey = append(dnskey, v)
		case strings.Contains(l, "Also available in DNSSEC format"):
			enabled = true
		default:
			if m := regexp.MustCompile(`^(KSK|ZSK).*id = (\d+)`).FindStringSubmatch(l); m != nil {
				keys = append(keys, map[string]any{
					"key_type": m[1],
					"key_id":   m[2],
					"detail":   l,
				})
			}
		}
	}
	return enabled, ds, dnskey, keys
}

// ---- allowlisted methods ------------------------------------------------------

// dnsCreateZone creates a Native zone via the PowerDNS API. When the payload
// carries no SOA, a conventional one is seeded (ns1.<zone>, hostmaster.<zone>)
// and reported honestly via soa_seeded — the operator sees the row and can
// correct it through a re-create. Conflict when the zone already exists.
func (r *Registry) dnsCreateZone(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone    string           `json:"zone"`
		Records []dnsRecordInput `json:"records"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	c, err := r.pdns()
	if err != nil {
		return nil, nil, err
	}
	if exists, err := c.zoneExists(zone); err != nil {
		return nil, nil, err
	} else if exists {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "zone already exists in PowerDNS"}
	}

	rrsets, err := normalizeRecords(zone, p.Records)
	if err != nil {
		return nil, nil, err
	}
	soaSeeded := false
	hasSOA := false
	for _, rr := range rrsets {
		if rr.Type == "SOA" {
			hasSOA = true
		}
	}
	if !hasSOA {
		soaSeeded = true
		soa := fmt.Sprintf("%s. hostmaster.%s. %d 10800 3600 604800 3600", zone, zone, nowFunc().Unix())
		rrsets = append(rrsets, pdnsRRset{Name: zone + ".", Type: "SOA", TTL: 3600, Records: []pdnsRecord{{Content: soa}}})
	}

	createBody := map[string]any{
		"name":         zone + ".",
		"kind":         "Native",
		"rrsets":       rrsets,
		"soa_edit_api": "DEFAULT",
	}
	if _, _, err := c.do(http.MethodPost, "/zones", createBody); err != nil {
		return nil, nil, err
	}

	entry := r.deps.WAL.NewEntry("dns.create_zone", map[string]any{
		"zone": zone, "record_count": len(rrsets), "soa_seeded": soaSeeded,
	})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{
		"status": "created", "zone": zone, "kind": "Native",
		"record_count": len(rrsets), "soa_seeded": soaSeeded,
	}, auditQueued(entry), nil
}

// dnsDeleteZone removes the zone. Absent is a success (desired state met).
func (r *Registry) dnsDeleteZone(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone string `json:"zone"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	c, err := r.pdns()
	if err != nil {
		return nil, nil, err
	}
	exists, err := c.zoneExists(zone)
	if err != nil {
		return nil, nil, err
	}
	if !exists {
		entry := r.deps.WAL.NewEntry("dns.delete_zone", map[string]any{"zone": zone, "absent": true})
		_ = r.deps.WAL.Append(entry)
		return map[string]any{"status": "absent", "zone": zone}, auditQueued(entry), nil
	}
	if _, _, err := c.do(http.MethodDelete, "/zones/"+zone+".", nil); err != nil {
		return nil, nil, err
	}
	entry := r.deps.WAL.NewEntry("dns.delete_zone", map[string]any{"zone": zone})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{"status": "removed", "zone": zone}, auditQueued(entry), nil
}

// dnsApplyRecords full-replaces the zone's record set (SOA excluded and
// protected — it is serial-managed via soa_edit_api). The diff is computed
// against live PowerDNS state, so out-of-band edits are cleaned up here too.
func (r *Registry) dnsApplyRecords(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone    string           `json:"zone"`
		Records []dnsRecordInput `json:"records"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	for _, in := range p.Records {
		if strings.EqualFold(strings.TrimSpace(in.Type), "SOA") {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodeInvalidParams,
				Message: "SOA is managed by the nameserver and cannot be set through apply_records",
			}
		}
	}
	c, err := r.pdns()
	if err != nil {
		return nil, nil, err
	}

	desired, err := normalizeRecords(zone, p.Records)
	if err != nil {
		return nil, nil, err
	}

	_, rawZone, err := c.do(http.MethodGet, "/zones/"+zone+".", nil)
	if err != nil {
		return nil, nil, err
	}
	var current struct {
		RRsets []pdnsRRset `json:"rrsets"`
	}
	if err := json.Unmarshal(rawZone, &current); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "pdns zone decode: " + err.Error()}
	}

	desiredKeys := map[string]bool{}
	patch := make([]pdnsRRset, 0, len(desired))
	for _, rr := range desired {
		desiredKeys[rr.Name+"|"+rr.Type] = true
		rr.ChangeType = "REPLACE"
		patch = append(patch, rr)
	}
	removed := 0
	for _, rr := range current.RRsets {
		if rr.Type == "SOA" {
			continue // serial-managed, never deleted here
		}
		if !desiredKeys[rr.Name+"|"+rr.Type] {
			rr.ChangeType = "DELETE"
			rr.Records = nil
			patch = append(patch, rr)
			removed++
		}
	}

	patchBody := map[string]any{"rrsets": patch}
	if _, _, err := c.do(http.MethodPatch, "/zones/"+zone+".", patchBody); err != nil {
		return nil, nil, err
	}

	entry := r.deps.WAL.NewEntry("dns.apply_records", map[string]any{
		"zone": zone, "applied": len(patch) - removed, "removed": removed,
	})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{
		"status": "applied", "zone": zone,
		"applied": len(patch) - removed, "removed": removed,
	}, auditQueued(entry), nil
}

// dnsReload asks PowerDNS to re-read its backend data. With the SQL backend
// behind the HTTP API changes apply immediately, so a missing pdns_control is
// an honest skip — never an error (D-11).
func (r *Registry) dnsReload(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	bin := r.deps.PdnsControlBinary
	if bin == "" {
		if found, err := exec.LookPath("pdns_control"); err == nil {
			bin = found
		}
	}
	if bin == "" {
		return map[string]any{
			"status": "skipped",
			"detail": "pdns_control not found — with the HTTP API + SQL backend, zone changes apply immediately and no reload is required",
		}, nil, nil
	}
	out, err := exec.Command(bin, "reload").CombinedOutput()
	if err != nil {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: fmt.Sprintf("pdns_control reload failed: %s", strings.TrimSpace(string(out))),
		}
	}
	entry := r.deps.WAL.NewEntry("dns.reload", map[string]any{"status": "reloaded"})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{"status": "reloaded", "detail": strings.TrimSpace(string(out))}, auditQueued(entry), nil
}

// dnsEnableDNSSEC secures the zone with pdnsutil and returns the DS/DNSKEY
// material the registrar needs. Idempotent: securing an already-secured zone
// is reported as already_enabled with the live material.
func (r *Registry) dnsEnableDNSSEC(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone string `json:"zone"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	out, err := r.runPdnsutil("secure-zone", zone)
	if err != nil {
		return nil, nil, err
	}
	show, err := r.runPdnsutil("show-zone", zone)
	if err != nil {
		return nil, nil, err
	}
	enabled, ds, dnskey, keys := parseDnssecShow(show)
	if !enabled {
		return nil, nil, &rpc.RPCError{
			Code:    rpc.CodeInternalError,
			Message: "secure-zone ran but the zone does not present DNSSEC material: " + firstLine(out),
		}
	}
	entry := r.deps.WAL.NewEntry("dns.enable_dnssec", map[string]any{
		"zone": zone, "ds_count": len(ds), "key_count": len(keys),
	})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{
		"status": "enabled", "zone": zone,
		"ds": ds, "dnskey": dnskey, "keys": keys,
	}, auditQueued(entry), nil
}

// dnsDisableDNSSEC unsecures the zone (pdnsutil unsecure-zone).
func (r *Registry) dnsDisableDNSSEC(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone string `json:"zone"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	if _, err := r.runPdnsutil("unsecure-zone", zone); err != nil {
		return nil, nil, err
	}
	entry := r.deps.WAL.NewEntry("dns.disable_dnssec", map[string]any{"zone": zone})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{"status": "disabled", "zone": zone}, auditQueued(entry), nil
}

// dnsAXFRExport returns the zone in transfer (AXFR) format via the PowerDNS
// export endpoint. Read-only (§6).
func (r *Registry) dnsAXFRExport(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone string `json:"zone"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	c, err := r.pdns()
	if err != nil {
		return nil, nil, err
	}
	_, body, err := c.do(http.MethodGet, "/zones/"+zone+"/export", nil)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{"zone": zone, "content": string(body)}, nil, nil
}

// dnsZoneCheck runs pdnsutil check-zone and returns its findings verbatim.
// Read-only (§6). Issues are informational rows; ok=false means the check
// reported at least one error line.
func (r *Registry) dnsZoneCheck(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone string `json:"zone"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	out, rerr := r.runPdnsutil("check-zone", zone)
	issues := []string{}
	ok := true
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if strings.Contains(strings.ToLower(l), "error") {
			ok = false
		}
		issues = append(issues, l)
	}
	if rerr != nil {
		// pdnsutil itself failed (binary, connectivity) — surface verbatim.
		if re, isRPC := rerr.(*rpc.RPCError); isRPC && strings.Contains(re.Message, "pdnsutil check-zone failed: ") {
			return map[string]any{"zone": zone, "ok": false, "issues": []string{re.Message}}, nil, nil
		}
		return nil, nil, rerr
	}
	return map[string]any{"zone": zone, "ok": ok, "issues": issues}, nil, nil
}

// dnsGetDNSSEC reads the live DNSSEC state (ADR-0012 read-only amendment).
// Read-only (§6): safe while the control plane is unreachable.
func (r *Registry) dnsGetDNSSEC(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Zone string `json:"zone"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	zone, err := canonicalZone(p.Zone)
	if err != nil {
		return nil, nil, err
	}
	show, err := r.runPdnsutil("show-zone", zone)
	if err != nil {
		return nil, nil, err
	}
	enabled, ds, dnskey, keys := parseDnssecShow(show)
	return map[string]any{
		"zone": zone, "enabled": enabled,
		"ds": ds, "dnskey": dnskey, "keys": keys,
	}, nil, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
