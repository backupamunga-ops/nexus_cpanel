package commands

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "os"
        "path/filepath"
        "strings"
        "testing"

        "github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// dns.* tests (agent spec §4.9, ADR-0012). PowerDNS is faked with an
// httptest server speaking the subset of the API the agent uses (zone
// create/get/delete/patch/export); pdnsutil is a fake shell script whose
// output covers the secure/not-secured show-zone shapes.

// fakePdns is an in-test PowerDNS: a map of zone → rrsets plus per-zone
// export text. Failure injection lets tests prove error surfacing.
type fakePdns struct {
        t       *testing.T
        mu      *counting // request counter (nil = don't count)
        zones   map[string][]pdnsRRset
        exports map[string]string
        failDel map[string]int // zone → status to return on DELETE
}

type counting struct{ n int }

func newFakePdns(t *testing.T, zones map[string][]pdnsRRset) (*httptest.Server, *fakePdns) {
        t.Helper()
        f := &fakePdns{
                t:       t,
                zones:   zones,
                exports: map[string]string{},
                failDel: map[string]int{},
        }
        mux := http.NewServeMux()
        mux.HandleFunc("/api/v1/servers/localhost/zones", func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodPost {
                        w.WriteHeader(http.StatusMethodNotAllowed)
                        return
                }
                var body struct {
                        Name   string      `json:"name"`
                        Kind   string      `json:"kind"`
                        RRsets []pdnsRRset `json:"rrsets"`
                }
                if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                        w.WriteHeader(http.StatusBadRequest)
                        return
                }
                name := strings.TrimSuffix(body.Name, ".")
                if _, exists := f.zones[name]; exists {
                        w.WriteHeader(http.StatusUnprocessableEntity)
                        _, _ = w.Write([]byte(`{"error": "Duplicate zone"}`))
                        return
                }
                f.zones[name] = body.RRsets
                w.WriteHeader(http.StatusCreated)
        })
        mux.HandleFunc("/api/v1/servers/localhost/zones/", func(w http.ResponseWriter, r *http.Request) {
                rest := strings.TrimPrefix(r.URL.Path, "/api/v1/servers/localhost/zones/")
                switch {
                case strings.HasSuffix(rest, "/export"):
                        zone := strings.TrimSuffix(rest, "/export")
                        zone = strings.TrimSuffix(zone, ".")
                        txt, ok := f.exports[zone]
                        if !ok {
                                w.WriteHeader(http.StatusNotFound)
                                return
                        }
                        _, _ = w.Write([]byte(txt))
                default:
                        zone := strings.TrimSuffix(rest, ".")
                        if r.Method == http.MethodGet {
                                rrsets, ok := f.zones[zone]
                                if !ok {
                                        w.WriteHeader(http.StatusNotFound)
                                        _, _ = w.Write([]byte(`{"error": "Could not find domain '"` + zone + `"'`))
                                        return
                                }
                                _ = json.NewEncoder(w).Encode(map[string]any{"rrsets": rrsets})
                                return
                        }
                        if r.Method == http.MethodDelete {
                                if code := f.failDel[zone]; code != 0 {
                                        w.WriteHeader(code)
                                        return
                                }
                                if _, ok := f.zones[zone]; !ok {
                                        w.WriteHeader(http.StatusNotFound)
                                        return
                                }
                                delete(f.zones, zone)
                                w.WriteHeader(http.StatusNoContent)
                                return
                        }
                        if r.Method == http.MethodPatch {
                                _, ok := f.zones[zone]
                                if !ok {
                                        w.WriteHeader(http.StatusNotFound)
                                        return
                                }
                                var body struct {
                                        RRsets []pdnsRRset `json:"rrsets"`
                                }
                                if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                                        w.WriteHeader(http.StatusBadRequest)
                                        return
                                }
                                for _, rr := range body.RRsets {
                                        f.applyPatch(zone, rr)
                                }
                                w.WriteHeader(http.StatusNoContent)
                                return
                        }
                        w.WriteHeader(http.StatusMethodNotAllowed)
                }
        })
        srv := httptest.NewServer(mux)
        t.Cleanup(srv.Close)
        return srv, f
}

func (f *fakePdns) applyPatch(zone string, rr pdnsRRset) {
        cur := f.zones[zone]
        // Remove the (name,type) group first.
        kept := cur[:0]
        for _, have := range cur {
                if have.Name == rr.Name && have.Type == rr.Type {
                        continue
                }
                kept = append(kept, have)
        }
        cur = kept
        if rr.ChangeType == "REPLACE" {
                cur = append(cur, rr)
        }
        f.zones[zone] = cur
}

func newDnsRegistry(t *testing.T, srv *httptest.Server, pdnsutilScript string) *Registry {
        t.Helper()
        binDir := t.TempDir()
        var utilBin string
        if pdnsutilScript != "" {
                utilBin = filepath.Join(binDir, "pdnsutil")
                if err := os.WriteFile(utilBin, []byte(pdnsutilScript), 0o755); err != nil {
                        t.Fatal(err)
                }
        }
        return NewRegistry(Deps{
                WAL:            newTestWAL(t),
                HomeRoot:       t.TempDir(),
                VhostRoot:      t.TempDir(),
                PdnsAPIURL:     srv.URL + "/api/v1",
                PdnsAPIKey:     "test-key",
                PdnsServerID:   "localhost",
                PdnsHTTP:       srv.Client(),
                PdnsutilBinary: utilBin,
        })
}

func dnsCreateParams(t *testing.T, zone string, records []map[string]any) json.RawMessage {
        t.Helper()
        return rawParams(t, map[string]any{"zone": zone, "records": records})
}

func TestDnsCreateZoneSeedsSOA(t *testing.T) {
        srv, fake := newFakePdns(t, map[string][]pdnsRRset{})
        r := newDnsRegistry(t, srv, "")

        res, hint, err := r.dnsCreateZone("id", dnsCreateParams(t, "Example.COM.", []map[string]any{
                {"name": "www", "type": "A", "content": "192.0.2.10", "ttl": 3600},
        }))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(map[string]any)
        if out["status"] != "created" || out["zone"] != "example.com" {
                t.Fatalf("unexpected result: %v", out)
        }
        if out["record_count"] != 2 { // A + seeded SOA
                t.Fatalf("unexpected record_count: %v", out)
        }
        if out["soa_seeded"] != true {
                t.Fatalf("expected soa_seeded=true, got %v", out)
        }
        if hint == nil || hint.EntryID == "" {
                t.Fatalf("expected WAL audit hint")
        }
        rrsets := fake.zones["example.com"]
        var soa, www *pdnsRRset
        for i := range rrsets {
                if rrsets[i].Type == "SOA" {
                        soa = &rrsets[i]
                }
                if rrsets[i].Type == "A" {
                        www = &rrsets[i]
                }
        }
        if soa == nil {
                t.Fatal("SOA was not seeded")
        }
        if !strings.HasPrefix(soa.Records[0].Content, "example.com. hostmaster.example.com. ") {
                t.Fatalf("unexpected SOA content: %s", soa.Records[0].Content)
        }
        if www == nil || www.Name != "www.example.com." || www.Records[0].Content != "192.0.2.10" {
                t.Fatalf("unexpected A rrset: %+v", www)
        }
}

func TestDnsCreateZoneConflictAndValidation(t *testing.T) {
        srv, _ := newFakePdns(t, map[string][]pdnsRRset{
                "taken.example": {{Name: "taken.example.", Type: "SOA", TTL: 3600}},
        })
        r := newDnsRegistry(t, srv, "")

        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "taken.example", nil)); err == nil {
                t.Fatal("expected conflict on existing zone")
        }
        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "not_a_zone", nil)); err == nil {
                t.Fatal("expected invalid single-label zone")
        }
        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "ok.example", []map[string]any{
                {"name": "www", "type": "A", "content": "not-an-ip"},
        })); err == nil {
                t.Fatal("expected invalid A content rejection")
        }
        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "ok.example", []map[string]any{
                {"name": "@", "type": "CNAME", "content": "elsewhere.example"},
        })); err == nil {
                t.Fatal("expected apex CNAME rejection")
        }
        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "ok.example", []map[string]any{
                {"name": "x", "type": "MX", "content": "mail.example"},
        })); err == nil {
                t.Fatal("expected MX without priority rejection")
        }
        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "ok.example", []map[string]any{
                {"name": "x", "type": "SRV", "content": "_sip._tcp", "priority": 10, "weight": 20},
        })); err == nil {
                t.Fatal("expected SRV without port rejection")
        }
        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "ok.example", []map[string]any{
                {"name": "x", "type": "TXT", "content": "line1\nline2"},
        })); err == nil {
                t.Fatal("expected multi-line TXT rejection")
        }
        if _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "ok.example", []map[string]any{
                {"name": "escape", "type": "A", "content": "192.0.2.1", "ttl": 1},
        })); err == nil {
                t.Fatal("expected low TTL rejection")
        }
}

func TestDnsApplyRecordsFullReplace(t *testing.T) {
        srv, fake := newFakePdns(t, map[string][]pdnsRRset{
                "example.com": {
                        {Name: "example.com.", Type: "SOA", TTL: 3600, Records: []pdnsRecord{{Content: "example.com. hostmaster.example.com. 1 1 1 1 1"}}},
                        {Name: "old.example.com.", Type: "A", TTL: 3600, Records: []pdnsRecord{{Content: "192.0.2.99"}}},
                        {Name: "keep.example.com.", Type: "TXT", TTL: 300, Records: []pdnsRecord{{Content: `"keep"`}}},
                },
        })
        r := newDnsRegistry(t, srv, "")

        res, _, err := r.dnsApplyRecords("id", dnsCreateParams(t, "example.com", []map[string]any{
                {"name": "@", "type": "A", "content": "192.0.2.1"},
                {"name": "www", "type": "A", "content": "192.0.2.2"},
                {"name": "keep", "type": "TXT", "content": "keep", "ttl": 300},
        }))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(map[string]any)
        if out["applied"] != 3 || out["removed"] != 1 {
                t.Fatalf("unexpected diff counts: %v", out)
        }
        rrsets := fake.zones["example.com"]
        names := map[string]bool{}
        for _, rr := range rrsets {
                names[rr.Name+"|"+rr.Type] = true
        }
        if names["old.example.com.|A"] {
                t.Fatal("old.example.com A should have been deleted")
        }
        if !names["example.com.|SOA"] {
                t.Fatal("SOA must survive apply_records")
        }
        // SOA attempt is rejected before any API call.
        if _, _, err := r.dnsApplyRecords("id", dnsCreateParams(t, "example.com", []map[string]any{
                {"name": "@", "type": "SOA", "content": "evil"},
        })); err == nil {
                t.Fatal("expected SOA rejection")
        }
}

func TestDnsDeleteZoneAbsentIsSuccess(t *testing.T) {
        srv, fake := newFakePdns(t, map[string][]pdnsRRset{
                "gone.example": nil,
        })
        r := newDnsRegistry(t, srv, "")

        res, _, err := r.dnsDeleteZone("id", rawParams(t, map[string]any{"zone": "gone.example"}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(map[string]any)["status"] != "removed" {
                t.Fatalf("expected removed, got %v", res)
        }
        if len(fake.zones) != 0 {
                t.Fatal("zone was not deleted from PowerDNS")
        }

        res, _, err = r.dnsDeleteZone("id", rawParams(t, map[string]any{"zone": "never.example"}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(map[string]any)["status"] != "absent" {
                t.Fatalf("expected absent, got %v", res)
        }
}

func TestDnsPDNSErrorSurfacesVerbatim(t *testing.T) {
        srv, fake := newFakePdns(t, map[string][]pdnsRRset{"bad.example": nil})
        fake.failDel["bad.example"] = http.StatusUnprocessableEntity
        r := newDnsRegistry(t, srv, "")

        _, _, err := r.dnsDeleteZone("id", rawParams(t, map[string]any{"zone": "bad.example"}))
        if err == nil {
                t.Fatal("expected error from PowerDNS failure")
        }
        re, ok := err.(*rpc.RPCError)
        if !ok || re.Code != rpc.CodePrecondition {
                t.Fatalf("expected precondition RPCError, got %v", err)
        }
        if !strings.Contains(re.Message, "422") {
                t.Fatalf("error should carry the API status, got: %s", re.Message)
        }
}

func TestDnsAXFRExportAndZoneCheck(t *testing.T) {
        srv, fake := newFakePdns(t, map[string][]pdnsRRset{"example.com": nil})
        fake.exports["example.com"] = "example.com.\t3600\tIN\tSOA\tns1.example.com. hostmaster.example.com. 1 1 1 1 1\n"
        r := newDnsRegistry(t, srv, "")

        res, _, err := r.dnsAXFRExport("id", rawParams(t, map[string]any{"zone": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        if !strings.Contains(res.(map[string]any)["content"].(string), "IN\tSOA") {
                t.Fatalf("unexpected export: %v", res)
        }

        // zone_check with a fake pdnsutil that reports a clean zone.
        util := "#!/bin/sh\necho 'Checked 3 records of '\"$2\"', 0 problems, 0 warnings.'\n"
        r2 := newDnsRegistry(t, srv, util)
        out, _, err := r2.dnsZoneCheck("id", rawParams(t, map[string]any{"zone": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        resMap := out.(map[string]any)
        if resMap["ok"] != true {
                t.Fatalf("expected ok=true, got %v", resMap)
        }

        // A check that reports errors must flip ok and keep the line verbatim.
        utilErr := "#!/bin/sh\necho '[Error] unknown record type in file'\n"
        r3 := newDnsRegistry(t, srv, utilErr)
        out, _, err = r3.dnsZoneCheck("id", rawParams(t, map[string]any{"zone": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        if out.(map[string]any)["ok"] != false {
                t.Fatalf("expected ok=false, got %v", out)
        }
}

const pdnsShowSecured = `This is a Native level zone.
Also available in DNSSEC format:
DS = example.com. IN DS 1234 8 2 abcdef0123456789 ; (SHA256 digest)
DNSKEY = example.com. IN DNSKEY 257 3 8 AwEAAfakeksk ; (ksk)
DNSKEY = example.com. IN DNSKEY 256 3 8 AwEAAfakezsk ; (zsk)
KSK dot example.com.: id = 1 (KSK), tag = 1234, algo = 8, bits = 2048  Active: 1 ( yes )
ZSK dot example.com.: id = 2 (ZSK), tag = 5678, algo = 8, bits = 1024  Active: 1 ( yes )
`

const pdnsShowPlain = `This is a Native level zone.
Zone is not actively setup for DNSSEC
`

func TestDnsEnableDisableDNSSEC(t *testing.T) {
        srv, _ := newFakePdns(t, map[string][]pdnsRRset{"example.com": nil})
        util := "#!/bin/sh\ncase \"$1\" in\n  secure-zone) ;;\n  unsecure-zone) ;;\n  show-zone) cat <<'ZONEEOF'\n" + pdnsShowSecured + "ZONEEOF\n;;\nesac\n"
        r := newDnsRegistry(t, srv, util)

        res, _, err := r.dnsEnableDNSSEC("id", rawParams(t, map[string]any{"zone": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(map[string]any)
        if out["status"] != "enabled" {
                t.Fatalf("unexpected status: %v", out)
        }
        ds := out["ds"].([]string)
        if len(ds) != 1 || !strings.Contains(ds[0], "1234 8 2") {
                t.Fatalf("unexpected DS parse: %v", ds)
        }
        if len(out["dnskey"].([]string)) != 2 {
                t.Fatalf("expected 2 DNSKEYs, got %v", out["dnskey"])
        }
        if len(out["keys"].([]map[string]any)) != 2 {
                t.Fatalf("expected 2 key rows, got %v", out["keys"])
        }

        utilPlain := "#!/bin/sh\ncase \"$1\" in\n  secure-zone) exit 0 ;;\n  show-zone) cat <<'ZONEEOF'\n" + pdnsShowPlain + "ZONEEOF\n;;\nesac\n"
        r2 := newDnsRegistry(t, srv, utilPlain)
        // secure-zone "succeeds" but the zone shows no material → loud failure.
        if _, _, err := r2.dnsEnableDNSSEC("id", rawParams(t, map[string]any{"zone": "example.com"})); err == nil {
                t.Fatal("expected loud failure when no DNSSEC material appears")
        }

        utilUnsecure := "#!/bin/sh\ncase \"$1\" in\n  unsecure-zone) exit 0 ;;\n  show-zone) echo 'nope' ;;\nesac\n"
        r3 := newDnsRegistry(t, srv, utilUnsecure)
        res, _, err = r3.dnsDisableDNSSEC("id", rawParams(t, map[string]any{"zone": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(map[string]any)["status"] != "disabled" {
                t.Fatalf("unexpected status: %v", res)
        }
}

func TestDnsGetDNSSECReadsLiveState(t *testing.T) {
        srv, _ := newFakePdns(t, map[string][]pdnsRRset{"example.com": nil})
        util := "#!/bin/sh\ncase \"$1\" in\n  show-zone) cat <<'ZONEEOF'\n" + pdnsShowSecured + "ZONEEOF\n;;\nesac\n"
        r := newDnsRegistry(t, srv, util)

        res, hint, err := r.dnsGetDNSSEC("id", rawParams(t, map[string]any{"zone": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        out := res.(map[string]any)
        if out["enabled"] != true {
                t.Fatalf("expected enabled=true, got %v", out)
        }
        if hint != nil {
                t.Fatal("read-only method must not produce an audit hint")
        }

        utilPlain := "#!/bin/sh\ncat <<'ZONEEOF'\n" + pdnsShowPlain + "ZONEEOF\n"
        r2 := newDnsRegistry(t, srv, utilPlain)
        res, _, err = r2.dnsGetDNSSEC("id", rawParams(t, map[string]any{"zone": "example.com"}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(map[string]any)["enabled"] != false {
                t.Fatalf("expected enabled=false, got %v", res)
        }
}

func TestDnsMissingConfigurationFailsLoudly(t *testing.T) {
        // No PdnsAPIKey and no injected client → precondition, before any I/O.
        r := NewRegistry(Deps{WAL: newTestWAL(t)})
        _, _, err := r.dnsCreateZone("id", dnsCreateParams(t, "example.com", nil))
        if err == nil {
                t.Fatal("expected precondition without PowerDNS config")
        }
        re, ok := err.(*rpc.RPCError)
        if !ok || re.Code != rpc.CodePrecondition {
                t.Fatalf("expected precondition, got %v", err)
        }
        if !strings.Contains(re.Message, "PowerDNS API not configured") {
                t.Fatalf("unexpected message: %s", re.Message)
        }

        // pdnsutil missing → precondition for DNSSEC reads.
        srv, _ := newFakePdns(t, map[string][]pdnsRRset{})
        r2 := newDnsRegistry(t, srv, "")
        if _, _, err := r2.dnsGetDNSSEC("id", rawParams(t, map[string]any{"zone": "example.com"})); err == nil {
                t.Fatal("expected precondition without pdnsutil")
        }
}

func TestDnsReloadHonestSkip(t *testing.T) {
        srv, _ := newFakePdns(t, map[string][]pdnsRRset{})
        // Registry without pdns_control on PATH (PATH is stripped in CI) → honest skip.
        r := newDnsRegistry(t, srv, "")
        t.Setenv("PATH", t.TempDir()) // no pdns_control anywhere
        res, _, err := r.dnsReload("id", rawParams(t, map[string]any{}))
        if err != nil {
                t.Fatal(err)
        }
        if res.(map[string]any)["status"] != "skipped" {
                t.Fatalf("expected honest skip, got %v", res)
        }
}

func TestCanonicalRecordName(t *testing.T) {
        cases := []struct {
                in, zone, want string
        }{
                {"@", "example.com", "example.com"},
                {"www", "example.com", "www.example.com"},
                {"www.example.com", "example.com", "www.example.com"},
                {"www.example.com.", "example.com", "www.example.com"},
                {"a.b", "example.com", "a.b.example.com"},
                {"*.sub", "example.com", "*.sub.example.com"},
                {"example.com", "example.com", "example.com"},
        }
        for _, c := range cases {
                got, err := canonicalRecordName(c.in, c.zone)
                if err != nil {
                        t.Fatalf("%q: unexpected error %v", c.in, err)
                }
                if got != c.want {
                        t.Fatalf("%q → %q, want %q", c.in, got, c.want)
                }
        }
        // Absolute (trailing dot) names outside the zone are rejected.
        for _, bad := range []string{"other.org.", "www.other.org.", "-bad.example.com.", "ex example.com", "bad_.example.com"} {
                if _, err := canonicalRecordName(bad, "example.com"); err == nil {
                        t.Fatalf("%q should be rejected", bad)
                }
        }
        // "*" is only legal as the leftmost label.
        if _, err := canonicalRecordName("sub.*", "example.com"); err == nil {
                t.Fatal("mid-name wildcard should be rejected")
        }
}
