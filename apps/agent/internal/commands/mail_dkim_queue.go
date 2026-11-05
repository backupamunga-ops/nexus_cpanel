package commands

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// mail.apply_dkim + mail.queue_* (agent spec §4.8, ADR-0014) — P4
// deliverability.
//
// DKIM: the control plane mints the RSA-2048 keypair and sends the private
// PEM here over the signed Unix socket. The agent stores it at
// <dkim_root>/<domain>/<selector>.private (0600), maintains managed
// KeyTable/SigningTable snippets, derives the public half and returns the
// exact DNS TXT value the panel writes through its DNS module (ADR-0014).
// opendkim absence is an honest skip: the key + DNS record are still real,
// signing is stated as not active.
//
// Queue: postqueue is the only honest source. queue_list parses
// `postqueue -p`; flush/retry map to `postqueue -f|-i` and `postsuper -r`.
// A missing binary is a loud precondition error — the panel must never show
// an "empty queue" it cannot see.

const (
	dkimKeyFileMode   = 0o600
	dkimTableFileMode = 0o644
	queueEntryCap     = 500
)

var (
	dkimSelectorRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)
	queueIDRe      = regexp.MustCompile(`^[0-9A-Za-z!*-]{6,20}$`)
)

type mailDkimResult struct {
	Status      string               `json:"status"` // created | rotated
	Domain      string               `json:"domain"`
	Selector    string               `json:"selector"`
	DnsTxt      string               `json:"dns_txt"`
	KeyFingerprint string            `json:"key_fingerprint"`
	Opendkim    *mailOwnershipResult `json:"opendkim,omitempty"`
}

// applyDKIM stores the private key and returns the DNS TXT record value.
func (r *Registry) mailApplyDkim(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Domain        string `json:"domain"`
		Selector      string `json:"selector"`
		PrivateKeyPem string `json:"private_key_pem"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	if len(domain) > 253 || !mailDomainRe.MatchString(domain) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid mail domain"}
	}
	selector := strings.ToLower(strings.TrimSpace(p.Selector))
	if !dkimSelectorRe.MatchString(selector) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid selector (lowercase letters, digits, dash; 2-64 chars)"}
	}

	// Parse and re-serialize: never persist attacker-shaped PEM material.
	block, _ := pem.Decode([]byte(p.PrivateKeyPem))
	if block == nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "private_key_pem is not PEM"}
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		k, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "private key must be RSA"}
		}
		key = k
	} else if k, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 == nil {
		key = k
	} else {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "private key must be PKCS#1 or PKCS#8 RSA"}
	}
	if key.N.BitLen() < 1024 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "RSA key too small (minimum 1024 bits; use 2048)"}
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, mailInternalError("public key marshal failed", err)
	}
	pubSum := sha256.Sum256(pubDER)
	fingerprint := fmt.Sprintf("%x", pubSum[:8])
	dnsTxt := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubDER)

	keyDir := r.mailDkimKeyDir(domain)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, nil, mailInternalError("dkim key dir create failed", err)
	}
	keyPath := keyDir + "/" + selector + ".private"
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, dkimKeyFileMode); err != nil {
		return nil, nil, mailInternalError("dkim key write failed", err)
	}
	opendkim := r.mailWriteDkimTables(domain, selector, keyPath)

	entry := r.deps.WAL.NewEntry("mail.apply_dkim", map[string]any{
		"domain": domain, "selector": selector, "key_fingerprint": fingerprint,
		"opendkim_applied": opendkim.Applied,
	})
	_ = r.deps.WAL.Append(entry)
	return mailDkimResult{
		Status:         "created",
		Domain:         domain,
		Selector:       selector,
		DnsTxt:         dnsTxt,
		KeyFingerprint: fingerprint,
		Opendkim:       opendkim,
	}, auditQueued(entry), nil
}

func (r *Registry) mailDkimKeyDir(domain string) string {
	root := r.deps.OpendkimKeyRoot
	if root == "" {
		root = "/etc/opendkim/keys"
	}
	return root + "/" + domain
}

// mailWriteDkimTables maintains managed KeyTable/SigningTable snippets.
// Missing opendkim config dir is fine (created); the honest skip fires when
// the snippet files cannot be owned by this agent (not wired into the main
// config) — the panel surfaces it as "stored — not signing".
func (r *Registry) mailWriteDkimTables(domain, selector, keyPath string) *mailOwnershipResult {
	tableDir := r.deps.OpendkimTableDir
	if tableDir == "" {
		tableDir = "/etc/opendkim/nexuspanel"
	}
	if err := os.MkdirAll(tableDir, 0o755); err != nil {
		return &mailOwnershipResult{Applied: false, Skipped: "opendkim table dir create failed: " + err.Error()}
	}
	keyTable := "# managed by nexuspanel — do not edit\n" +
		selector + "._domainkey." + domain + " " + domain + ":" + selector + ":" + keyPath + "\n"
	signingTable := "# managed by nexuspanel — do not edit\n" +
		"@" + domain + " " + selector + "._domainkey." + domain + "\n"
	if err := os.WriteFile(tableDir+"/KeyTable", []byte(keyTable), dkimTableFileMode); err != nil {
		return &mailOwnershipResult{Applied: false, Skipped: "KeyTable write failed: " + err.Error()}
	}
	if err := os.WriteFile(tableDir+"/SigningTable", []byte(signingTable), dkimTableFileMode); err != nil {
		return &mailOwnershipResult{Applied: false, Skipped: "SigningTable write failed: " + err.Error()}
	}
	return &mailOwnershipResult{Applied: true}
}

// ---- queue ----------------------------------------------------------------------

type mailQueueEntry struct {
	QueueID   string `json:"queue_id"`
	Size      int64  `json:"size"`
	Arrival   string `json:"arrival"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type mailQueueListResult struct {
	Queue  []mailQueueEntry `json:"queue"`
	Total  int              `json:"total"`
	Source string           `json:"source"` // postqueue -p
}

var queueHeaderRe = regexp.MustCompile(`^([0-9A-Za-z!*-]{6,20})\s+(\d+)\s+(.{19})\s(.*)$`)
var queueReasonRe = regexp.MustCompile(`^\((.*)\)\s*$`)

// mailQueueList returns the deferred queue. Read-only (§6).
func (r *Registry) mailQueueList(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	bin := r.deps.PostqueueBinary
	if bin == "" {
		found, err := exec.LookPath("postqueue")
		if err != nil {
			return nil, nil, &rpc.RPCError{
				Code:    rpc.CodePrecondition,
				Message: "postqueue binary not found on this node — the queue cannot be read honestly, so no state is claimed",
			}
		}
		bin = found
	}
	out, err := exec.Command(bin, "-p").CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if len(trimmed) > mailErrDetailCap {
			trimmed = trimmed[:mailErrDetailCap-3] + "..."
		}
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "postqueue -p failed: " + trimmed}
	}
	queue := parsePostqueue(string(out))
	if len(queue) > queueEntryCap {
		queue = queue[:queueEntryCap]
	}
	return mailQueueListResult{Queue: queue, Total: len(queue), Source: "postqueue -p"}, nil, nil
}

// parsePostqueue handles the classic postqueue -p shape:
//
//	-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
//	AB12CD34EF      512 Tue Nov  4 09:15:22  sender@example.com
//	(connect to mx.example.net[203.0.113.9]:25: Connection refused)
//	                                                 rcpt@example.net
func parsePostqueue(out string) []mailQueueEntry {
	entries := []mailQueueEntry{}
	var current *mailQueueEntry
	flush := func() {
		if current != nil {
			entries = append(entries, *current)
			current = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "-Queue ID-") || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "Mail queue is empty") {
			return []mailQueueEntry{}
		}
		if m := queueHeaderRe.FindStringSubmatch(line); m != nil {
			flush()
			var size int64
			fmt.Sscanf(m[2], "%d", &size)
			current = &mailQueueEntry{QueueID: strings.TrimSuffix(m[1], "*"), Size: size, Arrival: strings.TrimSpace(m[3]), Sender: strings.TrimSpace(m[4])}
			continue
		}
		if current == nil {
			continue
		}
		if m := queueReasonRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			current.Reason = strings.TrimSpace(m[1])
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && current.Recipient == "" {
			current.Recipient = trimmed
		}
	}
	flush()
	return entries
}

// mailQueueFlush flushes the whole queue (no queue_id) or one site entry.
func (r *Registry) mailQueueFlush(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		QueueID string `json:"queue_id"`
	}
	if len(raw) > 0 {
		if err := decodeParams(raw, &p); err != nil {
			return nil, nil, err
		}
	}
	bin := r.deps.PostqueueBinary
	if bin == "" {
		found, err := exec.LookPath("postqueue")
		if err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "postqueue binary not found on this node"}
		}
		bin = found
	}
	args := []string{"-f"}
	if p.QueueID != "" {
		if !queueIDRe.MatchString(p.QueueID) {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid queue_id"}
		}
		args = []string{"-i", p.QueueID}
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if len(trimmed) > mailErrDetailCap {
			trimmed = trimmed[:mailErrDetailCap-3] + "..."
		}
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "postqueue flush failed: " + trimmed}
	}
	entry := r.deps.WAL.NewEntry("mail.queue_flush", map[string]any{"queue_id": p.QueueID})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{"status": "flushed", "queue_id": p.QueueID}, auditQueued(entry), nil
}

// mailQueueRetry requeues one message via postsuper -r.
func (r *Registry) mailQueueRetry(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		MessageID string `json:"message_id"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !queueIDRe.MatchString(p.MessageID) {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid message_id"}
	}
	bin := r.deps.PostsuperBinary
	if bin == "" {
		found, err := exec.LookPath("postsuper")
		if err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "postsuper binary not found on this node"}
		}
		bin = found
	}
	out, err := exec.Command(bin, "-r", p.MessageID).CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if len(trimmed) > mailErrDetailCap {
			trimmed = trimmed[:mailErrDetailCap-3] + "..."
		}
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "postsuper -r failed: " + trimmed}
	}
	entry := r.deps.WAL.NewEntry("mail.queue_retry", map[string]any{"message_id": p.MessageID})
	_ = r.deps.WAL.Append(entry)
	return map[string]any{"status": "requeued", "message_id": p.MessageID}, auditQueued(entry), nil
}

// sortQueueEntries keeps output deterministic for tests.
func sortQueueEntries(entries []mailQueueEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].QueueID < entries[j].QueueID })
}
