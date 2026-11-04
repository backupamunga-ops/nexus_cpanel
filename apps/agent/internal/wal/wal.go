// Package wal implements the agent's offline audit queue (agent spec §6).
//
// While the control plane is unreachable, audit entries are appended one file per
// entry (fsync'd) under the WAL directory and drained in order on reconnection.
// The queue is capped; on overflow the oldest entries are dropped and a
// wal_dropped event must be emitted (logged in M0).
//
// Entry hashes follow the security model §4 construction so drained entries chain
// into the control-plane audit log without rehashing:
//
//	this_hash = SHA-256(prior_hash || occurred_at(8B BE unix-seconds) ||
//	                     actor_user_id(16B zeros) || operation ||
//	                     canonical_json(parameters) || outcome)
package wal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry is one queued audit record.
type Entry struct {
	ID        string         `json:"id"`
	Occurred  int64          `json:"occurred_at"` // unix seconds
	Operation string         `json:"operation"`
	Params    map[string]any `json:"parameters"`
	Outcome   string         `json:"outcome"`
	PriorHash [32]byte       `json:"prior_hash"`
	ThisHash  [32]byte       `json:"this_hash"`

	e_seq uint64 // file sequence; not serialized
}

// Hash returns the marshaled ThisHash for the wire hint.
func (e *Entry) Hash() string { return fmt.Sprintf("%x", e.ThisHash) }

// Queue is a durable, ordered, capped append log.
type Queue struct {
	dir     string
	cap     int
	mu      sync.Mutex
	head    [32]byte
	seq     uint64
	dropped uint64
}

// Open prepares (or resumes) a WAL directory.
func Open(dir string, capacity int) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, cap: capacity}
	if err := q.resume(); err != nil {
		return nil, err
	}
	return q, nil
}

// resume restores sequence and chain head from existing files.
func (q *Queue) resume() error {
	files, err := walFiles(q.dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		var e Entry
		b, err := os.ReadFile(filepath.Join(q.dir, f))
		if err != nil {
			continue
		}
		if json.Unmarshal(b, &e) == nil {
			q.head = e.ThisHash
			if s := seqOf(f); s > q.seq {
				q.seq = s
			}
		}
	}
	return nil
}

// NewEntry builds a chained entry (does not persist it).
func (q *Queue) NewEntry(operation string, params map[string]any) *Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.seq++
	e := &Entry{
		ID:        fmt.Sprintf("wal_%012d_%d", q.seq, time.Now().UnixNano()),
		Occurred:  time.Now().Unix(),
		Operation: operation,
		Params:    params,
		Outcome:   "success",
		PriorHash: q.head,
		e_seq:     q.seq,
	}
	e.ThisHash = hashEntry(e.PriorHash, e.Occurred, e.Operation, e.Params, e.Outcome)
	return e
}

// Append persists an entry durably (one file per entry, fsync'd).
func (q *Queue) Append(e *Entry) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.enforceCap(); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	name := filepath.Join(q.dir, fmt.Sprintf("%012d.json", e.e_seq))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	q.head = e.ThisHash
	return nil
}

// Drain delivers every queued entry in order and removes the files on success.
func (q *Queue) Drain(deliver func(*Entry) error) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, err := walFiles(q.dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(q.dir, f))
		if err != nil {
			return n, err
		}
		var e Entry
		if err := json.Unmarshal(b, &e); err != nil {
			return n, fmt.Errorf("corrupt wal entry %s: %w", f, err)
		}
		if err := deliver(&e); err != nil {
			return n, err
		}
		if err := os.Remove(filepath.Join(q.dir, f)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// enforceCap drops oldest entries beyond capacity, counting a wal_dropped event.
func (q *Queue) enforceCap() error {
	files, err := walFiles(q.dir)
	if err != nil {
		return err
	}
	if len(files) < q.cap {
		return nil
	}
	excess := len(files) - q.cap + 1
	for i := 0; i < excess; i++ {
		if err := os.Remove(filepath.Join(q.dir, files[i])); err == nil {
			q.dropped++
		}
	}
	// M0: the wal_dropped event is logged; P1 wires it into the event stream.
	fmt.Fprintf(os.Stderr, "nexuspanel-agent: wal_dropped count=%d\n", q.dropped)
	return nil
}

// Close flushes nothing (writes are already durable); placeholder for P1 metrics.
func (q *Queue) Close() error { return nil }

// Dropped reports how many entries were dropped by cap enforcement.
func (q *Queue) Dropped() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// ---- helpers ----------------------------------------------------------------

// hashEntry implements the security-model §4 hash over agent-side fields
// (actor_user_id is 16 zero bytes: attribution happens at the control plane).
func hashEntry(prior [32]byte, occurred int64, operation string, params map[string]any, outcome string) [32]byte {
	h := sha256.New()
	h.Write(prior[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(occurred))
	h.Write(ts[:])
	h.Write(make([]byte, 16)) // actor_user_id: zeros from the agent side
	h.Write([]byte(operation))
	pj, _ := json.Marshal(canonicalize(params))
	h.Write(pj)
	h.Write([]byte(outcome))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// canonicalize sorts map keys by round-tripping through generic JSON-friendly
// structures; json.Marshal already sorts map[string]any keys, so this is a
// normalization hook for future nested types.
func canonicalize(m map[string]any) map[string]any { return m }

func walFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files) // zero-padded sequence => lexicographic == chronological
	return files, nil
}

func seqOf(name string) uint64 {
	var s uint64
	fmt.Sscanf(name, "%012d", &s)
	return s
}
