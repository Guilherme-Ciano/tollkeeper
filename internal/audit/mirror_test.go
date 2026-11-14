package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errInjected = errors.New("injected mirror failure")

type memMirror struct {
	mu            sync.Mutex
	rows          []Row
	failPrepare   atomic.Bool
	failCommit    atomic.Bool
	reportLastSeq atomic.Int64
}

type memPending struct {
	m    *memMirror
	rows []Row
}

func (p *memPending) Commit(context.Context) error {
	if p.m.failCommit.Load() {
		return errInjected
	}
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	for _, r := range p.rows {
		want := ZeroHash
		if n := len(p.m.rows); n > 0 {
			if p.m.rows[n-1].Seq != r.Seq-1 {
				return fmt.Errorf("non contiguous seq %d after %d", r.Seq, p.m.rows[n-1].Seq)
			}
			want = p.m.rows[n-1].Hash
		}
		if r.Prev != want {
			return fmt.Errorf("row %d does not link", r.Seq)
		}
		got, err := ChainHash(r.Prev, r.Raw)
		if err != nil || got != r.Hash {
			return fmt.Errorf("row %d hash mismatch", r.Seq)
		}
		p.m.rows = append(p.m.rows, r)
	}
	return nil
}

func (p *memPending) Abort(context.Context) {}

func (m *memMirror) Prepare(_ context.Context, rows []Row) (Pending, error) {
	if m.failPrepare.Load() {
		return nil, errInjected
	}
	return &memPending{m: m, rows: append([]Row(nil), rows...)}, nil
}

func (m *memMirror) LastSeq(context.Context, string) (uint64, error) {
	if v := m.reportLastSeq.Load(); v > 0 {
		return uint64(v), nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rows) == 0 {
		return 0, nil
	}
	return m.rows[len(m.rows)-1].Seq, nil
}

func (m *memMirror) snapshot() []Row {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Row(nil), m.rows...)
}

func fileRecords(t *testing.T, path string) []Record {
	t.Helper()
	var out []Record
	for _, line := range lines(t, path) {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func assertSameChain(t *testing.T, path string, m *memMirror) {
	t.Helper()
	recs := fileRecords(t, path)
	rows := m.snapshot()
	if len(recs) != len(rows) {
		t.Fatalf("file has %d records, mirror has %d", len(recs), len(rows))
	}
	for i := range recs {
		if recs[i].Hash != rows[i].Hash || string(recs[i].Body) != string(rows[i].Raw) {
			t.Fatalf("record %d differs between file and mirror", i)
		}
	}
}

func openMirrored(t *testing.T, path string, m *memMirror, priv []byte) *Log {
	t.Helper()
	l, err := Open(Options{
		Path: path, ChainID: "c1", Buffer: 64, BatchSize: 4, FlushInterval: time.Millisecond,
		Signer: priv, CheckpointEvery: 3, Mirror: m, MirrorTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestMirrorReceivesExactlyTheFileRecords(t *testing.T) {
	t.Parallel()
	_, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	m := &memMirror{}
	l := openMirrored(t, path, m, priv)
	for i := range 20 {
		if err := l.Append(t.Context(), Event{Method: "tools/call", RequestID: fmt.Sprint(i), Decision: DecisionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	assertSameChain(t, path, m)
	kinds := map[string]int{}
	for _, r := range m.snapshot() {
		kinds[r.Kind]++
	}
	if kinds[KindEvent] != 20 || kinds[KindCheckpoint] == 0 {
		t.Fatalf("unexpected row kinds %v", kinds)
	}
}

func TestMirrorCommitFailureRollsBackTheFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	m := &memMirror{}
	l := openMirrored(t, path, m, nil)
	if err := l.Append(t.Context(), Event{Method: "first", Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(m.snapshot()) == 1 })
	m.failCommit.Store(true)
	if err := l.Append(t.Context(), Event{Method: "lost", Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return l.SinkErr() != nil })
	if got := len(fileRecords(t, path)); got != 1 {
		t.Fatalf("file kept %d records after the mirror refused the batch, want 1", got)
	}
	m.failCommit.Store(false)
	waitFor(t, func() bool { return l.SinkErr() == nil })
	if err := l.Append(t.Context(), Event{Method: "after", Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	assertSameChain(t, path, m)
}

func TestMirrorPrepareFailureWritesNothing(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	m := &memMirror{}
	m.failPrepare.Store(true)
	l := openMirrored(t, path, m, nil)
	if err := l.Append(t.Context(), Event{Method: "x", Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return l.SinkErr() != nil })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("file grew to %d bytes while the mirror was unavailable", info.Size())
	}
	m.failPrepare.Store(false)
	waitFor(t, func() bool { return l.SinkErr() == nil })
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenBackfillsMirrorFromFile(t *testing.T) {
	t.Parallel()
	_, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeLog(t, path, priv, 9)
	m := &memMirror{}
	recs := fileRecords(t, path)
	for _, rec := range recs[:3] {
		var b Body
		if err := json.Unmarshal(rec.Body, &b); err != nil {
			t.Fatal(err)
		}
		m.rows = append(m.rows, rowFor(&b, rec))
	}
	l := openMirrored(t, path, m, priv)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	assertSameChain(t, path, m)
}

func TestOpenRefusesMirrorAheadOfFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeLog(t, path, nil, 2)
	m := &memMirror{}
	m.reportLastSeq.Store(50)
	_, err := Open(Options{Path: path, ChainID: "c1", Mirror: m})
	if !errors.Is(err, ErrMirrorAhead) {
		t.Fatalf("Open = %v, want ErrMirrorAhead", err)
	}
}
