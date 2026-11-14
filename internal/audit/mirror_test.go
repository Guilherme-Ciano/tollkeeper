package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	lateCommit    atomic.Bool
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
	if p.m.lateCommit.Load() {
		if err := p.apply(); err != nil {
			return err
		}
		return errInjected
	}
	return p.apply()
}

func (p *memPending) apply() error {
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

func (p *memPending) Abort(context.Context) error { return nil }

func (m *memMirror) Prepare(_ context.Context, rows []Row) (Pending, error) {
	if m.failPrepare.Load() {
		return nil, errInjected
	}
	return &memPending{m: m, rows: append([]Row(nil), rows...)}, nil
}

func (m *memMirror) Last(context.Context, string) (seq uint64, hash string, err error) {
	if v := m.reportLastSeq.Load(); v > 0 {
		return uint64(v), "", nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rows) == 0 {
		return 0, "", nil
	}
	last := m.rows[len(m.rows)-1]
	return last.Seq, last.Hash, nil
}

func (m *memMirror) snapshot() []Row {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Row(nil), m.rows...)
}

func fileRecords(t *testing.T, path string) []Record {
	t.Helper()
	ls := lines(t, path)
	out := make([]Record, 0, len(ls))
	for _, line := range ls {
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
		e := Event{Method: "tools/call", RequestID: strconv.Itoa(i), Decision: DecisionAllow}
		if err := l.Append(t.Context(), e); err != nil {
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

func TestMirrorCatchesUpAfterFailedCommit(t *testing.T) {
	t.Parallel()
	cases := map[string]func(m *memMirror, on bool){
		"commit lost":                 func(m *memMirror, on bool) { m.failCommit.Store(on) },
		"commit applied but reported": func(m *memMirror, on bool) { m.lateCommit.Store(on) },
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			m := &memMirror{}
			var sinkErrors atomic.Int64
			l, err := Open(Options{
				Path: path, ChainID: "c1", Buffer: 64, BatchSize: 4, FlushInterval: time.Millisecond,
				Mirror: m, MirrorTimeout: time.Second,
				Hooks: Hooks{SinkError: func(error) { sinkErrors.Add(1) }},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := l.Append(t.Context(), Event{Method: "first", Decision: DecisionAllow}); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { return len(m.snapshot()) == 1 })
			inject(m, true)
			if err := l.Append(t.Context(), Event{Method: "second", Decision: DecisionAllow}); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { return sinkErrors.Load() > 0 })
			if got := len(fileRecords(t, path)); got != 2 {
				t.Fatalf("an fsynced record was removed from the file: %d records", got)
			}
			inject(m, false)
			if err := l.Append(t.Context(), Event{Method: "third", Decision: DecisionAllow}); err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			assertSameChain(t, path, m)
		})
	}
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

func TestOpenRefusesDivergedMirror(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeLog(t, path, nil, 4)
	recs := fileRecords(t, path)
	m := &memMirror{}
	for i, rec := range recs[:2] {
		var b Body
		if err := json.Unmarshal(rec.Body, &b); err != nil {
			t.Fatal(err)
		}
		r := rowFor(&b, rec)
		if i == 1 {
			r.Hash = strings.Repeat("f", 64)
		}
		m.rows = append(m.rows, r)
	}
	if _, err := Open(Options{Path: path, ChainID: "c1", Mirror: m}); !errors.Is(err, ErrMirrorDiverged) {
		t.Fatalf("Open = %v, want ErrMirrorDiverged", err)
	}
}
