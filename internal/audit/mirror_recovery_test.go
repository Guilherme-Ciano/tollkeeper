package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type flakyMirror struct {
	mu          sync.Mutex
	rows        []Row
	failPrepare atomic.Bool
	failCommit  atomic.Bool
	prepares    atomic.Int32
	commits     atomic.Int32
	aborts      atomic.Int32
}

type flakyPending struct {
	m    *flakyMirror
	rows []Row
}

func (p *flakyPending) Commit(context.Context) error {
	p.m.commits.Add(1)
	if p.m.failCommit.Load() {
		return errors.New("postgres commit timeout")
	}
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	for _, r := range p.rows {
		if len(p.m.rows) > 0 {
			last := p.m.rows[len(p.m.rows)-1]
			if r.Seq != last.Seq+1 || r.Prev != last.Hash {
				return fmt.Errorf("mirror chain break at seq %d", r.Seq)
			}
		} else if r.Seq != 1 || r.Prev != ZeroHash {
			return fmt.Errorf("mirror chain must start at seq 1, got %d", r.Seq)
		}
		p.m.rows = append(p.m.rows, r)
	}
	return nil
}

func (p *flakyPending) Abort(context.Context) error {
	p.m.aborts.Add(1)
	return nil
}

func (m *flakyMirror) Prepare(_ context.Context, rows []Row) (Pending, error) {
	m.prepares.Add(1)
	if m.failPrepare.Load() {
		return nil, errors.New("postgres unavailable")
	}
	cp := make([]Row, len(rows))
	copy(cp, rows)
	return &flakyPending{m: m, rows: cp}, nil
}

func (m *flakyMirror) Last(_ context.Context, _ string) (seq uint64, hash string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rows) == 0 {
		return 0, "", nil
	}
	last := m.rows[len(m.rows)-1]
	return last.Seq, last.Hash, nil
}

func mirrorSeq(t *testing.T, m *flakyMirror) uint64 {
	t.Helper()
	seq, _, err := m.Last(t.Context(), "pg-rec")
	if err != nil {
		t.Fatalf("mirror.Last: %v", err)
	}
	return seq
}

func TestAuditMirrorCommitOutageAndAutomaticBackfillRecovery(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	mirror := &flakyMirror{}

	l, err := OpenContext(ctx, Options{
		Path:          path,
		ChainID:       "pg-rec",
		BatchSize:     1,
		FlushInterval: 5 * time.Millisecond,
		Fsync:         true,
		Mirror:        mirror,
		MirrorTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "e1", Method: "m", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	waitFor(t, func() bool { return mirrorSeq(t, mirror) == 1 })

	mirror.failCommit.Store(true)
	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "e2", Method: "m", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 2 during commit outage: %v", err)
	}
	waitFor(t, func() bool { return l.Seq() == 2 })

	if seq := mirrorSeq(t, mirror); seq != 1 {
		t.Fatalf("mirror should still be at seq 1 during commit failure, got %d", seq)
	}

	mirror.failCommit.Store(false)
	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "e3", Method: "m", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 3 after recovery: %v", err)
	}
	waitFor(t, func() bool { return mirrorSeq(t, mirror) == 3 })

	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := Verify(f, nil)
	if err != nil {
		t.Fatalf("verify local file: %v", err)
	}
	seq, hash, err := mirror.Last(ctx, "pg-rec")
	if err != nil {
		t.Fatal(err)
	}
	if seq != rep.LastSeq || hash != rep.LastHash || rep.Events != 3 {
		t.Fatalf("mirror head (%d, %s) != local file (%d, %s)", seq, hash, rep.LastSeq, rep.LastHash)
	}
}
