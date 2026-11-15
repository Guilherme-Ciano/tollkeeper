package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAnchorStatementLayout(t *testing.T) {
	t.Parallel()
	h := HashBytes([]byte("x"))
	msg, err := AnchorStatement("c1", 42, h)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("tollkeeper-anchor-v1\x00c1\x00"), binary.BigEndian.AppendUint64(nil, 42)...)
	want = append(want, raw...)
	if !bytes.Equal(msg, want) {
		t.Fatalf("statement %x, want %x", msg, want)
	}
	d, err := AnchorDigest("c1", 42, h)
	if err != nil || d != sha512.Sum512(want) {
		t.Fatalf("digest mismatch: %v", err)
	}
	ck, err := checkpointMessage("c1", 42, h)
	if err != nil || bytes.Equal(ck, msg) {
		t.Fatalf("anchor and checkpoint statements must differ: %v", err)
	}
	if _, err := AnchorStatement("c1", 1, "zz"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad hash accepted: %v", err)
	}
}

type anchorCapture struct {
	mu   sync.Mutex
	refs []CheckpointRef
}

func (c *anchorCapture) add(r CheckpointRef) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refs = append(c.refs, r)
}

func (c *anchorCapture) last(t *testing.T) CheckpointRef {
	t.Helper()
	waitFor(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.refs) > 0
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refs[len(c.refs)-1]
}

func openAnchoring(t *testing.T, path string, priv ed25519.PrivateKey, c *anchorCapture, dropped func(error)) *Log {
	t.Helper()
	l, err := Open(Options{
		Path: path, ChainID: "c1", Buffer: 64, BatchSize: 4, FlushInterval: time.Millisecond,
		Signer: priv, CheckpointEvery: 2, CheckpointCommitted: c.add, AnchorDropped: dropped,
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func appendN(t *testing.T, l *Log, n int) {
	t.Helper()
	for range n {
		if err := l.Append(
			t.Context(),
			Event{Phase: PhaseOutcome, Method: "tools/call", Decision: DecisionAllow},
		); err != nil {
			t.Fatal(err)
		}
	}
}

func fakeAnchor(ref CheckpointRef, pub ed25519.PublicKey) *Anchor {
	return &Anchor{
		CoversSeq: ref.Seq, CoversHash: ref.Hash, KeyID: KeyID(pub), Log: "log.example",
		Entry: []byte("{}"), Checkpoint: "log.example\n1\nAAAA\n",
	}
}

func TestAppendAnchorWritesChainedRecordAndVerifies(t *testing.T) {
	t.Parallel()
	pub, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	c := &anchorCapture{}
	l := openAnchoring(t, path, priv, c, nil)
	appendN(t, l, 4)
	ref := c.last(t)
	if ref.ChainID != "c1" || ref.Seq == 0 || len(ref.Hash) != 64 || ref.Ordinal == 0 {
		t.Fatalf("checkpoint ref %+v", ref)
	}
	if err := l.AppendAnchor(ref, fakeAnchor(ref, pub)); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 1)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.AppendAnchor(ref, fakeAnchor(ref, pub)); !errors.Is(err, ErrClosed) {
		t.Fatalf("append after close: %v", err)
	}
	rep, err := verifyFile(t, path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Anchors != 1 || rep.UnverifiedAnchors != 1 || rep.LastAnchoredSeq != 0 {
		t.Fatalf("report %+v", rep)
	}
	if !strings.Contains(string(mustRead(t, path)), `"anchor":{"covers_seq":`) {
		t.Fatal("anchor record not written")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAppendAnchorQueueFull(t *testing.T) {
	t.Parallel()
	pub, priv := keyPair(t)
	l, err := Open(Options{
		Path: filepath.Join(t.TempDir(), "a.jsonl"), ChainID: "c1", FlushInterval: time.Hour, Signer: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ref := CheckpointRef{ChainID: "c1", Seq: 1, Hash: ZeroHash}
	var full error
	for range 64 {
		if err := l.AppendAnchor(ref, fakeAnchor(ref, pub)); err != nil {
			full = err
			break
		}
	}
	if !errors.Is(full, ErrAnchorQueue) {
		t.Fatalf("queue never filled: %v", full)
	}
}

func TestStaleAndForeignAnchorsAreDropped(t *testing.T) {
	t.Parallel()
	pub, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	c := &anchorCapture{}
	var mu sync.Mutex
	var drops []error
	l := openAnchoring(t, path, priv, c, func(err error) {
		mu.Lock()
		drops = append(drops, err)
		mu.Unlock()
	})
	appendN(t, l, 2)
	ref := c.last(t)
	future := ref
	future.Seq += 1000
	foreign := ref
	foreign.ChainID = "other"
	for _, r := range []CheckpointRef{future, foreign} {
		if err := l.AppendAnchor(r, fakeAnchor(r, pub)); err != nil {
			t.Fatal(err)
		}
	}
	appendN(t, l, 1)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(drops) != 2 || !errors.Is(drops[0], ErrAnchorStale) {
		t.Fatalf("drops %v", drops)
	}
	rep, err := verifyFile(t, path, pub)
	if err != nil || rep.Anchors != 0 {
		t.Fatalf("stale anchor written: %+v %v", rep, err)
	}
}

func TestCheckpointCommittedNotFiredOnFailedWrite(t *testing.T) {
	t.Parallel()
	_, priv := keyPair(t)
	c := &anchorCapture{}
	l, err := Open(Options{
		Path: filepath.Join(t.TempDir(), "audit.jsonl"), ChainID: "c", Buffer: 8, BatchSize: 1,
		FlushInterval: time.Hour, Signer: priv, CheckpointEvery: 1, CheckpointCommitted: c.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	ff := &flakyFile{logFile: l.file}
	ff.failWrites.Store(1 << 20)
	l.file = ff
	t.Cleanup(func() { _ = l.Close() })
	if err := l.Append(t.Context(), Event{Phase: PhaseOutcome, Method: "m", Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return l.SinkErr() != nil })
	c.mu.Lock()
	n := len(c.refs)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("checkpoint hook fired %d times for a failed write", n)
	}
}

func TestRecoveredCheckpointExposesTail(t *testing.T) {
	t.Parallel()
	_, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeLog(t, path, priv, 5)
	l, err := Open(Options{Path: path, ChainID: "c1", Signer: priv})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ref, ok := l.RecoveredCheckpoint()
	if !ok || ref.Seq != l.Seq() || ref.ChainID != "c1" {
		t.Fatalf("recovered %+v %t, seq %d", ref, ok, l.Seq())
	}
}

type stubAnchors struct {
	err error
	at  time.Time
}

func (s stubAnchors) VerifyAnchor(_ string, a *Anchor, _ CheckpointRef, _ ed25519.PublicKey) (AnchorEvidence, error) {
	return AnchorEvidence{Log: a.Log, LogIndex: 9, WitnessedAt: s.at}, s.err
}

func anchoredFile(t *testing.T) (string, ed25519.PublicKey, CheckpointRef) {
	t.Helper()
	pub, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	c := &anchorCapture{}
	l := openAnchoring(t, path, priv, c, nil)
	appendN(t, l, 2)
	ref := c.last(t)
	if err := l.AppendAnchor(ref, fakeAnchor(ref, pub)); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 3)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path, pub, ref
}

func TestVerifyWithAnchorVerifierReportsAnchoredPrefix(t *testing.T) {
	t.Parallel()
	path, pub, ref := anchoredFile(t)
	at := time.Unix(0, ref.TS).Add(90 * time.Second)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := VerifyWith(f, VerifyOptions{PublicKey: pub, Anchors: stubAnchors{at: at}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.LastAnchoredSeq != ref.Seq || rep.RecordsAfterAnchor != rep.LastSeq-ref.Seq ||
		rep.UnverifiedAnchors != 0 || rep.LastAnchorIndex != 9 || rep.MaxAnchorDelay != 90*time.Second {
		t.Fatalf("report %+v", rep)
	}
	if _, err := VerifyWith(
		bytes.NewReader(mustRead(t, path)),
		VerifyOptions{Anchors: stubAnchors{}},
	); !errors.Is(
		err,
		ErrAnchorNeedsKey,
	) {
		t.Fatalf("verifier without key: %v", err)
	}
	_, err = VerifyWith(
		bytes.NewReader(mustRead(t, path)),
		VerifyOptions{PublicKey: pub, Anchors: stubAnchors{err: ErrMalformed}},
	)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("failing anchor accepted: %v", err)
	}
}

func TestVerifyRejectsAnchorForOtherCheckpointOrKey(t *testing.T) {
	t.Parallel()
	path, pub, ref := anchoredFile(t)
	data := string(mustRead(t, path))
	other, _ := keyPair(t)
	for name, tc := range map[string]struct {
		pub ed25519.PublicKey
		old string
		new string
	}{
		"hash": {pub, `"covers_hash":"` + ref.Hash, `"covers_hash":"` + ZeroHash},
		"key":  {other, "", ""},
	} {
		mutated := data
		if tc.old != "" {
			mutated = rewriteAnchor(t, data, tc.old, tc.new)
		}
		if _, err := Verify(strings.NewReader(mutated), tc.pub); !errors.Is(err, ErrTampered) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func rewriteAnchor(t *testing.T, data, old, replacement string) string {
	t.Helper()
	out := make([]string, 0, strings.Count(data, "\n"))
	prev := ZeroHash
	for line := range strings.SplitSeq(strings.TrimSuffix(data, "\n"), "\n") {
		body, _, _ := strings.Cut(strings.TrimPrefix(line, `{"body":`), `,"hash":`)
		body = strings.Replace(body, old, replacement, 1)
		body = strings.Replace(body, `"prev":"`+prevOf(body), `"prev":"`+prev, 1)
		h, err := ChainHash(prev, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, `{"body":`+body+`,"hash":"`+h+`"}`)
		prev = h
	}
	return strings.Join(out, "\n") + "\n"
}

func prevOf(body string) string {
	_, rest, _ := strings.Cut(body, `"prev":"`)
	p, _, _ := strings.Cut(rest, `"`)
	return p
}

func TestVerifyRejectsRecordWithTwoKinds(t *testing.T) {
	t.Parallel()
	path, pub, _ := anchoredFile(t)
	data := rewriteAnchor(
		t,
		string(mustRead(t, path)),
		`"anchor":{`,
		`"event":{"phase":"x","request_id":"","method":"m","decision":"allow"},"anchor":{`,
	)
	if _, err := Verify(strings.NewReader(data), pub); !errors.Is(err, ErrTampered) {
		t.Fatalf("two kinds accepted: %v", err)
	}
}

func TestCheckpointRingBounded(t *testing.T) {
	t.Parallel()
	var r checkpointRing
	for i := range uint64(3 * MaxAnchorLagCheckpoints) {
		r.add(CheckpointRef{Seq: i + 1})
	}
	if len(r.refs) > 2*MaxAnchorLagCheckpoints {
		t.Fatalf("ring grew to %d", len(r.refs))
	}
	if _, ok := r.find(3 * MaxAnchorLagCheckpoints); !ok {
		t.Fatal("newest checkpoint missing")
	}
	if _, ok := r.find(1); ok {
		t.Fatal("checkpoint beyond the lag bound still found")
	}
}
