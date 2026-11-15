package anchor_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor/rekortest"
)

type lateSink struct {
	log *audit.Log
}

func (s *lateSink) AppendAnchor(r audit.CheckpointRef, a *audit.Anchor) error {
	return s.log.AppendAnchor(r, a)
}

func runAnchoredLog(t *testing.T, s *rekortest.Server, k ed25519.PrivateKey, every, events int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &lateSink{}
	anchored := make(chan uint64, 64)
	a, err := anchor.New(anchor.Options{
		ChainID: "gw-1", Key: k, Every: every, Timeout: 5 * time.Second,
		BaseBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond,
		Verifier: anchor.NewReceiptVerifier(trustFor(t, s, 0)),
		Hooks:    anchor.Hooks{Anchored: func(seq uint64, _ time.Time) { anchored <- seq }},
	}, client(t, s), sink)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(audit.Options{
		Path: path, ChainID: "gw-1", Buffer: 256, BatchSize: 8, FlushInterval: time.Millisecond, Fsync: true,
		Signer: k, CheckpointEvery: 4, CheckpointCommitted: a.Offer,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink.log = l
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	for i := range events {
		if err := l.Append(t.Context(), audit.Event{
			Phase: audit.PhaseOutcome, RequestID: "r", Method: "tools/call", Decision: audit.DecisionAllow,
			LatencyMicros: int64(i),
		}); err != nil {
			t.Fatal(err)
		}
		if i == events/2 {
			select {
			case <-anchored:
			case <-time.After(10 * time.Second):
				t.Fatal("no anchor within 10s")
			}
		}
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEndToEndLogAnchorVerify(t *testing.T) {
	t.Parallel()
	at := time.Now().Add(time.Second)
	s := rekortest.New(t, rekortest.WithClock(func() time.Time { return at }), rekortest.WithWitness("w1.example"))
	k := key(t)
	pub := pubOf(t, k)
	path := runAnchoredLog(t, s, k, 1, 40)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := audit.VerifyWith(f, audit.VerifyOptions{
		PublicKey: pub, Anchors: anchor.NewReceiptVerifier(trustFor(t, s, 1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Anchors == 0 || rep.UnverifiedAnchors != 0 || rep.LastAnchoredSeq == 0 ||
		rep.RecordsAfterAnchor != rep.LastSeq-rep.LastAnchoredSeq || rep.LastAnchorLog != s.Origin ||
		!rep.LastWitnessedAt.Equal(at.Truncate(time.Second)) {
		t.Fatalf("report %+v", rep)
	}
	if rep.Anchors != uint64(s.Entries()) {
		t.Fatalf("%d anchors in the file, %d entries in the log", rep.Anchors, s.Entries())
	}
}

func TestEndToEndAnchorsFromAnotherLogFailVerification(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	other := rekortest.New(t)
	k := key(t)
	path := runAnchoredLog(t, s, k, 1, 12)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := audit.VerifyWith(f, audit.VerifyOptions{
		PublicKey: pubOf(t, k), Anchors: anchor.NewReceiptVerifier(trustFor(t, other, 0)),
	}); err == nil {
		t.Fatal("anchors verified against an untrusted log")
	}
}

func BenchmarkVerifyAnchor(b *testing.B) {
	s := rekortest.New(b)
	k := key(b)
	pub := pubOf(b, k)
	c, err := anchor.NewClient(s.URL, "", nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := range 1000 {
		sub, err := anchor.Sign(k, ref(uint64(i+1)))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.Submit(b.Context(), sub); err != nil {
			b.Fatal(err)
		}
	}
	sub, err := anchor.Sign(k, ref(5000))
	if err != nil {
		b.Fatal(err)
	}
	rec, err := c.Submit(b.Context(), sub)
	if err != nil {
		b.Fatal(err)
	}
	a := anchor.NewAnchor(ref(5000), pub, s.Origin, rec)
	v := anchor.NewReceiptVerifier(trustFor(b, s, 0))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.VerifyAnchor(chainID, a, ref(5000), pub); err != nil {
			b.Fatal(err)
		}
	}
}
