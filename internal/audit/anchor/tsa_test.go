package anchor_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor/rekortest"
)

func stamped(t *testing.T, s *rekortest.Server, r audit.CheckpointRef) (a *audit.Anchor, pub []byte) {
	t.Helper()
	k := key(t)
	a = anchored(t, s, k, r)
	tc, err := anchor.NewTimestampClient(s.TSAURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := audit.AnchorStatement(r.ChainID, r.Seq, r.Hash)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tc.Timestamp(t.Context(), statement)
	if err != nil {
		t.Fatal(err)
	}
	a.Timestamp = token
	return a, pubOf(t, k)
}

func TestTimestampedAnchorProvesTime(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s := rekortest.New(t, rekortest.WithTSA(), rekortest.WithClock(func() time.Time { return at }))
	r := ref(4)
	a, pub := stamped(t, s, r)
	ev, err := anchor.NewReceiptVerifier(trustFor(t, s, 0).RequireTime()).VerifyAnchor(chainID, a, r, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.TimestampedAt.Equal(at) || !ev.ProvenAt().Equal(at) || ev.Witnesses != 0 {
		t.Fatalf("evidence %+v", ev)
	}
}

func TestTimestampWithoutEmbeddedCertificatesUsesTrustedChain(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t, rekortest.WithTSA())
	s.TSAOmitCertificates()
	r := ref(4)
	a, pub := stamped(t, s, r)
	if _, err := anchor.NewReceiptVerifier(trustFor(t, s, 0)).VerifyAnchor(chainID, a, r, pub); err != nil {
		t.Fatal(err)
	}
}

func TestTimestampFromUntrustedAuthorityIsRejected(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t, rekortest.WithTSA())
	other := rekortest.New(t, rekortest.WithTSA())
	r := ref(4)
	a, pub := stamped(t, s, r)
	tr, err := anchor.ParseTrust(s.TrustedRootJSON(), "")
	if err != nil {
		t.Fatal(err)
	}
	otherTSA, err := anchor.ParseTrust(other.TrustedRootJSON(), "")
	if err != nil {
		t.Fatal(err)
	}
	mixed := tr.WithTimestampAuthorities(otherTSA)
	if _, err := anchor.NewReceiptVerifier(mixed).
		VerifyAnchor(chainID, a, r, pub); !errors.Is(
		err,
		anchor.ErrUntrustedTimestamp,
	) {
		t.Fatalf("timestamp from another authority accepted: %v", err)
	}
	logOnly, err := anchor.ParseTrust(rekortest.New(t).TrustedRootJSON(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anchor.NewReceiptVerifier(tr.WithTimestampAuthorities(logOnly)).
		VerifyAnchor(chainID, a, r, pub); !errors.Is(
		err,
		anchor.ErrUntrustedTimestamp,
	) {
		t.Fatalf("timestamp accepted without any trusted authority: %v", err)
	}
}

func TestTimestampForAnotherCheckpointIsRejected(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t, rekortest.WithTSA())
	a, pub := stamped(t, s, ref(4))
	b, _ := stamped(t, s, ref(5))
	a.Timestamp = b.Timestamp
	if _, err := anchor.NewReceiptVerifier(trustFor(t, s, 0)).
		VerifyAnchor(chainID, a, ref(4), pub); !errors.Is(
		err,
		anchor.ErrDigestMismatch,
	) {
		t.Fatalf("timestamp of another checkpoint accepted: %v", err)
	}
}

func TestRequireTimeRejectsAnchorWithoutTime(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t, rekortest.WithTSA())
	k := key(t)
	a := anchored(t, s, k, ref(4))
	if _, err := anchor.NewReceiptVerifier(trustFor(t, s, 0).RequireTime()).
		VerifyAnchor(chainID, a, ref(4), pubOf(t, k)); !errors.Is(
		err,
		anchor.ErrNoProvenTime,
	) {
		t.Fatalf("anchor without time accepted: %v", err)
	}
}

func TestAnchorerTimestampsAndRetriesTSAOutage(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t, rekortest.WithTSA())
	s.TSAFailNext(2)
	tc, err := anchor.NewTimestampClient(s.TSAURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := newSink()
	var mu sync.Mutex
	outcomes := map[string]int{}
	a := newAnchorer(t, s, key(t), sink, func(o *anchor.Options) {
		o.Timestamper = tc
		o.Verifier = anchor.NewReceiptVerifier(trustFor(t, s, 0).RequireTime())
		o.Hooks.Attempt = func(out string) {
			mu.Lock()
			outcomes[out]++
			mu.Unlock()
		}
	})
	a.Offer(ref(1))
	sink.wait(t)
	mu.Lock()
	defer mu.Unlock()
	if outcomes[anchor.OutcomeRetry] != 2 || len(sink.got[0].Timestamp) == 0 || s.Entries() != 1 {
		t.Fatalf("outcomes %v, entries %d", outcomes, s.Entries())
	}
}

func TestTimestampClientChecksNonceAndStatus(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t, rekortest.WithTSA())
	s.TSAFailNext(1)
	tc, err := anchor.NewTimestampClient(s.TSAURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = tc.Timestamp(ctx, []byte("x"))
	var he *anchor.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusServiceUnavailable || !anchor.IsRetryable(err) {
		t.Fatalf("503 from the authority: %v", err)
	}
	if _, err := anchor.NewTimestampClient("http://tsa.example.com", nil); !errors.Is(err, anchor.ErrBadTrust) {
		t.Fatalf("plain http to a remote authority accepted: %v", err)
	}
}
