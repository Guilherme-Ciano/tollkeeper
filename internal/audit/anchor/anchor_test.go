package anchor_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor/rekortest"
)

const chainID = "gw-1"

func key(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return priv
}

func pubOf(tb testing.TB, k ed25519.PrivateKey) ed25519.PublicKey {
	tb.Helper()
	pub, ok := k.Public().(ed25519.PublicKey)
	if !ok {
		tb.Fatal("not an ed25519 key")
	}
	return pub
}

func ref(seq uint64) audit.CheckpointRef {
	return audit.CheckpointRef{
		ChainID: chainID, Seq: seq, Hash: audit.HashBytes([]byte{byte(seq)}),
		TS: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC).UnixNano(), Ordinal: seq,
	}
}

func trustFor(tb testing.TB, s *rekortest.Server, minWitnesses int) *anchor.Trust {
	tb.Helper()
	tr, err := anchor.ParseTrust(s.TrustedRootJSON(), "")
	if err != nil {
		tb.Fatal(err)
	}
	tr, err = tr.WithWitnesses(s.WitnessVKeys(), minWitnesses)
	if err != nil {
		tb.Fatal(err)
	}
	return tr
}

func client(tb testing.TB, s *rekortest.Server) *anchor.Client {
	tb.Helper()
	c, err := anchor.NewClient(s.URL, "tollkeeper-test", nil)
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

func anchored(t *testing.T, s *rekortest.Server, k ed25519.PrivateKey, r audit.CheckpointRef) *audit.Anchor {
	t.Helper()
	sub, err := anchor.Sign(k, r)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := client(t, s).Submit(t.Context(), sub)
	if err != nil {
		t.Fatal(err)
	}
	return anchor.NewAnchor(r, pubOf(t, k), s.Origin, rec)
}

func TestSubmitSendsEd25519phOverSHA512Digest(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	k := key(t)
	a := anchored(t, s, k, ref(7))
	v := anchor.NewReceiptVerifier(trustFor(t, s, 0))
	ev, err := v.VerifyAnchor(chainID, a, ref(7), pubOf(t, k))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Log != s.Origin || ev.TreeSize != 1 || ev.LogIndex != 0 {
		t.Fatalf("evidence %+v", ev)
	}
	pure, err := anchor.Sign(k, ref(8))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := audit.AnchorStatement(chainID, 8, ref(8).Hash)
	if err != nil {
		t.Fatal(err)
	}
	pure.Signature = ed25519.Sign(k, msg)
	if _, err := client(t, s).Submit(t.Context(), pure); !errors.Is(err, anchor.ErrRejected) {
		t.Fatalf("pure Ed25519 signature accepted: %v", err)
	}
}

func TestSubmitRequestJSONShape(t *testing.T) {
	t.Parallel()
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/log/entries" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request %s %s", r.URL.Path, r.Header.Get("Content-Type"))
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got = b
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	c, err := anchor.NewClient(srv.URL+"/", "ua", nil)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := anchor.Sign(key(t), ref(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Submit(t.Context(), sub); !errors.Is(err, anchor.ErrUnavailable) {
		t.Fatalf("503 not mapped to unavailable: %v", err)
	}
	want := `{"hashedRekordRequestV002":{"digest":"` + base64.StdEncoding.EncodeToString(sub.Digest[:]) +
		`","signature":{"content":"` + base64.StdEncoding.EncodeToString(sub.Signature) +
		`","verifier":{"publicKey":{"rawBytes":"` + base64.StdEncoding.EncodeToString(sub.PublicKeyDER) +
		`"},"keyDetails":"PKIX_ED25519_PH"}}}}`
	if string(got) != want {
		t.Fatalf("request body\n got %s\nwant %s", got, want)
	}
}

func TestSubmitMapsStatusToErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusBadRequest, anchor.ErrRejected},
		{http.StatusConflict, anchor.ErrRejected},
		{http.StatusTooManyRequests, anchor.ErrUnavailable},
		{http.StatusServiceUnavailable, anchor.ErrUnavailable},
		{http.StatusRequestTimeout, anchor.ErrUnavailable},
	} {
		s := rekortest.New(t)
		s.FailNext(tc.status, 1, 7*time.Second)
		sub, err := anchor.Sign(key(t), ref(1))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client(t, s).Submit(t.Context(), sub)
		var he *anchor.HTTPError
		if !errors.Is(err, tc.want) || !errors.As(err, &he) || he.RetryAfter != 7*time.Second {
			t.Errorf("status %d: %v", tc.status, err)
		}
	}
}

func TestSubmitRejectsMalformedAndOversizedReceipts(t *testing.T) {
	t.Parallel()
	for name, body := range map[string][]byte{
		"malformed": []byte(`{"logIndex":`),
		"oversized": bytes.Repeat([]byte(" "), 2<<20),
		"wrongKind": []byte(`{"logIndex":"1","kindVersion":{"kind":"dsse","version":"0.0.2"},` +
			`"canonicalizedBody":"e30=","inclusionProof":{"checkpoint":{"envelope":"x"}}}`),
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			if _, err := w.Write(body); err != nil {
				t.Error(err)
			}
		}))
		c, err := anchor.NewClient(srv.URL, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		sub, err := anchor.Sign(key(t), ref(1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Submit(t.Context(), sub); !errors.Is(err, anchor.ErrInvalidReceipt) {
			t.Errorf("%s: %v", name, err)
		}
		srv.Close()
	}
}

func TestSubmitRefusesRedirect(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	redir := httptest.NewServer(http.RedirectHandler(s.URL+"/api/v2/log/entries", http.StatusTemporaryRedirect))
	t.Cleanup(redir.Close)
	c, err := anchor.NewClient(redir.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := anchor.Sign(key(t), ref(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Submit(t.Context(), sub); !errors.Is(err, anchor.ErrRejected) || s.Entries() != 0 {
		t.Fatalf("redirect followed: %v, entries %d", err, s.Entries())
	}
}

func TestSubmitHonoursContextCancel(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	s.Delay(time.Hour)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	sub, err := anchor.Sign(key(t), ref(1))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := client(t, s).Submit(ctx, sub); !anchor.IsRetryable(err) || time.Since(start) > 5*time.Second {
		t.Fatalf("cancel: %v after %s", err, time.Since(start))
	}
}

func TestReceiptVerifierRejectsTampering(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t, rekortest.WithWitness("w1.example"))
	other := rekortest.New(t)
	k := key(t)
	pub := pubOf(t, k)
	for range 3 {
		anchored(t, s, k, ref(1))
	}
	good := anchored(t, s, k, ref(5))
	v := anchor.NewReceiptVerifier(trustFor(t, s, 0))
	if _, err := v.VerifyAnchor(chainID, good, ref(5), pub); err != nil {
		t.Fatalf("good receipt: %v", err)
	}
	cases := map[string]struct {
		mutate  func(a *audit.Anchor)
		covered audit.CheckpointRef
		pub     ed25519.PublicKey
		want    error
	}{
		"proof":  {func(a *audit.Anchor) { a.Proof[0][3] ^= 1 }, ref(5), pub, anchor.ErrInvalidReceipt},
		"index":  {func(a *audit.Anchor) { a.LogIndex = 1 }, ref(5), pub, anchor.ErrInvalidReceipt},
		"origin": {func(a *audit.Anchor) { a.Log = other.Origin }, ref(5), pub, anchor.ErrUntrustedLog},
		"checkpoint": {
			func(a *audit.Anchor) { a.Checkpoint = strings.Replace(a.Checkpoint, "\n4\n", "\n5\n", 1) },
			ref(5),
			pub,
			anchor.ErrInvalidReceipt,
		},
		"otherCkpt": {func(*audit.Anchor) {}, ref(6), pub, anchor.ErrDigestMismatch},
		"otherKey":  {func(*audit.Anchor) {}, ref(5), pubOf(t, key(t)), anchor.ErrInvalidReceipt},
		"entry": {
			func(a *audit.Anchor) { a.Entry = bytes.Replace(a.Entry, []byte("SHA2_512"), []byte("SHA2_256"), 1) },
			ref(5),
			pub,
			anchor.ErrInvalidReceipt,
		},
		"foreignEntry": {
			func(a *audit.Anchor) { a.Checkpoint = anchored(t, other, k, ref(5)).Checkpoint },
			ref(5),
			pub,
			anchor.ErrInvalidReceipt,
		},
	}
	for name, tc := range cases {
		a := *good
		a.Proof = make([][]byte, len(good.Proof))
		for i := range good.Proof {
			a.Proof[i] = bytes.Clone(good.Proof[i])
		}
		a.Entry = bytes.Clone(good.Entry)
		tc.mutate(&a)
		if _, err := v.VerifyAnchor(chainID, &a, tc.covered, tc.pub); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}

func TestReceiptVerifierRejectsTamperedProofFromLog(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	k := key(t)
	anchored(t, s, k, ref(1))
	s.TamperNextProof()
	a := anchored(t, s, k, ref(2))
	v := anchor.NewReceiptVerifier(trustFor(t, s, 0))
	if _, err := v.VerifyAnchor(
		chainID,
		a,
		ref(2),
		pubOf(t, k),
	); !errors.Is(
		err,
		anchor.ErrInvalidReceipt,
	) {
		t.Fatalf("tampered proof accepted: %v", err)
	}
}

func TestReceiptVerifierWitnessQuorumAndTime(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 14, 21, 58, 0, 0, time.UTC)
	s := rekortest.New(t, rekortest.WithClock(func() time.Time { return at }),
		rekortest.WithWitness("w1.example"), rekortest.WithWitness("w2.example"))
	k := key(t)
	pub := pubOf(t, k)
	a := anchored(t, s, k, ref(3))
	ev, err := anchor.NewReceiptVerifier(trustFor(t, s, 2)).VerifyAnchor(chainID, a, ref(3), pub)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Witnesses != 2 || !ev.WitnessedAt.Equal(at) {
		t.Fatalf("witness evidence %+v", ev)
	}
	tr, err := anchor.ParseTrust(s.TrustedRootJSON(), "")
	if err != nil {
		t.Fatal(err)
	}
	strict, err := tr.WithWitnesses(
		append(s.WitnessVKeys(), anchor.CosignatureVKey("w3.example", pubOf(t, key(t)))),
		3,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anchor.NewReceiptVerifier(strict).
		VerifyAnchor(chainID, a, ref(3), pub); !errors.Is(
		err,
		anchor.ErrWitnessQuorum,
	) {
		t.Fatalf("quorum: %v", err)
	}
}

func TestCosignatureVerifierRejectsBadKeys(t *testing.T) {
	t.Parallel()
	pub := pubOf(t, key(t))
	good := anchor.CosignatureVKey("w.example", pub)
	if _, err := anchor.NewCosignatureVerifier(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"", "w.example", "w.example+00000000+" + strings.SplitN(good, "+", 3)[2],
		strings.Replace(good, "+B", "+A", 1), "w.example+zz+AAAA",
	} {
		if _, err := anchor.NewCosignatureVerifier(bad); !errors.Is(err, anchor.ErrBadTrust) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

func TestLoadTrustRealSigstoreRoot(t *testing.T) {
	t.Parallel()
	tr, err := anchor.LoadTrust([]string{filepath.Join("testdata", "trusted_root.json")}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(tr.Origins(), ","), "log2025-1.rekor.sigstore.dev") {
		t.Fatalf("origins %v", tr.Origins())
	}
	cp, err := os.ReadFile(filepath.Join("testdata", "log2025-1-checkpoint.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.CheckLogCheckpoint(tr, string(cp)); err != nil {
		t.Fatalf("live checkpoint does not verify with the trusted root: %v", err)
	}
	tampered := strings.Replace(string(cp), "\n2", "\n3", 1)
	if err := anchor.CheckLogCheckpoint(tr, tampered); err == nil {
		t.Fatal("tampered checkpoint verified")
	}
}

func TestLoadTrustPEMAndGarbage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, pubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(dir, "log.pub")
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(pemPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(garbage, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := anchor.LoadTrust([]string{pemPath}, "rekor.internal"); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{"noOrigin": {pemPath}, "garbage": {garbage}, "none": nil} {
		origin := ""
		if _, err := anchor.LoadTrust(args, origin); !errors.Is(err, anchor.ErrBadTrust) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type memSink struct {
	mu   sync.Mutex
	got  []*audit.Anchor
	refs []audit.CheckpointRef
	err  error
	cond chan struct{}
}

func newSink() *memSink { return &memSink{cond: make(chan struct{}, 64)} }

func (m *memSink) AppendAnchor(r audit.CheckpointRef, a *audit.Anchor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.got = append(m.got, a)
	m.refs = append(m.refs, r)
	m.cond <- struct{}{}
	return nil
}

func (m *memSink) wait(t *testing.T) {
	t.Helper()
	const n = 1
	deadline := time.After(10 * time.Second)
	for {
		m.mu.Lock()
		have := len(m.got)
		m.mu.Unlock()
		if have >= n {
			return
		}
		select {
		case <-m.cond:
		case <-deadline:
			t.Fatalf("got %d anchors, want %d", have, n)
		}
	}
}

func newAnchorer(
	t *testing.T,
	s *rekortest.Server,
	k ed25519.PrivateKey,
	sink *memSink,
	mut func(*anchor.Options),
) *anchor.Anchorer {
	t.Helper()
	opts := anchor.Options{
		ChainID: chainID, Key: k, Interval: time.Hour, Timeout: 5 * time.Second,
		BaseBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond,
		Verifier: anchor.NewReceiptVerifier(trustFor(t, s, 0)),
	}
	if mut != nil {
		mut(&opts)
	}
	a, err := anchor.New(opts, client(t, s), sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("anchorer did not exit after cancel")
		}
	})
	return a
}

func TestAnchorerAnchorsFirstCheckpointThenWaitsForInterval(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	sink := newSink()
	a := newAnchorer(t, s, key(t), sink, nil)
	a.Offer(ref(10))
	sink.wait(t)
	a.Offer(ref(20))
	time.Sleep(50 * time.Millisecond)
	if s.Entries() != 1 || sink.got[0].CoversSeq != 10 {
		t.Fatalf("entries %d, anchors %+v", s.Entries(), sink.got)
	}
	if a.LastSuccess().IsZero() {
		t.Fatal("last success not recorded")
	}
}

func TestAnchorerEveryNCheckpoints(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	sink := newSink()
	a := newAnchorer(t, s, key(t), sink, func(o *anchor.Options) { o.Interval, o.Every = 0, 3 })
	for i := uint64(1); i <= 7; i++ {
		a.Offer(ref(i))
	}
	sink.wait(t)
	time.Sleep(50 * time.Millisecond)
	if n := s.Entries(); n < 1 || n > 2 {
		t.Fatalf("entries %d for 7 checkpoints with every=3", n)
	}
}

func TestAnchorerRetriesWithBackoffThenSucceedsOnNewestRef(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	s.FailNext(http.StatusServiceUnavailable, 3, 0)
	sink := newSink()
	var mu sync.Mutex
	outcomes := map[string]int{}
	a := newAnchorer(t, s, key(t), sink, func(o *anchor.Options) {
		o.Hooks.Attempt = func(out string) {
			mu.Lock()
			outcomes[out]++
			mu.Unlock()
		}
	})
	a.Offer(ref(1))
	a.Offer(ref(2))
	sink.wait(t)
	mu.Lock()
	defer mu.Unlock()
	if outcomes[anchor.OutcomeRetry] != 3 || outcomes[anchor.OutcomeOK] != 1 || sink.got[0].CoversSeq != 2 {
		t.Fatalf("outcomes %v, anchored %d", outcomes, sink.got[0].CoversSeq)
	}
}

func TestAnchorerDoesNotRetryRejected(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	s.FailNext(http.StatusBadRequest, 1, 0)
	sink := newSink()
	rejected := make(chan string, 4)
	a := newAnchorer(t, s, key(t), sink, func(o *anchor.Options) {
		o.Hooks.Attempt = func(out string) { rejected <- out }
	})
	a.Offer(ref(1))
	if got := <-rejected; got != anchor.OutcomeRejected {
		t.Fatalf("outcome %s", got)
	}
	time.Sleep(50 * time.Millisecond)
	if len(rejected) != 0 {
		t.Fatal("rejected checkpoint was retried")
	}
	a.Offer(ref(2))
	sink.wait(t)
}

func TestAnchorerExitsOnCancelDuringSlowSubmit(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	s.Delay(time.Hour)
	a := newAnchorer(t, s, key(t), newSink(), func(o *anchor.Options) { o.Timeout = time.Hour })
	a.Offer(ref(1))
	time.Sleep(20 * time.Millisecond)
}

func TestNewRejectsMissingSchedule(t *testing.T) {
	t.Parallel()
	s := rekortest.New(t)
	_, err := anchor.New(anchor.Options{Key: key(t), Verifier: anchor.NewReceiptVerifier(trustFor(t, s, 0))},
		client(t, s), newSink())
	if !errors.Is(err, anchor.ErrNoSchedule) {
		t.Fatalf("no schedule: %v", err)
	}
}
