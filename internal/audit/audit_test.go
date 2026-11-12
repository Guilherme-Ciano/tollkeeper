package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func keyPair(tb testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return pub, priv
}

func writeLog(t *testing.T, path string, priv ed25519.PrivateKey, n int) {
	t.Helper()
	l, err := Open(Options{
		Path: path, ChainID: "c1", Buffer: 64, BatchSize: 4, FlushInterval: time.Millisecond,
		Signer: priv, CheckpointEvery: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		e := Event{
			Phase: PhaseOutcome, RequestID: "r" + string(rune('a'+i%26)), Subject: "alice", Method: "tools/call",
			Tool: "notes__search", Decision: DecisionAllow, LatencyMicros: int64(i),
		}
		if err := l.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func verifyFile(t *testing.T, path string, pub ed25519.PublicKey) (Report, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return Verify(f, pub)
}

func TestLogRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeLog(t, path, priv, 10)
	rep, err := verifyFile(t, path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events != 10 || rep.Checkpoints < 3 || rep.UnsignedTail != 0 || rep.ChainID != "c1" {
		t.Fatalf("unexpected report %+v", rep)
	}
}

func TestLogContinuesChainAfterRestart(t *testing.T) {
	t.Parallel()
	pub, priv := keyPair(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeLog(t, path, priv, 5)
	writeLog(t, path, priv, 5)
	rep, err := verifyFile(t, path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events != 10 {
		t.Fatalf("events %d", rep.Events)
	}
	if _, err := Open(Options{Path: path, ChainID: "other"}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("chain id mismatch accepted: %v", err)
	}
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func TestVerifyDetectsTampering(t *testing.T) {
	t.Parallel()
	pub, priv := keyPair(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeLog(t, path, priv, 8)
	orig := lines(t, path)
	otherPub, _ := keyPair(t)
	cases := []struct {
		name   string
		mutate func([]string) []string
		pub    ed25519.PublicKey
		want   string
	}{
		{"edit field", func(l []string) []string {
			l[1] = strings.Replace(l[1], `"sub":"alice"`, `"sub":"mallory"`, 1)
			return l
		}, pub, "hash mismatch"},
		{"delete record", func(l []string) []string { return append(l[:2], l[3:]...) }, pub, "sequence gap"},
		{"swap records", func(l []string) []string { l[1], l[2] = l[2], l[1]; return l }, pub, "sequence gap"},
		{"unknown field", func(l []string) []string {
			l[0] = strings.Replace(l[0], `{"body"`, `{"x":1,"body"`, 1)
			return l
		}, pub, "malformed record"},
		{"truncated tail", func(l []string) []string { l[len(l)-1] = l[len(l)-1][:20]; return l }, pub, "malformed"},
		{"wrong key", func(l []string) []string { return l }, otherPub, "unknown key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated := tc.mutate(append([]string(nil), orig...))
			p := filepath.Join(t.TempDir(), "a.jsonl")
			if err := os.WriteFile(p, []byte(strings.Join(mutated, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := verifyFile(t, p, tc.pub)
			if !errors.Is(err, ErrTampered) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyRejectsForgedCheckpoint(t *testing.T) {
	t.Parallel()
	pub, priv := keyPair(t)
	_, attacker := keyPair(t)
	var buf bytes.Buffer
	prev := ZeroHash
	for seq := uint64(1); seq <= 2; seq++ {
		var b Body
		if seq == 1 {
			b = Body{Seq: 1, ChainID: "c", Prev: prev, Event: &Event{Method: "m", Decision: DecisionAllow}}
		} else {
			ck, err := SignCheckpoint(attacker, "c", 1, prev)
			if err != nil {
				t.Fatal(err)
			}
			ck.KeyID = KeyID(pub)
			b = Body{Seq: 2, ChainID: "c", Prev: prev, Checkpoint: ck}
		}
		rec, err := Seal(&b)
		if err != nil {
			t.Fatal(err)
		}
		buf.WriteString(`{"body":` + string(rec.Body) + `,"hash":"` + rec.Hash + `"}` + "\n")
		prev = rec.Hash
	}
	if _, err := Verify(&buf, pub); err == nil || !strings.Contains(err.Error(), "invalid checkpoint signature") {
		t.Fatalf("forged checkpoint accepted: %v", err)
	}
	ck, err := SignCheckpoint(priv, "c", 1, ZeroHash)
	if err != nil || !VerifyCheckpoint(pub, "c", ck) {
		t.Fatalf("legitimate checkpoint rejected: %v", err)
	}
}

func TestFailOpenRecordsGap(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	dropped := 0
	l, err := Open(Options{
		Path: path, ChainID: "c", Buffer: 1, BatchSize: 1000, FlushInterval: time.Hour, FailOpen: true,
		Hooks: Hooks{Dropped: func() { dropped++ }},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if err := l.Append(t.Context(), Event{Method: "m", Decision: DecisionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := verifyFile(t, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dropped == 0 || rep.Gaps != 1 || rep.DroppedEvents != uint64(dropped) {
		t.Fatalf("dropped=%d report=%+v", dropped, rep)
	}
	if err := l.Append(t.Context(), Event{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("append after close: %v", err)
	}
}

func TestFailClosedBackpressure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(Options{
		Path: path, ChainID: "c", Buffer: 1, BatchSize: 1, FlushInterval: time.Hour,
		Hooks: Hooks{Written: func(int) { time.Sleep(50 * time.Millisecond) }},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var lastErr error
	for range 5 {
		ctx, cancel := contextWithTimeout(t, 5*time.Millisecond)
		lastErr = l.Append(ctx, Event{Method: "m"})
		cancel()
	}
	if !errors.Is(lastErr, ErrBackpressure) {
		t.Fatalf("expected backpressure, got %v", lastErr)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	t.Parallel()
	privPEM, pubPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := SignCheckpoint(priv, "c", 7, ZeroHash)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCheckpoint(pub, "c", ck) || VerifyCheckpoint(pub, "other-chain", ck) {
		t.Fatal("checkpoint signature not bound to chain id")
	}
	if _, err := ParsePrivateKey(pubPEM); err == nil {
		t.Fatal("public key parsed as private")
	}
}

func FuzzVerify(f *testing.F) {
	pub, priv := keyPair(f)
	dir := f.TempDir()
	path := filepath.Join(dir, "seed.jsonl")
	l, err := Open(Options{Path: path, ChainID: "c", Signer: priv, CheckpointEvery: 2, FlushInterval: time.Millisecond})
	if err != nil {
		f.Fatal(err)
	}
	for range 3 {
		if err := l.Append(f.Context(), Event{Method: "m", Decision: DecisionAllow}); err != nil {
			f.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		f.Fatal(err)
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("{}\n"))
	f.Add([]byte(`{"body":{"seq":1},"hash":"00"}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := Verify(bytes.NewReader(data), pub)
		if err == nil && rep.Records > 0 && rep.LastHash == "" {
			t.Fatal("verified chain without last hash")
		}
	})
}

func BenchmarkAppend(b *testing.B) {
	path := filepath.Join(b.TempDir(), "audit.jsonl")
	l, err := Open(
		Options{
			Path:          path,
			ChainID:       "bench",
			Buffer:        1 << 16,
			BatchSize:     512,
			FlushInterval: 50 * time.Millisecond,
			Fsync:         true,
		},
	)
	if err != nil {
		b.Fatal(err)
	}
	e := Event{
		Phase: PhaseOutcome, RequestID: "0123456789abcdef01234567", Subject: "alice", ClientID: "demo",
		Method: "tools/call", Tool: "notes__search", Upstream: "notes", Decision: DecisionAllow, Rule: "readers",
		ArgsHash: ZeroHash, ResultHash: ZeroHash, LatencyMicros: 250,
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := l.Append(b.Context(), e); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := l.Close(); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkSeal(b *testing.B) {
	body := Body{
		Seq:     1,
		TS:      1,
		ChainID: "bench",
		Prev:    ZeroHash,
		Event:   &Event{Method: "tools/call", Tool: "notes__search", Decision: DecisionAllow},
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Seal(&body); err != nil {
			b.Fatal(err)
		}
	}
}
