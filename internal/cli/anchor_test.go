package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor/rekortest"
)

type logSink struct{ l *audit.Log }

func (s *logSink) AppendAnchor(r audit.CheckpointRef, a *audit.Anchor) error {
	return s.l.AppendAnchor(r, a)
}

type anchoredLog struct {
	path, pub, root string
	witnesses       []string
}

func writeAnchoredLog(t *testing.T, witnessDelay time.Duration) anchoredLog {
	t.Helper()
	dir := t.TempDir()
	privPEM, pubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := audit.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	s := rekortest.New(t, rekortest.WithClock(func() time.Time { return time.Now().Add(witnessDelay) }),
		rekortest.WithWitness("w1.example"))
	al := anchoredLog{
		path: filepath.Join(dir, "audit.jsonl"), pub: filepath.Join(dir, "k.pub"),
		root: filepath.Join(dir, "trusted_root.json"), witnesses: s.WitnessVKeys(),
	}
	for p, b := range map[string][]byte{al.pub: pubPEM, al.root: s.TrustedRootJSON()} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	trust, err := anchor.LoadTrust([]string{al.root}, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := anchor.NewClient(s.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &logSink{}
	got := make(chan struct{}, 16)
	an, err := anchor.New(anchor.Options{
		ChainID: "c", Key: priv, Every: 1, Timeout: 5 * time.Second, Verifier: anchor.NewReceiptVerifier(trust),
		Hooks: anchor.Hooks{Anchored: func(uint64, time.Time) { got <- struct{}{} }},
	}, c, sink)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(audit.Options{
		Path: al.path, ChainID: "c", BatchSize: 2, FlushInterval: time.Millisecond, Signer: priv,
		CheckpointEvery: 2, CheckpointCommitted: an.Offer,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink.l = l
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		an.Run(ctx)
	}()
	for range 4 {
		if err := l.Append(
			t.Context(),
			audit.Event{Phase: audit.PhaseOutcome, Method: "m", Decision: "allow"},
		); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("no anchor")
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	for range 3 {
		if err := l.Append(
			t.Context(),
			audit.Event{Phase: audit.PhaseOutcome, Method: "m", Decision: "allow"},
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return al
}

func TestVerifyAnchorsCLI(t *testing.T) {
	t.Parallel()
	al := writeAnchoredLog(t, 0)
	slow := writeAnchoredLog(t, time.Hour)
	base := func(a anchoredLog) verifyOpts {
		return verifyOpts{file: a.path, pubkey: a.pub, maxUnsigned: 1000, rekorTrust: []string{a.root}}
	}
	withWitness := func(o verifyOpts, a anchoredLog) verifyOpts {
		o.witnesses, o.minWitnesses = a.witnesses, 1
		return o
	}
	cases := []struct {
		name string
		o    verifyOpts
		ok   bool
		want string
	}{
		{"anchors verified", withWitness(base(al), al), true, "ANCHORED anchors="},
		{
			"unverified warns",
			verifyOpts{file: al.path, pubkey: al.pub, maxUnsigned: 1000},
			true,
			"WARN 1 anchors not verified",
		},
		{
			"require anchors",
			func() verifyOpts { o := base(al); o.requireAnchors = true; return o }(),
			true,
			"anchored_seq=",
		},
		{
			"max unanchored",
			func() verifyOpts { o := base(al); o.maxUnanchored = 1; return o }(),
			false,
			"exceed --max-unanchored",
		},
		{"late witness", func() verifyOpts {
			o := withWitness(base(slow), slow)
			o.maxAnchorDelay = time.Minute
			return o
		}(), false, "--max-anchor-delay"},
		{
			"delay needs witnesses",
			func() verifyOpts { o := base(al); o.maxAnchorDelay = time.Minute; return o }(),
			false,
			"needs --min-witnesses",
		},
		{
			"require needs trust",
			verifyOpts{file: al.path, pubkey: al.pub, requireAnchors: true},
			false,
			"need --rekor-trust",
		},
		{
			"trust needs key",
			verifyOpts{file: al.path, noSignatures: true, rekorTrust: []string{al.root}},
			false,
			"needs --pubkey",
		},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		err := runVerify(&out, tc.o)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v out=%s", tc.name, err, out.String())
			continue
		}
		if !tc.ok && !errors.Is(err, ErrVerify) {
			t.Errorf("%s: expected ErrVerify, got %v", tc.name, err)
		}
		got := out.String()
		if err != nil {
			got += err.Error()
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: output %q missing %q", tc.name, got, tc.want)
		}
	}
}

func TestVerifyAnchorsFailAgainstOtherLog(t *testing.T) {
	t.Parallel()
	al := writeAnchoredLog(t, 0)
	other := rekortest.New(t)
	root := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(root, other.TrustedRootJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runVerify(&out, verifyOpts{file: al.path, pubkey: al.pub, maxUnsigned: 1000, rekorTrust: []string{root}})
	if err == nil || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("anchors from an untrusted log passed: %v %s", err, out.String())
	}
}
