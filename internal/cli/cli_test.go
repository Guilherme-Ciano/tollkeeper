package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

func writeChain(t *testing.T, dir string, signed bool) (logPath, pubPath string) {
	t.Helper()
	privPEM, pubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubPath = filepath.Join(dir, "audit.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	priv, err := audit.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(dir, "audit.jsonl")
	opts := audit.Options{Path: logPath, ChainID: "c", FlushInterval: time.Millisecond}
	if signed {
		opts.Signer = priv
	}
	l, err := audit.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := l.Append(t.Context(), audit.Event{Method: "m", Decision: audit.DecisionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return logPath, pubPath
}

func TestVerifyCLI(t *testing.T) {
	t.Parallel()
	signedLog, pub := writeChain(t, t.TempDir(), true)
	unsignedLog, pub2 := writeChain(t, t.TempDir(), false)
	cases := []struct {
		name string
		o    verifyOpts
		ok   bool
		want string
	}{
		{"signed ok", verifyOpts{file: signedLog, pubkey: pub, maxUnsigned: 0}, true, "OK chain=c"},
		{"pubkey required", verifyOpts{file: signedLog}, false, "pass --pubkey"},
		{
			"stripped signatures fail",
			verifyOpts{file: unsignedLog, pubkey: pub2, maxUnsigned: 1000},
			false,
			"no signed checkpoint",
		},
		{
			"hash chain only on request",
			verifyOpts{file: unsignedLog, noSignatures: true},
			true,
			"WARN signatures not checked",
		},
		{"chain id pinned", verifyOpts{file: signedLog, pubkey: pub, chainID: "other"}, false, "chain id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := runVerify(&out, tc.o)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v out=%s", err, out.String())
			}
			if !tc.ok && !errors.Is(err, ErrVerify) {
				t.Fatalf("expected ErrVerify, got %v", err)
			}
			got := out.String()
			if err != nil {
				got += err.Error()
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("output %q missing %q", got, tc.want)
			}
		})
	}
}
