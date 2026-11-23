package audit

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildSignedChain(t *testing.T, events int) (logPath string, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	privPEM, pubPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err = ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(Options{
		Path:            logPath,
		ChainID:         "recovery-chain",
		Signer:          priv,
		FlushInterval:   time.Millisecond,
		CheckpointEvery: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range events {
		if err := l.Append(t.Context(), Event{
			Phase:    PhaseIntent,
			Method:   "tools/call",
			Tool:     "notes__search",
			Subject:  "alice",
			Decision: DecisionAllow,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return logPath, priv, pub
}

func TestRepairTailRecoversFromPowerLossAndContinuesChain(t *testing.T) {
	t.Parallel()
	logPath, priv, pub := buildSignedChain(t, 4)

	torn := `{"body":{"chain_id":"recovery-chain","seq":99,"ts":170000`
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(torn); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(Options{Path: logPath, ChainID: "recovery-chain", Signer: priv}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open with torn tail = %v, want ErrMalformed", err)
	}

	rep, err := RepairTail(logPath, VerifyOptions{PublicKey: pub})
	if err != nil {
		t.Fatalf("RepairTail failed: %v", err)
	}
	if rep.TruncatedBytes != int64(len(torn)) {
		t.Fatalf("truncated %d bytes, want %d", rep.TruncatedBytes, len(torn))
	}
	backup, err := os.ReadFile(rep.BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != torn {
		t.Fatalf("backup = %q, want %q", string(backup), torn)
	}

	resumed, err := Open(Options{
		Path:            logPath,
		ChainID:         "recovery-chain",
		Signer:          priv,
		FlushInterval:   time.Millisecond,
		CheckpointEvery: 1,
	})
	if err != nil {
		t.Fatalf("Open after repair failed: %v", err)
	}
	if err := resumed.Append(t.Context(), Event{
		Phase:    PhaseOutcome,
		Method:   "tools/call",
		Tool:     "notes__search",
		Subject:  "bob",
		Decision: DecisionAllow,
	}); err != nil {
		t.Fatal(err)
	}
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}

	vf, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer vf.Close()
	finalRep, err := Verify(vf, pub)
	if err != nil {
		t.Fatalf("Verify after resumed writes failed: %v", err)
	}
	if finalRep.Events != 5 || finalRep.Checkpoints < 2 {
		t.Fatalf("unexpected final report: %+v", finalRep)
	}
}

func TestRepairTailRefusesTamperedMiddleRecord(t *testing.T) {
	t.Parallel()
	logPath, _, pub := buildSignedChain(t, 4)

	orig, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(orig), `"sub":"alice"`, `"sub":"eve"`, 1)
	if tampered == string(orig) {
		t.Fatal("failed to tamper record")
	}
	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RepairTail(logPath, VerifyOptions{PublicKey: pub}); !errors.Is(err, ErrUnrecoverable) {
		t.Fatalf("RepairTail(mid-file tamper) = %v, want ErrUnrecoverable", err)
	}
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != tampered {
		t.Fatal("RepairTail modified file on unrecoverable tampering")
	}
}

func TestRepairTailRefusesTamperedFinalRecord(t *testing.T) {
	t.Parallel()
	logPath, _, pub := buildSignedChain(t, 2)

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	lastIdx := len(lines) - 1
	lines[lastIdx] = bytes.Replace(lines[lastIdx], []byte(`"recovery-chain"`), []byte(`"forged-chain"`), 1)
	corrupted := append(bytes.Join(lines, []byte("\n")), '\n')
	if err := os.WriteFile(logPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RepairTail(logPath, VerifyOptions{PublicKey: pub}); !errors.Is(err, ErrUnrecoverable) {
		t.Fatalf("RepairTail(tampered complete final record) = %v, want ErrUnrecoverable", err)
	}
}

func TestRepairTailRefusesSequenceGap(t *testing.T) {
	t.Parallel()
	logPath, _, pub := buildSignedChain(t, 4)

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	withoutMiddle := append(append([][]byte(nil), lines[:1]...), lines[2:]...)
	gapped := append(bytes.Join(withoutMiddle, []byte("\n")), '\n')
	if err := os.WriteFile(logPath, gapped, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RepairTail(logPath, VerifyOptions{PublicKey: pub}); !errors.Is(err, ErrUnrecoverable) {
		t.Fatalf("RepairTail(sequence gap) = %v, want ErrUnrecoverable", err)
	}
}

func TestRepairTailNoopOnHealthyChain(t *testing.T) {
	t.Parallel()
	logPath, _, pub := buildSignedChain(t, 2)

	rep, err := RepairTail(logPath, VerifyOptions{PublicKey: pub})
	if err != nil {
		t.Fatalf("RepairTail on healthy chain failed: %v", err)
	}
	if rep.TruncatedBytes != 0 || rep.BackupPath != "" {
		t.Fatalf("healthy chain should be a no-op, got %+v", rep)
	}
}

func TestOpenRefusesWrongChainID(t *testing.T) {
	t.Parallel()
	logPath, priv, _ := buildSignedChain(t, 2)

	_, err := Open(Options{
		Path:    logPath,
		ChainID: "different-chain",
		Signer:  priv,
	})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open with mismatched chain_id = %v, want ErrMalformed", err)
	}
}
