package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type p256Signer struct {
	priv  *ecdsa.PrivateKey
	keyID string
}

func newP256Signer(t *testing.T) *p256Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p256: %v", err)
	}
	id, err := KeyIDFor(&priv.PublicKey)
	if err != nil {
		t.Fatalf("key id: %v", err)
	}
	return &p256Signer{priv: priv, keyID: id}
}

func (s *p256Signer) KeyID() string               { return s.keyID }
func (s *p256Signer) PublicKey() crypto.PublicKey { return &s.priv.PublicKey }
func (s *p256Signer) Algorithm() string           { return AlgECDSAP256 }

func (s *p256Signer) Sign(_ context.Context, msg []byte) ([]byte, error) {
	sum := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, s.priv, sum[:])
}

type failingSigner struct {
	CheckpointSigner
	err error
}

func (f failingSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, f.err
}

func newEdSigner(t *testing.T) (*LocalSigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	s, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("new local signer: %v", err)
	}
	return s, pub
}

func TestRotateSignerMultiHopEd25519AndP256(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	s1, pub1 := newEdSigner(t)
	s2 := newP256Signer(t)
	s3, _ := newEdSigner(t)

	var seenKinds []string
	l, err := OpenContext(ctx, Options{
		Path:             path,
		ChainID:          "rot-chain",
		CheckpointSigner: s1,
		CheckpointEvery:  10,
		FlushInterval:    10 * time.Millisecond,
		Committed: func(rows []Row) {
			for _, r := range rows {
				seenKinds = append(seenKinds, r.Kind)
			}
		},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if l.ActiveKeyID() != s1.KeyID() {
		t.Fatalf("active key id = %q, want %q", l.ActiveKeyID(), s1.KeyID())
	}

	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "r1", Method: "tools/call", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if err := l.RotateSigner(ctx, s2); err != nil {
		t.Fatalf("rotate 1->2: %v", err)
	}
	if l.ActiveKeyID() != s2.KeyID() {
		t.Fatalf("active key id after 1->2 = %q, want %q", l.ActiveKeyID(), s2.KeyID())
	}

	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "r2", Method: "tools/call", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if err := l.RotateSigner(ctx, s3); err != nil {
		t.Fatalf("rotate 2->3: %v", err)
	}
	if l.ActiveKeyID() != s3.KeyID() {
		t.Fatalf("active key id after 2->3 = %q, want %q", l.ActiveKeyID(), s3.KeyID())
	}

	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "r3", Method: "tools/call", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 3: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	rep, err := Verify(f, pub1)
	if err != nil {
		t.Fatalf("verify from root pub1: %v", err)
	}
	if rep.Events != 3 {
		t.Fatalf("events = %d, want 3", rep.Events)
	}
	if rep.KeyRotations != 2 {
		t.Fatalf("rotations = %d, want 2", rep.KeyRotations)
	}
	if rep.UnsignedTail != 0 {
		t.Fatalf("unsigned tail = %d, want 0", rep.UnsignedTail)
	}
	if rep.Checkpoints < 4 {
		t.Fatalf("checkpoints = %d, want >= 4", rep.Checkpoints)
	}
	rotRows := 0
	for _, k := range seenKinds {
		if k == KindKeyRotation {
			rotRows++
		}
	}
	if rotRows != 2 {
		t.Fatalf("committed key_rotation rows = %d, want 2", rotRows)
	}
}

func TestRotateSignerRollbackOnFailure(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	s1, pub1 := newEdSigner(t)
	s2 := newP256Signer(t)
	wantErr := errors.New("kms unavailable")

	l, err := OpenContext(ctx, Options{
		Path:             path,
		ChainID:          "rollback-chain",
		CheckpointSigner: s1,
		CheckpointEvery:  10,
		FlushInterval:    10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "r1", Method: "tools/call", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if err := l.RotateSigner(ctx, failingSigner{CheckpointSigner: s2, err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("rotate with failing next signer = %v, want %v", err, wantErr)
	}
	if l.ActiveKeyID() != s1.KeyID() {
		t.Fatalf("active key changed on failed rotate: %q != %q", l.ActiveKeyID(), s1.KeyID())
	}
	if err := l.Append(
		ctx,
		Event{Phase: PhaseDecision, RequestID: "r2", Method: "tools/call", Decision: DecisionAllow},
	); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	rep, err := Verify(f, pub1)
	if err != nil {
		t.Fatalf("verify after rollback: %v", err)
	}
	if rep.Events != 2 || rep.KeyRotations != 0 || rep.UnsignedTail != 0 {
		t.Fatalf("unexpected report after rollback: %+v", rep)
	}
}

func TestRotateSignerErrors(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("no_signer", func(t *testing.T) {
		t.Parallel()
		l, err := OpenContext(ctx, Options{Path: filepath.Join(t.TempDir(), "a.jsonl"), ChainID: "c"})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer l.Close()
		s, _ := newEdSigner(t)
		if err := l.RotateSigner(ctx, s); !errors.Is(err, ErrNoSigner) {
			t.Fatalf("got %v, want ErrNoSigner", err)
		}
	})

	t.Run("same_key", func(t *testing.T) {
		t.Parallel()
		s, _ := newEdSigner(t)
		l, err := OpenContext(ctx, Options{
			Path:             filepath.Join(t.TempDir(), "a.jsonl"),
			ChainID:          "c",
			CheckpointSigner: s,
		})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer l.Close()
		if err := l.RotateSigner(ctx, s); !errors.Is(err, ErrSameKey) {
			t.Fatalf("got %v, want ErrSameKey", err)
		}
	})

	t.Run("nil_next", func(t *testing.T) {
		t.Parallel()
		s, _ := newEdSigner(t)
		l, err := OpenContext(ctx, Options{
			Path:             filepath.Join(t.TempDir(), "a.jsonl"),
			ChainID:          "c",
			CheckpointSigner: s,
		})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer l.Close()
		if err := l.RotateSigner(ctx, nil); !errors.Is(err, ErrNoSigner) {
			t.Fatalf("got %v, want ErrNoSigner", err)
		}
	})
}

func TestVerifyRejectsForgedKeyRotation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	s1, pub1 := newEdSigner(t)
	s2, _ := newEdSigner(t)
	rogue, _ := newEdSigner(t)

	kr, err := SignKeyRotation(ctx, rogue, s2, "c")
	if err != nil {
		t.Fatalf("sign rotation: %v", err)
	}
	kr.PrevKeyID = s1.KeyID()

	var buf bytes.Buffer
	prev := ZeroHash
	writeRec := func(seq uint64, b *Body) {
		b.Seq = seq
		b.TS = time.Now().UnixNano()
		b.ChainID = "c"
		b.Prev = prev
		rec, err := Seal(b)
		if err != nil {
			t.Fatalf("seal %d: %v", seq, err)
		}
		prev = rec.Hash
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal %d: %v", seq, err)
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}

	writeRec(
		1,
		&Body{Event: &Event{Phase: PhaseDecision, RequestID: "r1", Method: "tools/call", Decision: DecisionAllow}},
	)
	writeRec(2, &Body{KeyRotation: kr})

	_, err = Verify(&buf, pub1)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("verify forged rotation = %v, want ErrTampered", err)
	}
	if !strings.Contains(err.Error(), "invalid key rotation") {
		t.Fatalf("unexpected error reason: %v", err)
	}
}

func TestLoadKeySetDirSupportsEd25519AndP256(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, edPubPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k1.pub"), edPubPEM, 0o600); err != nil {
		t.Fatalf("write k1: %v", err)
	}

	p256 := newP256Signer(t)
	der, err := x509.MarshalPKIXPublicKey(p256.PublicKey())
	if err != nil {
		t.Fatalf("marshal p256: %v", err)
	}
	p256PEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "k2.pem"), p256PEM, 0o600); err != nil {
		t.Fatalf("write k2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write ignored: %v", err)
	}

	ks, err := LoadKeySetDir(dir)
	if err != nil {
		t.Fatalf("load key set dir: %v", err)
	}
	if ks.Len() != 2 {
		t.Fatalf("keyset len = %d, want 2", ks.Len())
	}
	if _, ok := ks.Lookup(p256.KeyID()); !ok {
		t.Fatalf("p256 key %q missing from keyset", p256.KeyID())
	}
}
