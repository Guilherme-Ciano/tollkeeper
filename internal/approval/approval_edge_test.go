package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

func TestApprovalEdgeCasesAndErrorPaths(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var nilKS *KeySet
	if nilKS.Len() != 0 {
		t.Fatal("nil KeySet should have Len 0")
	}
	if _, err := NewKeySet(ed25519.PublicKey("short")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed for short pubkey, got %v", err)
	}
	ks, err := NewKeySet(pub, pub)
	if err != nil || ks.Len() != 1 {
		t.Fatalf("duplicate pubkey should dedupe: len=%d err=%v", ks.Len(), err)
	}

	emptyDir := t.TempDir()
	if _, err := LoadKeySet(nil, emptyDir); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("expected ErrUntrustedKey for empty dir, got %v", err)
	}
	if _, err := LoadKeySet([]string{filepath.Join(emptyDir, "missing.pub")}, ""); err == nil {
		t.Fatal("expected error for missing pubkey file")
	}
	if err := os.Mkdir(filepath.Join(emptyDir, "subdir"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emptyDir, "notes.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, pubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	validFile := filepath.Join(emptyDir, "one.pub")
	if err := os.WriteFile(validFile, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeySet([]string{validFile}, emptyDir)
	if err != nil || loaded.Len() != 1 {
		t.Fatalf("LoadKeySet file+dir failed: len=%d err=%v", loaded.Len(), err)
	}

	if CanonicalArgsHash(nil) != CanonicalArgsHash(json.RawMessage(`{}`)) {
		t.Fatal("empty args should hash identically to {}")
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	if _, err := Sign(ed25519.PrivateKey("bad"), Claims{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short privkey: %v", err)
	}
	badClaims := []Claims{
		{Audience: "a", IssuedAt: 1, ExpiresAt: 2, Tool: "t", ArgsHash: "sha256:aa"},
		{Approver: "b", IssuedAt: 1, ExpiresAt: 2, Tool: "t", ArgsHash: "sha256:aa"},
		{Approver: "b", Audience: "a", IssuedAt: 10, ExpiresAt: 5, Tool: "t", ArgsHash: "sha256:aa"},
		{Approver: "b", Audience: "a", IssuedAt: 1, ExpiresAt: 2},
		{Approver: "b", Audience: "a", IssuedAt: 1, ExpiresAt: 2, Batch: []BatchItem{{Tool: "t", ArgsHash: "md5:1"}}},
	}
	for i, c := range badClaims {
		if _, err := Sign(priv, c); !errors.Is(err, ErrMalformed) {
			t.Fatalf("badClaims[%d]: expected ErrMalformed, got %v", i, err)
		}
	}

	var nilVerifier *Verifier
	if _, err := nilVerifier.Verify(VerifyRequest{Token: "a.b.c"}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("nil verifier should return ErrUntrustedKey, got %v", err)
	}

	v := NewVerifier(VerifierOptions{
		Keys:      ks,
		Issuer:    "https://iss.example",
		Audience:  "https://aud.example",
		ClockSkew: -1,
		Now:       func() time.Time { return now },
	})
	for _, badTok := range []string{
		"",
		"not-a-jwt",
		strings.Repeat("a", maxTokenBytes+1),
		"!!!.bbb.ccc",
		base64.RawURLEncoding.EncodeToString([]byte(`{bad`)) + ".e30." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"tk-approval+jwt"}`)) + ".e30." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"tk-approval+jwt"}`)) + ".!!!." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"tk-approval+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{bad`)) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"tk-approval+jwt"}`)) + ".e30.short",
	} {
		if _, err := v.Verify(VerifyRequest{Token: badTok}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("token %q: expected ErrMalformed, got %v", badTok[:min(len(badTok), 20)], err)
		}
	}

	hdrNoKid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"tk-approval+jwt"}`))
	claimsBytes, err := json.Marshal(Claims{
		JTI: "j1", Issuer: "https://iss.example", Audience: "https://aud.example",
		Subject: "alice", Approver: "bob", Tool: "t", ArgsHash: CanonicalArgsHash(nil),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(priv, []byte(hdrNoKid+"."+payloadEnc))
	tokNoKid := hdrNoKid + "." + payloadEnc + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := v.Verify(VerifyRequest{Token: tokNoKid, Subject: "alice", Tool: "t"}); err != nil {
		t.Fatalf("valid token without kid should verify: %v", err)
	}
	sig[0] ^= 0xff
	badSigTok := hdrNoKid + "." + payloadEnc + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := v.Verify(
		VerifyRequest{Token: badSigTok, Subject: "alice", Tool: "t"},
	); !errors.Is(
		err,
		ErrInvalidSignature,
	) {
		t.Fatalf("expected ErrInvalidSignature without kid, got %v", err)
	}

	wrongIss, err := Sign(priv, Claims{
		Issuer: "https://other.example", Audience: "https://aud.example", Subject: "alice",
		Approver: "bob", Tool: "t", ArgsHash: CanonicalArgsHash(nil),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(
		VerifyRequest{Token: wrongIss, Subject: "alice", Tool: "t"},
	); !errors.Is(
		err,
		ErrIssuerMismatch,
	) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}

	wrongAud, err := Sign(priv, Claims{
		Issuer: "https://iss.example", Audience: "https://wrong.example", Subject: "alice",
		Approver: "bob", Tool: "t", ArgsHash: CanonicalArgsHash(nil),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(
		VerifyRequest{Token: wrongAud, Subject: "alice", Tool: "t"},
	); !errors.Is(
		err,
		ErrAudienceMismatch,
	) {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestReplayStoreEvictionJanitorAndRedisError(t *testing.T) {
	t.Parallel()
	clock := time.Unix(1_700_000_000, 0)
	store := NewMemoryReplayStore(100, func() time.Time { return clock })
	for i := range 105 {
		clock = clock.Add(time.Millisecond)
		ok, err := store.Consume(t.Context(), "k-"+strconv.Itoa(i), time.Hour)
		if err != nil || !ok {
			t.Fatalf("consume %d failed: ok=%v err=%v", i, ok, err)
		}
	}
	if len(store.entries) > 100 {
		t.Fatalf("expected bounded entries <= 100, got %d", len(store.entries))
	}

	defStore := NewMemoryReplayStore(10, nil)
	if defStore.maxEntries != defaultReplayMaxEntries {
		t.Fatalf("expected default maxEntries, got %d", defStore.maxEntries)
	}
	if ok, err := defStore.Consume(t.Context(), "zero-ttl", 0); err != nil || !ok {
		t.Fatalf("zero ttl consume failed: ok=%v err=%v", ok, err)
	}

	jctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		store.RunJanitor(jctx, 5*time.Millisecond)
		close(done)
	}()
	time.Sleep(15 * time.Millisecond)
	cancel()
	<-done

	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond, MaxRetries: 0})
	t.Cleanup(func() {
		if err := dead.Close(); err != nil {
			t.Errorf("close dead redis: %v", err)
		}
	})
	rstore := NewRedisReplayStore(dead, "", 0)
	if _, err := rstore.Consume(t.Context(), "k", 0); err == nil {
		t.Fatal("expected error from unreachable redis")
	}
}
