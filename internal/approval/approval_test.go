package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

func TestApprovalSignVerifyAndSecurityChecks(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := NewKeySet(pub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	verifier := NewVerifier(VerifierOptions{
		Keys:      ks,
		Issuer:    "https://approvals.example.com",
		Audience:  "https://gw.example.com/mcp",
		MaxTTL:    10 * time.Minute,
		ClockSkew: 30 * time.Second,
		Now:       func() time.Time { return now },
	})

	argsA := json.RawMessage(`{"path":"/important","force":true}`)
	argsReordered := json.RawMessage(`{ "force" : true , "path" : "/important" }`)
	argsTampered := json.RawMessage(`{"path":"/etc/shadow","force":true}`)

	tok, err := Sign(priv, Claims{
		Issuer:    "https://approvals.example.com",
		Audience:  "https://gw.example.com/mcp",
		Subject:   "alice",
		Tenant:    "acme",
		Approver:  "bob@corp.com",
		Tool:      "files__delete_file",
		ArgsHash:  CanonicalArgsHash(argsA),
		Reason:    "CHG-1042",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := verifier.Verify(VerifyRequest{
		Token:   tok,
		Subject: "alice",
		Tenant:  "acme",
		Tool:    "files__delete_file",
		Args:    argsReordered,
	})
	if err != nil {
		t.Fatalf("expected valid approval with reordered JSON args, got %v", err)
	}
	if got.Approver != "bob@corp.com" || got.Reason != "CHG-1042" || got.ID == "" {
		t.Fatalf("unexpected verified claims: %+v", got)
	}

	cases := []struct {
		name    string
		req     VerifyRequest
		wantErr error
	}{
		{
			name: "tampered_args",
			req: VerifyRequest{
				Token: tok, Subject: "alice", Tenant: "acme", Tool: "files__delete_file", Args: argsTampered,
			},
			wantErr: ErrOperationMismatch,
		},
		{
			name: "wrong_tool",
			req: VerifyRequest{
				Token: tok, Subject: "alice", Tenant: "acme", Tool: "files__write_file", Args: argsA,
			},
			wantErr: ErrOperationMismatch,
		},
		{
			name: "wrong_subject",
			req: VerifyRequest{
				Token: tok, Subject: "mallory", Tenant: "acme", Tool: "files__delete_file", Args: argsA,
			},
			wantErr: ErrSubjectMismatch,
		},
		{
			name: "wrong_tenant",
			req: VerifyRequest{
				Token: tok, Subject: "alice", Tenant: "globex", Tool: "files__delete_file", Args: argsA,
			},
			wantErr: ErrTenantMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, verr := verifier.Verify(tc.req)
			if !errors.Is(verr, tc.wantErr) {
				t.Fatalf("got error %v, want %v", verr, tc.wantErr)
			}
		})
	}

	untrustedTok, err := Sign(otherPriv, Claims{
		Issuer:    "https://approvals.example.com",
		Audience:  "https://gw.example.com/mcp",
		Subject:   "alice",
		Tenant:    "acme",
		Approver:  "bob@corp.com",
		Tool:      "files__delete_file",
		ArgsHash:  CanonicalArgsHash(argsA),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(VerifyRequest{
		Token: untrustedTok, Subject: "alice", Tenant: "acme", Tool: "files__delete_file", Args: argsA,
	}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("expected ErrUntrustedKey, got %v", err)
	}

	longTok, err := Sign(priv, Claims{
		Issuer:    "https://approvals.example.com",
		Audience:  "https://gw.example.com/mcp",
		Subject:   "alice",
		Tenant:    "acme",
		Approver:  "bob@corp.com",
		Tool:      "files__delete_file",
		ArgsHash:  CanonicalArgsHash(argsA),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(20 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(VerifyRequest{
		Token: longTok, Subject: "alice", Tenant: "acme", Tool: "files__delete_file", Args: argsA,
	}); !errors.Is(err, ErrTTLTooLong) {
		t.Fatalf("expected ErrTTLTooLong, got %v", err)
	}

	expiredTok, err := Sign(priv, Claims{
		Issuer:    "https://approvals.example.com",
		Audience:  "https://gw.example.com/mcp",
		Subject:   "alice",
		Tenant:    "acme",
		Approver:  "bob@corp.com",
		Tool:      "files__delete_file",
		ArgsHash:  CanonicalArgsHash(argsA),
		IssuedAt:  now.Add(-5 * time.Minute).Unix(),
		ExpiresAt: now.Add(-1 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(VerifyRequest{
		Token: expiredTok, Subject: "alice", Tenant: "acme", Tool: "files__delete_file", Args: argsA,
	}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestApprovalBatchAndKeyDirLoading(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv1PEM, pub1PEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pub2PEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k1.pub"), pub1PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k2.pem"), pub2PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := LoadKeySet(nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Len() != 2 {
		t.Fatalf("expected 2 keys loaded from dir, got %d", ks.Len())
	}
	priv1, err := audit.ParsePrivateKey(priv1PEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	tok, err := Sign(priv1, Claims{
		Audience: "https://gw.example.com/mcp",
		Subject:  "alice",
		Approver: "carol@corp.com",
		Batch: []BatchItem{
			{Tool: "files__delete_file", ArgsHash: CanonicalArgsHash(json.RawMessage(`{"path":"/a"}`))},
			{Tool: "files__delete_file", ArgsHash: CanonicalArgsHash(json.RawMessage(`{"path":"/b"}`))},
		},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(VerifierOptions{
		Keys:     ks,
		Audience: "https://gw.example.com/mcp",
		Now:      func() time.Time { return now },
	})
	if _, err := v.Verify(VerifyRequest{
		Token: tok, Subject: "alice", Tool: "files__delete_file", Args: json.RawMessage(`{"path":"/b"}`),
	}); err != nil {
		t.Fatalf("batch item /b should verify: %v", err)
	}
	if _, err := v.Verify(VerifyRequest{
		Token: tok, Subject: "alice", Tool: "files__delete_file", Args: json.RawMessage(`{"path":"/c"}`),
	}); !errors.Is(err, ErrOperationMismatch) {
		t.Fatalf("unlisted item /c should fail with ErrOperationMismatch, got %v", err)
	}
}

func TestReplayStoresMemoryAndRedis(t *testing.T) {
	t.Parallel()
	t.Run("memory", func(t *testing.T) {
		t.Parallel()
		clock := time.Unix(1_700_000_000, 0)
		store := NewMemoryReplayStore(100, func() time.Time { return clock })
		k := ReplayKey("apr_1", "files__delete", "sha256:aaa")
		ok, err := store.Consume(t.Context(), k, 10*time.Second)
		if err != nil || !ok {
			t.Fatalf("first consume failed: ok=%v err=%v", ok, err)
		}
		ok, err = store.Consume(t.Context(), k, 10*time.Second)
		if err != nil || ok {
			t.Fatalf("second consume must fail: ok=%v err=%v", ok, err)
		}
		clock = clock.Add(11 * time.Second)
		if swept := store.Sweep(); swept != 1 {
			t.Fatalf("expected 1 swept entry, got %d", swept)
		}
		ok, err = store.Consume(t.Context(), k, 10*time.Second)
		if err != nil || !ok {
			t.Fatalf("consume after expiry failed: ok=%v err=%v", ok, err)
		}
	})

	t.Run("redis", func(t *testing.T) {
		t.Parallel()
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: 0})
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("close redis: %v", err)
			}
		})
		store := NewRedisReplayStore(client, "tk:test:apr:", 200*time.Millisecond)
		k := ReplayKey("apr_2", "files__delete", "sha256:bbb")
		ok, err := store.Consume(t.Context(), k, 10*time.Second)
		if err != nil || !ok {
			t.Fatalf("first redis consume failed: ok=%v err=%v", ok, err)
		}
		ok, err = store.Consume(t.Context(), k, 10*time.Second)
		if err != nil || ok {
			t.Fatalf("second redis consume must fail: ok=%v err=%v", ok, err)
		}
		mr.FastForward(11 * time.Second)
		ok, err = store.Consume(t.Context(), k, 10*time.Second)
		if err != nil || !ok {
			t.Fatalf("redis consume after TTL failed: ok=%v err=%v", ok, err)
		}
	})
}
