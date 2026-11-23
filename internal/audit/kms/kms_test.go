package kms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/netguard"
)

func writeJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func TestVaultSignerEd25519AndEndToEndAudit(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}

	var gotNamespace string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "root-tok" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		gotNamespace = r.Header.Get("X-Vault-Namespace")
		switch r.URL.Path {
		case "/v1/custom-transit/keys/audit-key":
			resp := map[string]any{
				"data": map[string]any{
					"type":           "ed25519",
					"latest_version": 2,
					"keys": map[string]any{
						"2": map[string]any{
							"public_key": base64.StdEncoding.EncodeToString(pub),
						},
					},
				},
			}
			writeJSON(w, resp)
		case "/v1/custom-transit/sign/audit-key":
			var req vaultSignReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			msg, err := base64.StdEncoding.DecodeString(req.Input)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sig := ed25519.Sign(priv, msg)
			writeJSON(w, map[string]any{
				"data": map[string]any{
					"signature": "vault:v2:" + base64.StdEncoding.EncodeToString(sig),
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	signer, err := NewVaultSigner(ctx, VaultOptions{
		Address:   srv.URL,
		Mount:     "custom-transit",
		KeyID:     "audit-key",
		Token:     "root-tok",
		Namespace: "sec-ops",
	})
	if err != nil {
		t.Fatalf("new vault signer: %v", err)
	}
	if gotNamespace != "sec-ops" {
		t.Fatalf("namespace = %q, want sec-ops", gotNamespace)
	}
	if signer.Algorithm() != audit.AlgEd25519 {
		t.Fatalf("alg = %q, want %q", signer.Algorithm(), audit.AlgEd25519)
	}

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.OpenContext(ctx, audit.Options{
		Path:             logPath,
		ChainID:          "vault-ed25519",
		CheckpointSigner: signer,
		CheckpointEvery:  1,
		FlushInterval:    10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	if err := l.Append(ctx, audit.Event{
		Phase: audit.PhaseDecision, RequestID: "r1", Method: "tools/call", Decision: audit.DecisionAllow,
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	rep, err := audit.Verify(f, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Events != 1 || rep.Checkpoints == 0 || rep.UnsignedTail != 0 {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

func TestVaultSignerECDSAP256(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys/p256-key":
			writeJSON(w, map[string]any{
				"data": map[string]any{
					"type":           "ecdsa-p256",
					"latest_version": 1,
					"keys": map[string]any{
						"1": map[string]any{"public_key": pubPEM},
					},
				},
			})
		case "/v1/transit/sign/p256-key":
			var req vaultSignReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.HashAlgorithm != "sha2-256" || req.MarshalingAlgorithm != "asn1" {
				http.Error(w, "missing p256 sign options", http.StatusBadRequest)
				return
			}
			msg, err := base64.StdEncoding.DecodeString(req.Input)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256(msg)
			sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{
				"data": map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	signer, err := NewVaultSigner(ctx, VaultOptions{
		Address: srv.URL,
		KeyID:   "p256-key",
		Token:   "tok",
	})
	if err != nil {
		t.Fatalf("new vault p256 signer: %v", err)
	}
	if signer.Algorithm() != audit.AlgECDSAP256 {
		t.Fatalf("alg = %q, want %q", signer.Algorithm(), audit.AlgECDSAP256)
	}
	ck, err := audit.SignCheckpointWith(ctx, signer, "c", 1, audit.ZeroHash)
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	if !audit.VerifyCheckpointAny(&priv.PublicKey, "c", ck) {
		t.Fatal("p256 checkpoint failed verification")
	}
}

func TestAWSSignerSigV4AndLiveKeyRotation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}

	fixedNow := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20261123/us-east-1/kms/aws4_request,") {
			http.Error(w, "bad sigv4 credential: "+auth, http.StatusForbidden)
			return
		}
		if r.Header.Get("X-Amz-Date") != "20261123T120000Z" {
			http.Error(w, "bad x-amz-date", http.StatusForbidden)
			return
		}
		if r.Header.Get("X-Amz-Security-Token") != "sess-tok" {
			http.Error(w, "missing session token", http.StatusForbidden)
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case awsTargetGetPubKey:
			writeJSON(w, awsGetPublicKeyResp{
				PublicKey:         base64.StdEncoding.EncodeToString(pubDER),
				SigningAlgorithms: []string{"ECDSA_SHA_256"},
			})
		case awsTargetSign:
			var req awsSignReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.MessageType != "DIGEST" || req.SigningAlgorithm != "ECDSA_SHA_256" {
				http.Error(w, "unexpected sign params", http.StatusBadRequest)
				return
			}
			digest, err := base64.StdEncoding.DecodeString(req.Message)
			if err != nil || len(digest) != sha256.Size {
				http.Error(w, "bad digest", http.StatusBadRequest)
				return
			}
			sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, awsSignResp{
				Signature: base64.StdEncoding.EncodeToString(sig),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	awsSigner, err := NewAWSSigner(ctx, AWSOptions{
		Region:          "us-east-1",
		KeyID:           "alias/tollkeeper-audit",
		Endpoint:        srv.URL,
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "secret-example",
		SessionToken:    "sess-tok",
		Clock:           func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("new aws signer: %v", err)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	localSigner, err := audit.NewLocalSigner(rootPriv)
	if err != nil {
		t.Fatalf("new local signer: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.OpenContext(ctx, audit.Options{
		Path:             logPath,
		ChainID:          "local-to-aws",
		CheckpointSigner: localSigner,
		CheckpointEvery:  10,
		FlushInterval:    10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	if err := l.Append(ctx, audit.Event{
		Phase: audit.PhaseDecision, RequestID: "before", Method: "tools/call", Decision: audit.DecisionAllow,
	}); err != nil {
		t.Fatalf("append before: %v", err)
	}
	if err := l.RotateSigner(ctx, awsSigner); err != nil {
		t.Fatalf("rotate to aws kms: %v", err)
	}
	if err := l.Append(ctx, audit.Event{
		Phase: audit.PhaseDecision, RequestID: "after", Method: "tools/call", Decision: audit.DecisionAllow,
	}); err != nil {
		t.Fatalf("append after: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	rep, err := audit.Verify(f, rootPub)
	if err != nil {
		t.Fatalf("verify rotated local->aws chain from root pubkey: %v", err)
	}
	if rep.Events != 2 || rep.KeyRotations != 1 || rep.UnsignedTail != 0 {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

func TestKMSSignerBlocksRedirectsAndPrivateIPs(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/steal", http.StatusFound)
	}))
	defer redirectSrv.Close()

	_, err := NewVaultSigner(ctx, VaultOptions{
		Address: redirectSrv.URL,
		KeyID:   "k",
		Token:   "secret-token",
	})
	if !errors.Is(err, ErrRedirectBlocked) {
		t.Fatalf("redirect error = %v, want ErrRedirectBlocked", err)
	}

	_, err = NewVaultSigner(ctx, VaultOptions{
		Address:         redirectSrv.URL,
		KeyID:           "k",
		Token:           "secret-token",
		BlockPrivateIPs: true,
	})
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("private ip error = %v, want ErrBlockedAddress", err)
	}
}
