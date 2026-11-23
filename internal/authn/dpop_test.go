package authn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signDPoPProof(
	t *testing.T,
	method jwt.SigningMethod,
	key any,
	jwkHeader any,
	claims jwt.MapClaims,
) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["typ"] = dpopTyp
	tok.Header["jwk"] = jwkHeader
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return s
}

func TestDPoPVerifierEd25519AndES256(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)
	v := NewDPoPVerifier(DPoPOptions{
		TargetURL: "https://gw.example.com/mcp",
		MaxAge:    60 * time.Second,
		Leeway:    10 * time.Second,
		Now:       func() time.Time { return now },
	})

	t.Run("ed25519_valid_and_replay_blocked", func(t *testing.T) {
		t.Parallel()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := EncodeJWK("", pub)
		if err != nil {
			t.Fatal(err)
		}
		jkt, err := JWKThumbprint(jwk)
		if err != nil {
			t.Fatal(err)
		}
		accessTok := "access-token-ed25519"
		proof := signDPoPProof(t, jwt.SigningMethodEdDSA, priv, jwk, jwt.MapClaims{
			"jti": "unique-jti-1",
			"htm": http.MethodPost,
			"htu": "https://gw.example.com/mcp",
			"iat": now.Unix(),
			"ath": AccessTokenHash(accessTok),
		})
		req := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"https://gw.example.com/mcp?foo=bar",
			http.NoBody,
		)
		req.Header.Set("DPoP", proof)

		gotJKT, err := v.Verify(req, accessTok, jkt)
		if err != nil {
			t.Fatalf("verify valid ed25519 dpop: %v", err)
		}
		if gotJKT != jkt {
			t.Fatalf("jkt = %q, want %q", gotJKT, jkt)
		}

		_, err = v.Verify(req, accessTok, jkt)
		if !errors.Is(err, ErrDPoPReplayed) {
			t.Fatalf("replayed proof error = %v, want ErrDPoPReplayed", err)
		}
	})

	t.Run("es256_valid", func(t *testing.T) {
		t.Parallel()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := EncodeJWK("", &priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		jkt, err := JWKThumbprint(jwk)
		if err != nil {
			t.Fatal(err)
		}
		accessTok := "access-token-es256"
		proof := signDPoPProof(t, jwt.SigningMethodES256, priv, jwk, jwt.MapClaims{
			"jti": "unique-jti-es256",
			"htm": http.MethodPost,
			"htu": "https://gw.example.com/mcp",
			"iat": now.Unix(),
			"ath": AccessTokenHash(accessTok),
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://gw.example.com/mcp", http.NoBody)
		req.Header.Set("DPoP", proof)

		if _, err := v.Verify(req, accessTok, jkt); err != nil {
			t.Fatalf("verify es256 dpop: %v", err)
		}
	})
}

func TestDPoPVerifierRejectionsAndNonce(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := EncodeJWK("", pub)
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}

	v := NewDPoPVerifier(DPoPOptions{
		TargetURL:     "https://gw.example.com/mcp",
		MaxAge:        60 * time.Second,
		Leeway:        10 * time.Second,
		NonceRequired: true,
		NonceTTL:      5 * time.Minute,
		Now:           func() time.Time { return now },
	})

	accessTok := "tok-123"
	nonce := v.IssueNonce()

	t.Run("missing_nonce_triggers_use_dpop_nonce", func(t *testing.T) {
		t.Parallel()
		proof := signDPoPProof(t, jwt.SigningMethodEdDSA, priv, jwk, jwt.MapClaims{
			"jti": "jti-no-nonce",
			"htm": http.MethodPost,
			"htu": "https://gw.example.com/mcp",
			"iat": now.Unix(),
			"ath": AccessTokenHash(accessTok),
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://gw.example.com/mcp", http.NoBody)
		req.Header.Set("DPoP", proof)
		_, err := v.Verify(req, accessTok, jkt)
		if !errors.Is(err, ErrUseDPoPNonce) {
			t.Fatalf("got %v, want ErrUseDPoPNonce", err)
		}
	})

	t.Run("valid_nonce_succeeds", func(t *testing.T) {
		t.Parallel()
		proof := signDPoPProof(t, jwt.SigningMethodEdDSA, priv, jwk, jwt.MapClaims{
			"jti":   "jti-with-nonce",
			"htm":   http.MethodPost,
			"htu":   "https://gw.example.com/mcp",
			"iat":   now.Unix(),
			"ath":   AccessTokenHash(accessTok),
			"nonce": nonce,
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://gw.example.com/mcp", http.NoBody)
		req.Header.Set("DPoP", proof)
		if _, err := v.Verify(req, accessTok, jkt); err != nil {
			t.Fatalf("valid nonce failed: %v", err)
		}
	})

	t.Run("rejects_private_jwk_material", func(t *testing.T) {
		t.Parallel()
		badHeader := map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   jwk.X,
			"d":   "should-never-be-in-header",
		}
		proof := signDPoPProof(t, jwt.SigningMethodEdDSA, priv, badHeader, jwt.MapClaims{
			"jti":   "jti-priv",
			"htm":   http.MethodPost,
			"htu":   "https://gw.example.com/mcp",
			"iat":   now.Unix(),
			"ath":   AccessTokenHash(accessTok),
			"nonce": nonce,
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://gw.example.com/mcp", http.NoBody)
		req.Header.Set("DPoP", proof)
		if _, err := v.Verify(req, accessTok, jkt); !errors.Is(err, ErrInvalidDPoP) {
			t.Fatalf("got %v, want ErrInvalidDPoP", err)
		}
	})

	t.Run("rejects_wrong_jkt_ath_htm_htu_and_multiple_headers", func(t *testing.T) {
		t.Parallel()
		proof := signDPoPProof(t, jwt.SigningMethodEdDSA, priv, jwk, jwt.MapClaims{
			"jti":   "jti-checks",
			"htm":   http.MethodPost,
			"htu":   "https://gw.example.com/mcp",
			"iat":   now.Unix(),
			"ath":   AccessTokenHash(accessTok),
			"nonce": nonce,
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://gw.example.com/mcp", http.NoBody)
		req.Header.Set("DPoP", proof)

		if _, err := v.Verify(req, accessTok, "wrong-thumbprint"); !errors.Is(err, ErrInvalidDPoP) {
			t.Fatalf("wrong jkt = %v, want ErrInvalidDPoP", err)
		}
		if _, err := v.Verify(req, "different-token", jkt); !errors.Is(err, ErrInvalidDPoP) {
			t.Fatalf("wrong ath = %v, want ErrInvalidDPoP", err)
		}
		getReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://gw.example.com/mcp", http.NoBody)
		getReq.Header.Set("DPoP", proof)
		if _, err := v.Verify(getReq, accessTok, jkt); !errors.Is(err, ErrInvalidDPoP) {
			t.Fatalf("wrong htm = %v, want ErrInvalidDPoP", err)
		}
		multiReq := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"https://gw.example.com/mcp",
			http.NoBody,
		)
		multiReq.Header.Add("DPoP", proof)
		multiReq.Header.Add("DPoP", proof)
		if _, err := v.Verify(multiReq, accessTok, jkt); !errors.Is(err, ErrInvalidDPoP) {
			t.Fatalf("multi header = %v, want ErrInvalidDPoP", err)
		}
	})
}
