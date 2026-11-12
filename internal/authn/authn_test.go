package authn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://issuer.test"
	testAudience = "https://gw.test/mcp"
)

type jwksServer struct {
	srv   *httptest.Server
	hits  atomic.Int64
	keys  atomic.Pointer[JWKSet]
	fails atomic.Bool
}

func newJWKS(t *testing.T) *jwksServer {
	t.Helper()
	j := &jwksServer{}
	j.keys.Store(&JWKSet{})
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j.hits.Add(1)
		if j.fails.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if err := json.NewEncoder(w).Encode(j.keys.Load()); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwksServer) publish(t *testing.T, keys ...JWK) {
	t.Helper()
	j.keys.Store(&JWKSet{Keys: keys})
}

func edKey(tb testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return pub, priv
}

func jwk(tb testing.TB, kid string, pub ed25519.PublicKey) JWK {
	tb.Helper()
	k, err := EncodeJWK(kid, pub)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func sign(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func claims(mut func(jwt.MapClaims)) jwt.MapClaims {
	now := time.Now()
	c := jwt.MapClaims{
		"iss": testIssuer, "aud": []string{testAudience}, "sub": "alice", "client_id": "agent",
		"scope": "mcp:tools files:read", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
	if mut != nil {
		mut(c)
	}
	return c
}

func TestVerifierMatrix(t *testing.T) {
	t.Parallel()
	j := newJWKS(t)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edJWK, err := EncodeJWK("ed", edPub)
	if err != nil {
		t.Fatal(err)
	}
	ecJWK, err := EncodeJWK("ec", &ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	j.publish(t, edJWK, ecJWK)
	ks := NewKeySet(j.srv.URL, j.srv.Client(), time.Hour)
	v := NewVerifier(FromKeySet(ks), VerifierOptions{
		Issuer:     testIssuer,
		Audiences:  []string{testAudience},
		Algorithms: []string{"EdDSA", "ES256"},
		Leeway:     5 * time.Second,
	})
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token string
		ok    bool
	}{
		{"eddsa valid", sign(t, jwt.SigningMethodEdDSA, edPriv, "ed", claims(nil)), true},
		{"es256 valid", sign(t, jwt.SigningMethodES256, ecPriv, "ec", claims(nil)), true},
		{
			"wrong audience",
			sign(
				t,
				jwt.SigningMethodEdDSA,
				edPriv,
				"ed",
				claims(func(c jwt.MapClaims) { c["aud"] = "https://other/mcp" }),
			),
			false,
		},
		{
			"missing audience",
			sign(t, jwt.SigningMethodEdDSA, edPriv, "ed", claims(func(c jwt.MapClaims) { delete(c, "aud") })),
			false,
		},
		{
			"wrong issuer",
			sign(t, jwt.SigningMethodEdDSA, edPriv, "ed", claims(func(c jwt.MapClaims) { c["iss"] = "https://evil" })),
			false,
		},
		{
			"expired",
			sign(
				t,
				jwt.SigningMethodEdDSA,
				edPriv,
				"ed",
				claims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
			),
			false,
		},
		{
			"no exp",
			sign(t, jwt.SigningMethodEdDSA, edPriv, "ed", claims(func(c jwt.MapClaims) { delete(c, "exp") })),
			false,
		},
		{
			"not yet valid",
			sign(
				t,
				jwt.SigningMethodEdDSA,
				edPriv,
				"ed",
				claims(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }),
			),
			false,
		},
		{
			"no sub",
			sign(t, jwt.SigningMethodEdDSA, edPriv, "ed", claims(func(c jwt.MapClaims) { delete(c, "sub") })),
			false,
		},
		{"wrong signer", sign(t, jwt.SigningMethodEdDSA, otherPriv, "ed", claims(nil)), false},
		{"missing kid", sign(t, jwt.SigningMethodEdDSA, edPriv, "", claims(nil)), false},
		{"alg none", sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "ed", claims(nil)), false},
		{"hs256 with public key bytes", sign(t, jwt.SigningMethodHS256, []byte(edPub), "ed", claims(nil)), false},
		{"garbage", "not.a.jwt", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := v.Verify(t.Context(), tc.token)
			if tc.ok {
				if err != nil {
					t.Fatalf("rejected valid token: %v", err)
				}
				if p.Subject != "alice" || p.ClientID != "agent" || !p.HasScope("files:read") || p.Fingerprint == "" {
					t.Fatalf("principal %+v", p)
				}
				return
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("expected ErrInvalidToken, got %v", err)
			}
		})
	}
}

func TestKeyRotationAndOutage(t *testing.T) {
	t.Parallel()
	j := newJWKS(t)
	pub1, priv1 := edKey(t)
	pub2, priv2 := edKey(t)
	k1 := jwk(t, "k1", pub1)
	k2 := jwk(t, "k2", pub2)
	j.publish(t, k1)
	ks := NewKeySet(j.srv.URL, j.srv.Client(), 0)
	v := NewVerifier(
		FromKeySet(ks),
		VerifierOptions{Issuer: testIssuer, Audiences: []string{testAudience}, Algorithms: []string{"EdDSA"}},
	)
	if _, err := v.Verify(t.Context(), sign(t, jwt.SigningMethodEdDSA, priv1, "k1", claims(nil))); err != nil {
		t.Fatal(err)
	}
	j.publish(t, k1, k2)
	if _, err := v.Verify(t.Context(), sign(t, jwt.SigningMethodEdDSA, priv2, "k2", claims(nil))); err != nil {
		t.Fatalf("rotated key not fetched on unknown kid: %v", err)
	}
	ks2 := NewKeySet(j.srv.URL, j.srv.Client(), time.Hour)
	j.fails.Store(true)
	v2 := NewVerifier(
		FromKeySet(ks2),
		VerifierOptions{Issuer: testIssuer, Audiences: []string{testAudience}, Algorithms: []string{"EdDSA"}},
	)
	if _, err := v2.Verify(
		t.Context(),
		sign(t, jwt.SigningMethodEdDSA, priv1, "k1", claims(nil)),
	); !errors.Is(
		err,
		ErrKeysUnavailable,
	) {
		t.Fatalf("outage should surface ErrKeysUnavailable, got %v", err)
	}
}

func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	t.Parallel()
	j := newJWKS(t)
	pub, priv := edKey(t)
	k := jwk(t, "k", pub)
	j.publish(t, k)
	ks := NewKeySet(j.srv.URL, j.srv.Client(), time.Hour)
	v := NewVerifier(
		FromKeySet(ks),
		VerifierOptions{Issuer: testIssuer, Audiences: []string{testAudience}, Algorithms: []string{"EdDSA"}},
	)
	for i := range 50 {
		kid := "random-" + string(rune('a'+i%26))
		if _, err := v.Verify(t.Context(), sign(t, jwt.SigningMethodEdDSA, priv, kid, claims(nil))); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if hits := j.hits.Load(); hits != 1 {
		t.Fatalf("JWKS fetched %d times for 50 unknown kids, want 1", hits)
	}
}

func TestParseJWKRejects(t *testing.T) {
	t.Parallel()
	for _, j := range []JWK{
		{Kty: "oct"},
		{Kty: "OKP", Crv: "X25519", X: "AA"},
		{Kty: "EC", Crv: "P-521"},
		{Kty: "RSA", N: "AQAB", E: "AQAB"},
		{Kty: "EC", Crv: "P-256", X: "AA", Y: "AA"},
	} {
		if _, err := ParseJWK(j); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("%+v accepted: %v", j, err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	pub, priv := edKey(b)
	ks := NewKeySet("http://unused", http.DefaultClient, time.Hour)
	ks.keys["k"] = pub
	v := NewVerifier(
		FromKeySet(ks),
		VerifierOptions{Issuer: testIssuer, Audiences: []string{testAudience}, Algorithms: []string{"EdDSA"}},
	)
	c := claims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(time.Hour).Unix() })
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	tok.Header["kid"] = "k"
	s, err := tok.SignedString(priv)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Verify(b.Context(), s); err != nil {
			b.Fatal(err)
		}
	}
}
