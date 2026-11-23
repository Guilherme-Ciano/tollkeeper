package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fixedKeySource struct {
	kid string
	key any
}

func (s fixedKeySource) Key(_ context.Context, kid string) (any, error) {
	if kid != s.kid {
		return nil, ErrInvalidToken
	}
	return s.key, nil
}

func TestVerifierExtractsActorChainAndTenant(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	now := time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC)
	v := NewVerifier(fixedKeySource{kid: "k1", key: pub}, VerifierOptions{
		Issuer:     "https://idp.example.com",
		Audiences:  []string{"https://gw.example.com/mcp"},
		Algorithms: []string{"EdDSA"},
		Now:        func() time.Time { return now },
	})

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":       "https://idp.example.com",
		"sub":       "alice",
		"aud":       "https://gw.example.com/mcp",
		"client_id": "mcp-client",
		"tid":       "tenant-acme",
		"scope":     "crm:read",
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
		"act": map[string]any{
			"sub":       "agent-orchestrator",
			"client_id": "agent-app",
			"iss":       "https://idp.example.com",
			"act": map[string]any{
				"sub": "agent-worker",
			},
		},
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	p, err := v.Verify(t.Context(), signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Tenant != "tenant-acme" {
		t.Fatalf("tenant = %q, want tenant-acme", p.Tenant)
	}
	if p.DelegationDepth() != 2 {
		t.Fatalf("delegation depth = %d, want 2", p.DelegationDepth())
	}
	wantChain := []string{"agent-orchestrator", "agent-worker"}
	if !slices.Equal(p.Actor.Chain(), wantChain) {
		t.Fatalf("actor chain = %v, want %v", p.Actor.Chain(), wantChain)
	}
	if p.Actor.ClientID != "agent-app" {
		t.Fatalf("actor client_id = %q, want agent-app", p.Actor.ClientID)
	}
}

func TestIntrospectorExtractsActorAndTenant(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"active":    true,
			"sub":       "alice",
			"client_id": "cli",
			"iss":       "https://idp.example.com",
			"aud":       "https://gw.example.com/mcp",
			"scope":     "crm:read",
			"tenant_id": "acme",
			"exp":       now.Add(5 * time.Minute).Unix(),
			"act": map[string]any{
				"sub": "agent-router",
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	in := NewIntrospector(IntrospectorOptions{
		URL:          srv.URL,
		ClientID:     "gw",
		ClientSecret: "sec",
		Issuer:       "https://idp.example.com",
		Audiences:    []string{"https://gw.example.com/mcp"},
		CacheTTL:     time.Minute,
		Client:       srv.Client(),
		Now:          func() time.Time { return now },
	})

	p, err := in.Verify(t.Context(), "opaque-token-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Tenant != "acme" || p.Actor == nil || p.Actor.Subject != "agent-router" {
		t.Fatalf("unexpected principal: %+v", p)
	}
}
