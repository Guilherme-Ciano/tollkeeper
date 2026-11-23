package upstream

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/netguard"
)

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func TestTokenExchangeTransportEndToEndAndIsolation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	var exchangeCalls atomic.Int32
	var discoveryCalls atomic.Int32
	var lastFormMu sync.Mutex
	lastForm := map[string]string{}

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "gw-client" || pass != "gw-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		grant := r.FormValue("grant_type")
		switch grant {
		case "client_credentials":
			discoveryCalls.Add(1)
			writeJSONResp(w, map[string]any{
				"access_token": "discovery-svc-token",
				"token_type":   "Bearer",
				"expires_in":   300,
			})
		case RFC8693GrantType:
			exchangeCalls.Add(1)
			lastFormMu.Lock()
			for k := range r.Form {
				lastForm[k] = r.FormValue(k)
			}
			lastFormMu.Unlock()
			subTok := r.FormValue("subject_token")
			writeJSONResp(w, map[string]any{
				"access_token":      "exchanged-for-" + subTok + "-scopes-" + r.FormValue("scope"),
				"issued_token_type": RFC8693AccessType,
				"token_type":        "Bearer",
				"expires_in":        300,
			})
		default:
			http.Error(w, "unsupported grant: "+grant, http.StatusBadRequest)
		}
	}))
	defer authSrv.Close()

	var gotAuthHeaders []string
	var hdrMu sync.Mutex
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdrMu.Lock()
		gotAuthHeaders = append(gotAuthHeaders, r.Header.Get("Authorization"))
		hdrMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upSrv.Close()

	cfg := config.Upstream{
		ID:        "crm",
		Transport: config.TransportStreamable,
		URL:       upSrv.URL,
		Auth: config.UpstreamAuth{
			Type:         config.UpstreamAuthTokenExchange,
			TokenURL:     authSrv.URL,
			ClientID:     "gw-client",
			ClientSecret: "gw-secret",
			Resource:     "https://crm.internal/mcp",
			Scopes:       []string{"crm:read", "crm:write"},
			TokenExchange: &config.TokenExchange{
				Audience:              "crm-api",
				ActorToken:            "gw-actor-jwt",
				RequestedTokenType:    RFC8693JWTType,
				IntersectCallerScopes: true,
				MaxDelegationDepth:    1,
				AllowedIssuers:        []string{"https://idp.example.com"},
				DiscoveryScopes:       []string{"mcp:discover"},
			},
		},
	}

	hc, err := HTTPClient(ctx, cfg)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	discReq, err := http.NewRequestWithContext(ctx, http.MethodGet, upSrv.URL+"/tools", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	discResp, err := hc.Do(discReq)
	if err != nil {
		t.Fatalf("discovery request: %v", err)
	}
	discResp.Body.Close()
	if discoveryCalls.Load() != 1 {
		t.Fatalf("discovery calls = %d, want 1", discoveryCalls.Load())
	}

	alice := identity.Principal{
		Subject: "alice",
		Issuer:  "https://idp.example.com",
		Scopes:  []string{"crm:read", "billing:admin"},
		Actor:   &identity.Actor{Subject: "coding-agent"},
	}
	aliceCtx := identity.WithSubjectToken(identity.WithPrincipal(ctx, alice), "alice-raw-token")

	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			req, rerr := http.NewRequestWithContext(aliceCtx, http.MethodPost, upSrv.URL+"/mcp", http.NoBody)
			if rerr != nil {
				t.Errorf("new req: %v", rerr)
				return
			}
			resp, derr := hc.Do(req)
			if derr != nil {
				t.Errorf("alice call: %v", derr)
				return
			}
			resp.Body.Close()
		})
	}
	wg.Wait()

	if exchangeCalls.Load() != 1 {
		t.Fatalf("expected singleflight+cache to issue 1 exchange call for alice, got %d", exchangeCalls.Load())
	}

	lastFormMu.Lock()
	if lastForm["resource"] != "https://crm.internal/mcp" ||
		lastForm["audience"] != "crm-api" ||
		lastForm["scope"] != "crm:read" ||
		lastForm["actor_token"] != "gw-actor-jwt" ||
		lastForm["actor_token_type"] != RFC8693AccessType ||
		lastForm["requested_token_type"] != RFC8693JWTType {
		t.Fatalf("unexpected exchange form: %+v", lastForm)
	}
	lastFormMu.Unlock()

	bob := identity.Principal{
		Subject: "bob",
		Issuer:  "https://idp.example.com",
		Scopes:  []string{"crm:read", "crm:write"},
	}
	bobCtx := identity.WithSubjectToken(identity.WithPrincipal(ctx, bob), "bob-raw-token")
	bobReq, err := http.NewRequestWithContext(bobCtx, http.MethodPost, upSrv.URL+"/mcp", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	bobResp, err := hc.Do(bobReq)
	if err != nil {
		t.Fatalf("bob call: %v", err)
	}
	bobResp.Body.Close()
	if exchangeCalls.Load() != 2 {
		t.Fatalf("expected separate exchange for bob, got %d total calls", exchangeCalls.Load())
	}

	hdrMu.Lock()
	defer hdrMu.Unlock()
	for _, h := range gotAuthHeaders {
		if h == "Bearer alice-raw-token" || h == "Bearer bob-raw-token" {
			t.Fatalf("raw caller token leaked to upstream: %s", h)
		}
	}
}

func TestTokenExchangeDelegationControlsAndFailClosed(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, map[string]any{
			"access_token": "downscoped-tok",
			"token_type":   "Bearer",
			"expires_in":   120,
		})
	}))
	t.Cleanup(authSrv.Close)

	now := time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC)
	ex := NewTokenExchanger(config.UpstreamAuth{
		Type:         config.UpstreamAuthTokenExchange,
		TokenURL:     authSrv.URL,
		ClientID:     "c",
		ClientSecret: "s",
		Resource:     "https://api.internal",
		Scopes:       []string{"docs:read", "docs:write"},
		TokenExchange: &config.TokenExchange{
			IntersectCallerScopes: true,
			MaxDelegationDepth:    1,
			AllowedIssuers:        []string{"https://trusted.idp"},
		},
	}, authSrv.Client(), func() time.Time { return now })

	t.Run("rejects_excessive_delegation_depth", func(t *testing.T) {
		t.Parallel()
		p := identity.Principal{
			Subject: "alice",
			Issuer:  "https://trusted.idp",
			Scopes:  []string{"docs:read"},
			Actor: &identity.Actor{
				Subject: "agent-1",
				Actor:   &identity.Actor{Subject: "agent-2"},
			},
		}
		_, err := ex.Exchange(ctx, "tok-depth", p)
		if !errors.Is(err, ErrDelegationDenied) {
			t.Fatalf("got %v, want ErrDelegationDenied", err)
		}
	})

	t.Run("rejects_disallowed_issuer", func(t *testing.T) {
		t.Parallel()
		p := identity.Principal{
			Subject: "alice",
			Issuer:  "https://untrusted.idp",
			Scopes:  []string{"docs:read"},
		}
		_, err := ex.Exchange(ctx, "tok-iss", p)
		if !errors.Is(err, ErrDelegationDenied) {
			t.Fatalf("got %v, want ErrDelegationDenied", err)
		}
	})

	t.Run("rejects_empty_scope_intersection", func(t *testing.T) {
		t.Parallel()
		p := identity.Principal{
			Subject: "alice",
			Issuer:  "https://trusted.idp",
			Scopes:  []string{"unrelated:scope"},
		}
		_, err := ex.Exchange(ctx, "tok-scope", p)
		if !errors.Is(err, ErrDelegationDenied) {
			t.Fatalf("got %v, want ErrDelegationDenied", err)
		}
	})

	t.Run("blocks_private_ip_token_endpoint", func(t *testing.T) {
		t.Parallel()
		hc, err := HTTPClient(ctx, config.Upstream{
			ID:              "private-test",
			Transport:       config.TransportStreamable,
			URL:             authSrv.URL,
			BlockPrivateIPs: true,
			Auth: config.UpstreamAuth{
				Type:         config.UpstreamAuthTokenExchange,
				TokenURL:     authSrv.URL,
				ClientID:     "c",
				ClientSecret: "s",
				Resource:     "https://api.internal",
			},
		})
		if err != nil {
			t.Fatalf("http client: %v", err)
		}
		p := identity.Principal{Subject: "alice", Scopes: []string{"docs:read"}}
		rctx := identity.WithSubjectToken(identity.WithPrincipal(ctx, p), "tok")
		req, err := http.NewRequestWithContext(rctx, http.MethodPost, authSrv.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hc.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, netguard.ErrBlockedAddress) {
			t.Fatalf("private ip exchange error = %v, want ErrBlockedAddress", err)
		}
	})
}

func TestTokenExchangeRejectsForeignHostAndMissingSubjectToken(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cfg := config.Upstream{
		ID:        "crm",
		Transport: config.TransportStreamable,
		URL:       "https://crm.example.com/mcp",
		Auth: config.UpstreamAuth{
			Type:         config.UpstreamAuthTokenExchange,
			TokenURL:     "https://idp.example.com/token",
			ClientID:     "c",
			ClientSecret: "s",
			Resource:     "https://crm.example.com/mcp",
		},
	}
	hc, err := HTTPClient(ctx, cfg)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	foreignReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://evil.example.com/mcp", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(foreignReq)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrForeignHost) {
		t.Fatalf("foreign host error = %v, want ErrForeignHost", err)
	}

	authedNoTokenCtx := identity.WithPrincipal(ctx, identity.Principal{Subject: "alice"})
	noTokReq, err := http.NewRequestWithContext(authedNoTokenCtx, http.MethodPost, cfg.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = hc.Do(noTokReq)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrTokenExchange) {
		t.Fatalf("missing subject token error = %v, want ErrTokenExchange", err)
	}
}
