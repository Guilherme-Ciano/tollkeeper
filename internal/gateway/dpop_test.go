package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type stubVerifier struct {
	fn func(raw string) (identity.Principal, error)
}

func (s stubVerifier) Verify(_ context.Context, raw string) (identity.Principal, error) {
	return s.fn(raw)
}

type noopCaller struct{}

func (noopCaller) CallTool(context.Context, upstream.Call) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
}

func makeDPoPTestProof(
	t *testing.T,
	priv ed25519.PrivateKey,
	jwk authn.JWK,
	method, htu, accessToken, nonce, jti string,
	now time.Time,
) string {
	t.Helper()
	claims := jwt.MapClaims{
		"jti": jti,
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
		"ath": authn.AccessTokenHash(accessToken),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign dpop: %v", err)
	}
	return s
}

func TestGatewayDPoPRequiredWithNonceAndPRM(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := authn.EncodeJWK("", pub)
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := authn.JWKThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Server.PublicURL = "https://gw.example.com/mcp"
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Auth.Resource = "https://gw.example.com/mcp"
	cfg.Auth.AuthorizationServers = []string{"https://idp.example.com"}
	cfg.Auth.DPoP.Mode = config.DPoPModeRequired
	cfg.Auth.DPoP.NonceRequired = true
	cfg.Audit.Enabled = false
	cfg.Policy = config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:   "allow-dpop",
				Tools:  []string{"*"},
				Effect: config.EffectAllow,
				When:   `principal.dpop && principal.jkt != ""`,
			},
		},
	}

	pol, err := policy.New(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(cfg.RateLimits, ratelimit.NewStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(10)
	tr, err := telemetry.NewTracing(t.Context(), "test", "test", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	dpopV := authn.NewDPoPVerifier(authn.DPoPOptions{
		TargetURL:     cfg.Server.PublicURL,
		NonceRequired: true,
		Now:           func() time.Time { return now },
	})

	g := New(Deps{
		Config: cfg,
		Verifier: stubVerifier{fn: func(raw string) (identity.Principal, error) {
			if raw == "unbound-token" {
				return identity.Principal{Subject: "alice"}, nil
			}
			return identity.Principal{Subject: "alice", TokenThumbprint: jkt}, nil
		}},
		DPoP:       dpopV,
		Policy:     pol,
		Limiter:    lim,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"demo": noopCaller{}},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     tr.Tracer(),
		Propagator: tr.Propagator,
		Log:        slog.New(slog.DiscardHandler),
		Version:    "test",
		Now:        func() time.Time { return now },
	})
	h := g.Handler()

	prmReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://gw.example.com/.well-known/oauth-protected-resource/mcp",
		http.NoBody,
	)
	prmRec := httptest.NewRecorder()
	h.ServeHTTP(prmRec, prmReq)
	if prmRec.Code != http.StatusOK {
		t.Fatalf("prm status = %d", prmRec.Code)
	}
	var prm map[string]any
	if err := json.Unmarshal(prmRec.Body.Bytes(), &prm); err != nil {
		t.Fatalf("decode prm: %v", err)
	}
	if bound, ok := prm["dpop_bound_access_tokens_required"].(bool); !ok || !bound {
		t.Fatalf("prm missing dpop_bound_access_tokens_required=true: %+v", prm)
	}

	pingBody := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	bearerReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://gw.example.com/mcp",
		bytes.NewBufferString(pingBody),
	)
	bearerReq.Header.Set("Authorization", "Bearer bound-token")
	bearerRec := httptest.NewRecorder()
	h.ServeHTTP(bearerRec, bearerReq)
	if bearerRec.Code != http.StatusUnauthorized ||
		!strings.HasPrefix(bearerRec.Header().Get("WWW-Authenticate"), "DPoP ") {
		t.Fatalf(
			"bearer in dpop required mode: status=%d hdr=%q",
			bearerRec.Code,
			bearerRec.Header().Get("WWW-Authenticate"),
		)
	}

	noNonceProof := makeDPoPTestProof(t, priv, jwk, http.MethodPost, cfg.Server.PublicURL, "bound-token", "", "j1", now)
	nonceReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://gw.example.com/mcp",
		bytes.NewBufferString(pingBody),
	)
	nonceReq.Header.Set("Authorization", "DPoP bound-token")
	nonceReq.Header.Set("DPoP", noNonceProof)
	nonceRec := httptest.NewRecorder()
	h.ServeHTTP(nonceRec, nonceReq)
	issuedNonce := nonceRec.Header().Get("DPoP-Nonce")
	if nonceRec.Code != http.StatusUnauthorized || issuedNonce == "" ||
		!strings.Contains(nonceRec.Header().Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		t.Fatalf(
			"nonce challenge failed: status=%d nonce=%q hdr=%q",
			nonceRec.Code,
			issuedNonce,
			nonceRec.Header().Get("WWW-Authenticate"),
		)
	}

	validProof := makeDPoPTestProof(
		t,
		priv,
		jwk,
		http.MethodPost,
		cfg.Server.PublicURL,
		"bound-token",
		issuedNonce,
		"j2",
		now,
	)
	okReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://gw.example.com/mcp",
		bytes.NewBufferString(pingBody),
	)
	okReq.Header.Set("Authorization", "DPoP bound-token")
	okReq.Header.Set("DPoP", validProof)
	okReq.Header.Set("Content-Type", "application/json")
	okReq.Header.Set("Accept", "application/json, text/event-stream")
	okRec := httptest.NewRecorder()
	h.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("valid dpop request failed: status=%d body=%s", okRec.Code, okRec.Body.String())
	}
}

func TestGatewayDPoPOptionalRejectsBoundTokenDowngrade(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)

	cfg := config.Defaults()
	cfg.Server.PublicURL = "https://gw.example.com/mcp"
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Auth.Resource = "https://gw.example.com/mcp"
	cfg.Auth.AuthorizationServers = []string{"https://idp.example.com"}
	cfg.Auth.DPoP.Mode = config.DPoPModeOptional
	cfg.Audit.Enabled = false

	pol, err := policy.New(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(cfg.RateLimits, ratelimit.NewStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := telemetry.NewTracing(t.Context(), "test", "test", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	g := New(Deps{
		Config: cfg,
		Verifier: stubVerifier{fn: func(raw string) (identity.Principal, error) {
			if raw == "sender-constrained" {
				return identity.Principal{Subject: "alice", TokenThumbprint: "some-jkt"}, nil
			}
			return identity.Principal{Subject: "bob"}, nil
		}},
		DPoP: authn.NewDPoPVerifier(
			authn.DPoPOptions{TargetURL: cfg.Server.PublicURL, Now: func() time.Time { return now }},
		),
		Policy:     pol,
		Limiter:    lim,
		Catalog:    catalog.New(10),
		Upstreams:  map[string]Caller{},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     tr.Tracer(),
		Propagator: tr.Propagator,
		Log:        slog.New(slog.DiscardHandler),
		Version:    "test",
		Now:        func() time.Time { return now },
	})
	h := g.Handler()

	pingBody := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	downgradeReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://gw.example.com/mcp",
		bytes.NewBufferString(pingBody),
	)
	downgradeReq.Header.Set("Authorization", "Bearer sender-constrained")
	downgradeRec := httptest.NewRecorder()
	h.ServeHTTP(downgradeRec, downgradeReq)
	if downgradeRec.Code != http.StatusUnauthorized {
		t.Fatalf("dpop-bound token sent as Bearer should be rejected with 401, got %d", downgradeRec.Code)
	}

	bearerReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://gw.example.com/mcp",
		bytes.NewBufferString(pingBody),
	)
	bearerReq.Header.Set("Authorization", "Bearer plain-bearer")
	bearerReq.Header.Set("Content-Type", "application/json")
	bearerReq.Header.Set("Accept", "application/json, text/event-stream")
	bearerRec := httptest.NewRecorder()
	h.ServeHTTP(bearerRec, bearerReq)
	if bearerRec.Code != http.StatusOK {
		t.Fatalf("plain bearer in optional mode failed: status=%d body=%s", bearerRec.Code, bearerRec.Body.String())
	}
}
