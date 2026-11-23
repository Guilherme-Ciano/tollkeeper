package gateway

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
)

func TestGatewayRFC9470StepUpChallengeAndTenantRateLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)

	cfg := config.Defaults()
	cfg.Server.PublicURL = "https://gw.example.com/mcp"
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Auth.Resource = "https://gw.example.com/mcp"
	cfg.Auth.AuthorizationServers = []string{"https://idp.example.com"}
	cfg.Auth.DPoP.Mode = config.DPoPModeOptional
	cfg.Audit.Enabled = false
	cfg.Policy = config.Policy{
		Default: config.EffectDeny,
		Tenants: map[string]config.TenantPolicy{
			"acme": {
				Default: config.EffectDeny,
				Rules: []config.Rule{
					{
						Name:   "acme-wire",
						Tools:  []string{"payments__wire"},
						Effect: config.EffectAllow,
						OnDeny: config.OnDeny{
							ACRValues: []string{"phr"},
							MaxAge:    5 * time.Minute,
						},
					},
					{
						Name:   "acme-dpop-only",
						Tools:  []string{"payments__vault"},
						Effect: config.EffectAllow,
						OnDeny: config.OnDeny{
							RequireDPoP: true,
						},
					},
				},
			},
		},
	}
	cfg.RateLimits = config.RateLimits{
		Rules: []config.RateRule{
			{Name: "tenant-limit", Tools: []string{"*"}, Per: config.PerTenant, Rate: "60/m", Burst: 10},
		},
	}

	pol, err := policy.New(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(cfg.RateLimits, ratelimit.NewStore(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(10)
	wireDesc, err := json.Marshal(map[string]any{
		"name":        "payments__wire",
		"inputSchema": map[string]any{"type": "object"},
	})
	if err != nil {
		t.Fatal(err)
	}
	vaultDesc, err := json.Marshal(map[string]any{
		"name":        "payments__vault",
		"inputSchema": map[string]any{"type": "object"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := cat.Replace("payments", []catalog.Tool{
		{Name: "payments__wire", Upstream: "payments", Original: "wire", Descriptor: wireDesc, Pin: "p1"},
		{Name: "payments__vault", Upstream: "payments", Original: "vault", Descriptor: vaultDesc, Pin: "p2"},
	})
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
			switch raw {
			case "stale-acme":
				return identity.Principal{
					Subject:  "alice",
					Tenant:   "acme",
					ACR:      "pwd",
					AuthTime: now.Add(-20 * time.Minute),
				}, nil
			case "fresh-acme":
				return identity.Principal{
					Subject:  "alice",
					Tenant:   "acme",
					ACR:      "phr",
					AuthTime: now.Add(-1 * time.Minute),
				}, nil
			default:
				return identity.Principal{Subject: "bob", Tenant: "globex"}, nil
			}
		}},
		DPoP: authn.NewDPoPVerifier(
			authn.DPoPOptions{TargetURL: cfg.Server.PublicURL, Now: func() time.Time { return now }},
		),
		Policy:     pol,
		Limiter:    lim,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"payments": noopCaller{}},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     tr.Tracer(),
		Propagator: tr.Propagator,
		Log:        slog.New(slog.DiscardHandler),
		Version:    "test",
		Now:        func() time.Time { return now },
	})
	g.Apply(delta)
	h := g.Handler()

	callWire := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payments__wire","arguments":{}}}`
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		cfg.Server.PublicURL,
		bytes.NewBufferString(callWire),
	)
	req.Header.Set("Authorization", "Bearer stale-acme")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	hdr := rec.Header().Get("WWW-Authenticate")
	if rec.Code != http.StatusUnauthorized ||
		!strings.Contains(hdr, `error="insufficient_user_authentication"`) ||
		!strings.Contains(hdr, `acr_values="phr"`) ||
		!strings.Contains(hdr, "max_age=300") {
		t.Fatalf("expected RFC 9470 challenge, got status=%d hdr=%q body=%s", rec.Code, hdr, rec.Body.String())
	}

	okReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		cfg.Server.PublicURL,
		bytes.NewBufferString(callWire),
	)
	okReq.Header.Set("Authorization", "Bearer fresh-acme")
	okReq.Header.Set("Content-Type", "application/json")
	okReq.Header.Set("Accept", "application/json, text/event-stream")
	okRec := httptest.NewRecorder()
	h.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK || strings.Contains(okRec.Body.String(), `"error"`) {
		t.Fatalf("fresh phr call failed: status=%d body=%s", okRec.Code, okRec.Body.String())
	}

	callVault := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"payments__vault","arguments":{}}}`
	dpopReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		cfg.Server.PublicURL,
		bytes.NewBufferString(callVault),
	)
	dpopReq.Header.Set("Authorization", "Bearer fresh-acme")
	dpopReq.Header.Set("Content-Type", "application/json")
	dpopReq.Header.Set("Accept", "application/json, text/event-stream")
	dpopRec := httptest.NewRecorder()
	h.ServeHTTP(dpopRec, dpopReq)
	if dpopRec.Code != http.StatusUnauthorized ||
		!strings.HasPrefix(dpopRec.Header().Get("WWW-Authenticate"), "DPoP ") {
		t.Fatalf(
			"expected DPoP step-up challenge, got status=%d hdr=%q",
			dpopRec.Code,
			dpopRec.Header().Get("WWW-Authenticate"),
		)
	}
}
