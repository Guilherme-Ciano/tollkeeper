package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
)

func BenchmarkMultiTenantGatewayAdmission(b *testing.B) {
	now := time.Date(2026, 11, 23, 16, 0, 0, 0, time.UTC)
	const tenantCount = 8
	tenants := make(map[string]config.TenantPolicy, tenantCount)
	tokens := make([]string, tenantCount)
	principals := make(map[string]identity.Principal, tenantCount)
	for i := range tenantCount {
		tid := fmt.Sprintf("tenant-%02d", i)
		tok := "tok-" + tid
		tokens[i] = tok
		principals[tok] = identity.Principal{
			Subject:  "user-" + tid,
			Tenant:   tid,
			Roles:    []string{"operator"},
			ACR:      "phr",
			AuthTime: now.Add(-1 * time.Minute),
		}
		tenants[tid] = config.TenantPolicy{
			Default: config.EffectDeny,
			Rules: []config.Rule{
				{
					Name:     "allow-op",
					Tools:    []string{"crm__get"},
					Subjects: config.Subjects{RolesAny: []string{"operator"}},
					Effect:   config.EffectAllow,
					OnDeny:   config.OnDeny{ACRValues: []string{"phr"}, MaxAge: 5 * time.Minute},
				},
			},
		}
	}

	cfg := config.Defaults()
	cfg.Server.PublicURL = "https://gw.example.com/mcp"
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Auth.Resource = "https://gw.example.com/mcp"
	cfg.Auth.AuthorizationServers = []string{"https://idp.example.com"}
	cfg.Audit.Enabled = false
	cfg.Policy = config.Policy{Default: config.EffectDeny, Tenants: tenants}
	cfg.RateLimits = config.RateLimits{
		Rules: []config.RateRule{
			{Name: "tenant-cap", Tools: []string{"*"}, Per: config.PerTenant, Rate: "1000000/s", Burst: 1000000},
		},
	}

	pol, err := policy.New(cfg.Policy)
	if err != nil {
		b.Fatal(err)
	}
	lim, err := ratelimit.New(cfg.RateLimits, ratelimit.NewStore(func() time.Time { return now }))
	if err != nil {
		b.Fatal(err)
	}
	cat := catalog.New(16)
	desc, err := json.Marshal(map[string]any{
		"name":        "crm__get",
		"inputSchema": map[string]any{"type": "object"},
	})
	if err != nil {
		b.Fatal(err)
	}
	delta, err := cat.Replace("crm", []catalog.Tool{
		{Name: "crm__get", Upstream: "crm", Original: "get", Descriptor: desc, Pin: "p1"},
	})
	if err != nil {
		b.Fatal(err)
	}
	tr, err := telemetry.NewTracing(b.Context(), "bench", "test", "", 0)
	if err != nil {
		b.Fatal(err)
	}

	g := New(Deps{
		Config: cfg,
		Verifier: stubVerifier{fn: func(raw string) (identity.Principal, error) {
			return principals[raw], nil
		}},
		Policy:     pol,
		Limiter:    lim,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"crm": noopCaller{}},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     tr.Tracer(),
		Propagator: tr.Propagator,
		Log:        slog.New(slog.DiscardHandler),
		Version:    "bench",
		Now:        func() time.Time { return now },
	})
	g.Apply(delta)
	h := g.Handler()

	payload := []byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm__get","arguments":{},` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
	)
	var seq atomic.Uint64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tok := tokens[seq.Add(1)%tenantCount]
			req := httptest.NewRequestWithContext(
				b.Context(),
				http.MethodPost,
				cfg.Server.PublicURL,
				bytes.NewReader(payload),
			)
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
			req.Header.Set("Mcp-Method", "tools/call")
			req.Header.Set("Mcp-Name", "crm__get")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		}
	})
}
