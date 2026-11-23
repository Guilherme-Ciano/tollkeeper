package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type chaosCaller struct {
	faultMode atomic.Int32
	calls     atomic.Int64
}

func (c *chaosCaller) CallTool(ctx context.Context, _ upstream.Call) (*mcp.CallToolResult, error) {
	c.calls.Add(1)
	if c.faultMode.Load() == 1 {
		switch rand.IntN(4) {
		case 0:
			return nil, upstream.ErrUnavailable
		case 1:
			return nil, upstream.ErrBreakerOpen
		case 2:
			return nil, upstream.ErrTimeout
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
}

func TestGatewayChaosFaultInjectionSwapAndRecovery(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "chaos-audit.jsonl")
	auditLog, err := audit.Open(audit.Options{
		Path:          auditPath,
		ChainID:       "chaos-1",
		FlushInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Server.PublicURL = "https://gw.example.com/mcp"
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Auth.Resource = "https://gw.example.com/mcp"
	cfg.Auth.AuthorizationServers = []string{"https://idp.example.com"}
	cfg.Audit.Enabled = true
	cfg.Audit.Path = auditPath
	cfg.Policy = config.Policy{
		Default: config.EffectDeny,
		Tenants: map[string]config.TenantPolicy{
			"acme": {
				Default: config.EffectDeny,
				Rules:   []config.Rule{{Name: "acme-ok", Tools: []string{"demo__ping"}, Effect: config.EffectAllow}},
			},
			"globex": {
				Default: config.EffectDeny,
				Rules:   []config.Rule{{Name: "globex-deny", Tools: []string{"demo__ping"}, Effect: config.EffectDeny}},
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
	cat := catalog.New(16)
	desc, err := json.Marshal(map[string]any{
		"name":        "demo__ping",
		"inputSchema": map[string]any{"type": "object"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := cat.Replace("demo", []catalog.Tool{
		{Name: "demo__ping", Upstream: "demo", Original: "ping", Descriptor: desc, Pin: "pin-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := telemetry.NewTracing(t.Context(), "chaos", "test", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	caller := &chaosCaller{}
	caller.faultMode.Store(1)

	g := New(Deps{
		Config: cfg,
		Verifier: stubVerifier{fn: func(raw string) (identity.Principal, error) {
			if raw == "tok-acme" {
				return identity.Principal{Subject: "alice", Tenant: "acme"}, nil
			}
			if raw == "tok-globex" {
				return identity.Principal{Subject: "bob", Tenant: "globex"}, nil
			}
			return identity.Principal{}, errors.New("bad token")
		}},
		Policy:     pol,
		Limiter:    lim,
		Audit:      auditLog,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"demo": caller},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     tr.Tracer(),
		Propagator: tr.Propagator,
		Log:        slog.New(slog.DiscardHandler),
		Version:    "test",
	})
	g.Apply(delta)
	h := g.Handler()

	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo__ping","arguments":{}}}`

	var wg sync.WaitGroup
	var globexAllowed atomic.Int32
	for w := range 8 {
		wg.Go(func() {
			for i := range 25 {
				tok := "tok-acme"
				if (w+i)%2 == 1 {
					tok = "tok-globex"
				}
				req := httptest.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					cfg.Server.PublicURL,
					bytes.NewBufferString(callBody),
				)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if tok == "tok-globex" && !strings.Contains(rec.Body.String(), "denied by policy") {
					globexAllowed.Add(1)
				}
			}
		})
	}
	wg.Go(func() {
		for range 10 {
			nextPol, perr := policy.New(cfg.Policy)
			if perr != nil {
				t.Errorf("compile policy during chaos: %v", perr)
				return
			}
			g.Swap(nextPol, lim)
			time.Sleep(time.Millisecond)
		}
	})
	wg.Wait()

	if globexAllowed.Load() != 0 {
		t.Fatalf("tenant isolation broken under chaos: globex got %d non-denied responses", globexAllowed.Load())
	}

	caller.faultMode.Store(0)
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		cfg.Server.PublicURL,
		bytes.NewBufferString(callBody),
	)
	req.Header.Set("Authorization", "Bearer tok-acme")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"text":"ok"`) {
		t.Fatalf("gateway did not recover after chaos: status=%d body=%s", rec.Code, rec.Body.String())
	}

	if err := auditLog.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}
	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := audit.Verify(f, nil)
	if err != nil {
		t.Fatalf("audit chain corrupted under chaos: %v", err)
	}
	if rep.Events < 200 {
		t.Fatalf("expected >= 200 audited chaos events, got %d", rep.Events)
	}
}
