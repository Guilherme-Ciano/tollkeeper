package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type countingCaller struct{ calls int }

func (c *countingCaller) CallTool(context.Context, upstream.Call) (*mcp.CallToolResult, error) {
	c.calls++
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
}

func TestBackstopRejectsCallsWithoutAdmission(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Audit.Enabled = false
	pol, err := policy.New(config.Policy{Default: config.EffectAllow})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(10)
	caller := &countingCaller{}
	g := New(Deps{
		Config:     cfg,
		Policy:     pol,
		Limiter:    lim,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"up": caller},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     noop.NewTracerProvider().Tracer("t"),
		Propagator: propagation.TraceContext{},
		Log:        slog.New(slog.DiscardHandler),
	})
	desc, err := json.Marshal(&mcp.Tool{Name: "up__t", InputSchema: map[string]any{"type": "object"}})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := json.Marshal(&mcp.Tool{Name: "up__bad", InputSchema: map[string]any{"type": "string"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := cat.Replace("up", []catalog.Tool{
		{Name: "up__t", Upstream: "up", Original: "t", Pin: "1", Descriptor: desc},
		{Name: "up__bad", Upstream: "up", Original: "bad", Pin: "1", Descriptor: bad},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(d)
	if _, ok := g.Quarantined()["up__bad"]; !ok {
		t.Fatal("tool with non-object schema not quarantined")
	}
	ct, st := mcp.NewInMemoryTransports()
	ss, err := g.Server().Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	_, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "up__t", Arguments: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("call without admission was not blocked: %v", err)
	}
	if caller.calls != 0 {
		t.Fatal("upstream reached without admission")
	}
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 0 {
		t.Fatalf("anonymous list without principal leaked %d tools", len(res.Tools))
	}
}
