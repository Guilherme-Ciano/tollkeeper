package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
)

func testGateway(t *testing.T, rules []config.Rule) (*Gateway, *telemetry.Metrics, *httptest.Server) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Auth.Mode = config.AuthModeNone
	cfg.Audit.Enabled = false
	pol, err := policy.New(config.Policy{Default: config.EffectDeny, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(10)
	m := telemetry.NewMetrics()
	g := New(Deps{
		Config: cfg, Policy: pol, Limiter: lim, Catalog: cat, Upstreams: map[string]Caller{"up": &countingCaller{}},
		Metrics: m, Tracer: noop.NewTracerProvider().Tracer("t"), Propagator: propagation.TraceContext{},
		Log: slog.New(slog.DiscardHandler),
	})
	desc, err := json.Marshal(&mcp.Tool{Name: "up__t", InputSchema: map[string]any{"type": "object"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := cat.Replace(
		"up",
		[]catalog.Tool{{Name: "up__t", Upstream: "up", Original: "t", Pin: "1", Descriptor: desc}},
	)
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(d)
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return g, m, srv
}

func send(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func TestUnknownNotificationsDoNotGrowMetrics(t *testing.T) {
	t.Parallel()
	_, m, srv := testGateway(t, nil)
	for i := range 50 {
		status, _ := send(t, srv.URL+"/mcp", `{"jsonrpc":"2.0","method":"notifications/x`+strconv.Itoa(i)+`"}`)
		if status != http.StatusAccepted {
			t.Fatalf("status %d", status)
		}
	}
	if n := testutil.CollectAndCount(m.Duration); n != 0 {
		t.Fatalf("unknown notifications created %d metric series", n)
	}
}

func TestUnknownToolLooksLikeDeniedTool(t *testing.T) {
	t.Parallel()
	_, _, srv := testGateway(
		t,
		[]config.Rule{{Name: "secret-rule-name", Tools: []string{"other__*"}, Effect: config.EffectAllow}},
	)
	call := func(name string) (int, string) {
		return send(
			t,
			srv.URL+"/mcp",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+name+`","arguments":{}}}`,
		)
	}
	s1, denied := call("up__t")
	s2, unknown := call("up__does_not_exist")
	if s1 != s2 || denied != unknown {
		t.Fatalf("denied (%d %s) and unknown (%d %s) responses differ", s1, denied, s2, unknown)
	}
	if strings.Contains(denied, "rule") {
		t.Fatalf("denial leaks rule data: %s", denied)
	}
}
