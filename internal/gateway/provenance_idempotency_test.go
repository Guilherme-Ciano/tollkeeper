package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type spyCaller struct {
	calls atomic.Int64
}

func (c *spyCaller) CallTool(_ context.Context, _ upstream.Call) (*mcp.CallToolResult, error) {
	c.calls.Add(1)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
	}, nil
}

func sendWithHeaders(t *testing.T, url, body string, headers map[string]string) (status int, respBody string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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

func buildV16Gateway(
	t *testing.T,
	cfg config.Config,
	rules []config.Rule,
	tools []catalog.Tool,
	now func() time.Time,
	idem IdempotencyStore,
) (*telemetry.Metrics, *spyCaller, *httptest.Server) {
	t.Helper()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Auth.Mode = config.AuthModeNone
	cfg.Audit.Enabled = false
	pol, err := policy.New(config.Policy{Default: config.EffectDeny, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(cfg.RateLimits, ratelimit.NewStore(now))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(16)
	m := telemetry.NewMetrics()
	caller := &spyCaller{}
	upstreams := map[string]Caller{}
	byUpstream := map[string][]catalog.Tool{}
	for i := range tools {
		upstreams[tools[i].Upstream] = caller
		byUpstream[tools[i].Upstream] = append(byUpstream[tools[i].Upstream], tools[i])
	}
	g := New(Deps{
		Config:      cfg,
		Policy:      pol,
		Limiter:     lim,
		Catalog:     cat,
		Upstreams:   upstreams,
		Metrics:     m,
		Tracer:      noop.NewTracerProvider().Tracer("t"),
		Propagator:  propagation.TraceContext{},
		Log:         slog.New(slog.DiscardHandler),
		Now:         now,
		Idempotency: idem,
	})
	for uid, list := range byUpstream {
		d, rerr := cat.Replace(uid, list)
		if rerr != nil {
			t.Fatal(rerr)
		}
		g.Apply(d)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return m, caller, srv
}

func makeToolDescriptor(t *testing.T, name string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProvenanceCELAndResponseStamps(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Server.StampProvenance = true
	tools := []catalog.Tool{
		{
			Name:       "web__fetch",
			Upstream:   "web",
			Original:   "fetch",
			Pin:        "pin-web-1",
			Descriptor: makeToolDescriptor(t, "web__fetch"),
			Metadata: catalog.Metadata{
				Trust:          config.TrustUntrusted,
				Classification: config.ClassPublic,
				Egress:         true,
				Impact:         config.ImpactRead,
			},
		},
		{
			Name:       "db__drop",
			Upstream:   "db",
			Original:   "drop",
			Pin:        "pin-db-1",
			Descriptor: makeToolDescriptor(t, "db__drop"),
			Metadata: catalog.Metadata{
				Trust:          config.TrustTrusted,
				Classification: config.ClassRestricted,
				Egress:         false,
				Impact:         config.ImpactDestructive,
			},
		},
	}
	rules := []config.Rule{
		{
			Name:   "allow-untrusted-non-destructive",
			Tools:  []string{"*"},
			When:   `tool.trust == "untrusted" && tool.egress && tool.impact == "read" && tool.classification == "public"`,
			Effect: config.EffectAllow,
		},
		{
			Name:   "deny-destructive-restricted",
			Tools:  []string{"*"},
			When:   `tool.impact == "destructive" && tool.classification == "restricted"`,
			Effect: config.EffectDeny,
		},
	}

	_, caller, srv := buildV16Gateway(t, cfg, rules, tools, nil, nil)

	sdkBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web__fetch","arguments":{"url":"https://example.com"}}}`
	status, resp := sendWithHeaders(t, srv.URL+"/mcp", sdkBody, nil)
	if status != http.StatusOK {
		t.Fatalf("sdk call status %d: %s", status, resp)
	}
	assertProvenanceStamp(
		t,
		resp,
		"web",
		"web__fetch",
		config.TrustUntrusted,
		config.ClassPublic,
		config.ImpactRead,
		"pin-web-1",
		true,
	)

	fastBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web__fetch","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	fastHeaders := map[string]string{
		"Mcp-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "web__fetch",
	}
	status, resp = sendWithHeaders(t, srv.URL+"/mcp", fastBody, fastHeaders)
	if status != http.StatusOK {
		t.Fatalf("fast call status %d: %s", status, resp)
	}
	assertProvenanceStamp(
		t,
		resp,
		"web",
		"web__fetch",
		config.TrustUntrusted,
		config.ClassPublic,
		config.ImpactRead,
		"pin-web-1",
		true,
	)

	denyBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"db__drop","arguments":{}}}`
	_, denyResp := sendWithHeaders(t, srv.URL+"/mcp", denyBody, nil)
	if !strings.Contains(denyResp, `"code":-32001`) {
		t.Fatalf("expected db__drop to be denied by provenance CEL, got %s", denyResp)
	}
	if caller.calls.Load() != 2 {
		t.Fatalf("expected 2 upstream calls, got %d", caller.calls.Load())
	}
}

func assertProvenanceStamp(
	t *testing.T,
	body, wantUpstream, wantTool, wantTrust, wantClass, wantImpact, wantPin string,
	wantEgress bool,
) {
	t.Helper()
	var env struct {
		Result struct {
			Meta map[string]any `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("unmarshal response %s: %v", body, err)
	}
	raw, ok := env.Result.Meta["tollkeeper.provenance"].(map[string]any)
	if !ok {
		t.Fatalf("missing _meta[tollkeeper.provenance] in %s", body)
	}
	if raw["upstream"] != wantUpstream || raw["tool"] != wantTool || raw["trust"] != wantTrust ||
		raw["classification"] != wantClass || raw["impact"] != wantImpact || raw["pin_hash"] != wantPin ||
		raw["egress"] != wantEgress {
		t.Fatalf("unexpected provenance stamp: %+v", raw)
	}
}

func TestIdempotencyModesAndReplayProtection(t *testing.T) {
	t.Parallel()
	tools := []catalog.Tool{
		{
			Name:       "files__delete",
			Upstream:   "files",
			Original:   "delete",
			Pin:        "p1",
			Descriptor: makeToolDescriptor(t, "files__delete"),
		},
		{
			Name:       "files__read",
			Upstream:   "files",
			Original:   "read",
			Pin:        "p2",
			Descriptor: makeToolDescriptor(t, "files__read"),
		},
	}
	allowAll := []config.Rule{{Name: "allow", Tools: []string{"*"}, Effect: config.EffectAllow}}

	t.Run("required_header_mode", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Idempotency.Enabled = true
		cfg.Idempotency.Mode = config.IdempotencyModeRequired
		cfg.Idempotency.Header = "Idempotency-Key"
		cfg.Idempotency.TTL = 5 * time.Minute
		cfg.Idempotency.Tools = []string{"files__delete*"}

		m, caller, srv := buildV16Gateway(t, cfg, allowAll, tools, nil, nil)
		delCall := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files__delete","arguments":{"path":"/tmp/x"}}}`
		readCall := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files__read","arguments":{"path":"/tmp/x"}}}`

		st, body := sendWithHeaders(t, srv.URL+"/mcp", readCall, nil)
		if st != http.StatusOK || strings.Contains(body, `"error"`) {
			t.Fatalf("non-matching tool should skip idempotency: %d %s", st, body)
		}

		st, body = sendWithHeaders(t, srv.URL+"/mcp", delCall, nil)
		if st != http.StatusBadRequest || !strings.Contains(body, `"code":-32602`) {
			t.Fatalf("missing header should fail with 400/-32602, got %d %s", st, body)
		}

		hdr := map[string]string{"Idempotency-Key": "op-123"}
		st, body = sendWithHeaders(t, srv.URL+"/mcp", delCall, hdr)
		if st != http.StatusOK || strings.Contains(body, `"error"`) {
			t.Fatalf("first call with key should succeed: %d %s", st, body)
		}

		st, body = sendWithHeaders(t, srv.URL+"/mcp", delCall, hdr)
		if st != http.StatusConflict || !strings.Contains(body, `"code":-32009`) {
			t.Fatalf("duplicate key should return 409/-32009, got %d %s", st, body)
		}

		if caller.calls.Load() != 2 {
			t.Fatalf("expected exactly 2 upstream calls (1 read + 1 delete), got %d", caller.calls.Load())
		}
		if got := testutil.ToFloat64(m.IdempotencyRejections); got != 2 {
			t.Fatalf("expected 2 idempotency rejections (1 missing + 1 duplicate), got %v", got)
		}
	})

	t.Run("canonical_hash_mode_and_ttl_expiry", func(t *testing.T) {
		t.Parallel()
		clock := time.Unix(1_700_000_000, 0)
		now := func() time.Time { return clock }
		cfg := config.Defaults()
		cfg.Idempotency.Enabled = true
		cfg.Idempotency.Mode = config.IdempotencyModeCanonicalHash
		cfg.Idempotency.TTL = 30 * time.Second

		_, caller, srv := buildV16Gateway(t, cfg, allowAll, tools, now, nil)
		c1 := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files__delete","arguments":{"b":2,"a":1}}}`
		c2 := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files__delete","arguments":{"a": 1, "b": 2}}}`

		st, _ := sendWithHeaders(t, srv.URL+"/mcp", c1, nil)
		if st != http.StatusOK {
			t.Fatalf("first canonical call status %d", st)
		}
		st, body := sendWithHeaders(t, srv.URL+"/mcp", c2, nil)
		if st != http.StatusConflict || !strings.Contains(body, `"code":-32009`) {
			t.Fatalf("reordered identical JSON args should be deduplicated, got %d %s", st, body)
		}

		clock = clock.Add(31 * time.Second)
		st, body = sendWithHeaders(t, srv.URL+"/mcp", c2, nil)
		if st != http.StatusOK || strings.Contains(body, `"error"`) {
			t.Fatalf("after TTL expiry call should succeed, got %d %s", st, body)
		}
		if caller.calls.Load() != 2 {
			t.Fatalf("expected 2 upstream calls, got %d", caller.calls.Load())
		}
	})

	t.Run("denied_call_does_not_poison_key", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Idempotency.Enabled = true
		cfg.Idempotency.Mode = config.IdempotencyModeHeader
		cfg.Idempotency.TTL = time.Minute
		store := NewMemoryIdempotencyStore(100, nil)
		denyAll := []config.Rule{{Name: "deny", Tools: []string{"*"}, Effect: config.EffectDeny}}

		_, caller, srv := buildV16Gateway(t, cfg, denyAll, tools, nil, store)
		delCall := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files__delete","arguments":{}}}`
		_, body := sendWithHeaders(t, srv.URL+"/mcp", delCall, map[string]string{"Idempotency-Key": "k-denied"})
		if !strings.Contains(body, `"code":-32001`) {
			t.Fatalf("expected policy deny, got %s", body)
		}
		if caller.calls.Load() != 0 {
			t.Fatalf("denied call reached upstream")
		}
		key := scopedIdempotencyKey("", "", "files__delete", "k-denied")
		claimed, err := store.Claim(t.Context(), key, time.Minute)
		if err != nil || !claimed {
			t.Fatalf("denied call should not have claimed idempotency key: claimed=%v err=%v", claimed, err)
		}
	})

	t.Run("redis_idempotency_store", func(t *testing.T) {
		t.Parallel()
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: 0})
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("close redis client: %v", err)
			}
		})
		store := NewRedisIdempotencyStore(client, "tk:test:idem:", 200*time.Millisecond)
		cfg := config.Defaults()
		cfg.Idempotency.Enabled = true
		cfg.Idempotency.Mode = config.IdempotencyModeHeader
		cfg.Idempotency.TTL = 10 * time.Second

		_, caller, srv := buildV16Gateway(t, cfg, allowAll, tools, nil, store)
		delCall := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files__delete","arguments":{}}}`
		hdr := map[string]string{"Idempotency-Key": "redis-op-1"}

		st, _ := sendWithHeaders(t, srv.URL+"/mcp", delCall, hdr)
		if st != http.StatusOK {
			t.Fatalf("first redis idempotent call failed: %d", st)
		}
		st, body := sendWithHeaders(t, srv.URL+"/mcp", delCall, hdr)
		if st != http.StatusConflict || !strings.Contains(body, `"code":-32009`) {
			t.Fatalf("duplicate redis idempotent call should return 409/-32009, got %d %s", st, body)
		}
		mr.FastForward(11 * time.Second)
		st, _ = sendWithHeaders(t, srv.URL+"/mcp", delCall, hdr)
		if st != http.StatusOK {
			t.Fatalf("call after redis TTL expiry should succeed, got %d", st)
		}
		if caller.calls.Load() != 2 {
			t.Fatalf("expected 2 upstream calls, got %d", caller.calls.Load())
		}
	})
}
