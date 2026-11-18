package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type recordingAuditor struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingAuditor) Append(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.RequestID, e.TraceID, e.LatencyMicros, e.UpstreamMicros = "", "", 0, 0
	r.events = append(r.events, e)
	return nil
}

func (r *recordingAuditor) take() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.events
	r.events = nil
	return out
}

type scriptedCaller struct {
	mu    sync.Mutex
	calls []upstream.Call
}

var scripted = map[string]string{
	"text":       `{"content":[{"type":"text","text":"hello <b>&</b>"}]}`,
	"empty":      `{}`,
	"tool_error": `{"content":[{"type":"text","text":"boom"}],"isError":true}`,
	"structured": `{"_meta":{"k":"v"},"content":[{"type":"text","text":"{\"n\":1}"}],"structuredContent":{"n":1}}`,
	"input": `{"inputRequests":{"ask":{"method":"elicitation/create","params":{"message":"name?",` +
		`"requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}}}},"requestState":"st-1"}`,
	"shed":         `{"inputRequests":{},"resultType":"input_required"}`,
	"liar":         `{"content":[{"type":"text","text":"done"}],"resultType":"input_required"}`,
	"both":         `{"content":[{"type":"text","text":"x"}],"inputRequests":{"a":{"method":"roots/list","params":{}}}}`,
	"upstream_err": ``,
	"foreign_info": `{"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"up","version":"9"}},"content":[]}`,
}

func (c *scriptedCaller) CallTool(_ context.Context, call upstream.Call) (*mcp.CallToolResult, error) {
	c.mu.Lock()
	call.Arguments = compact(call.Arguments)
	c.calls = append(c.calls, call)
	c.mu.Unlock()
	var args struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(call.Arguments, &args); err != nil {
		return nil, err
	}
	raw := scripted[args.Mode]
	if raw == "" {
		return nil, upstream.ErrTimeout
	}
	var res mcp.CallToolResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *scriptedCaller) take() []upstream.Call {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.calls
	c.calls = nil
	return out
}

func compact(raw json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return raw
	}
	return b.Bytes()
}

type diffSide struct {
	gw     *Gateway
	srv    *httptest.Server
	audit  *recordingAuditor
	caller *scriptedCaller
	m      *telemetry.Metrics
}

func newDiffSide(tb testing.TB, disableFast bool, descriptor map[string]any) *diffSide {
	tb.Helper()
	cfg := config.Defaults()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Server.DisableFastPath = disableFast
	cfg.Auth.Mode = config.AuthModeNone
	cfg.Audit.Enabled = true
	cfg.Audit.RecordArgs = config.RecordArgsFull
	pol, err := policy.New(config.Policy{Default: config.EffectAllow})
	if err != nil {
		tb.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(nil))
	if err != nil {
		tb.Fatal(err)
	}
	s := &diffSide{audit: &recordingAuditor{}, caller: &scriptedCaller{}, m: telemetry.NewMetrics()}
	cat := catalog.New(10)
	s.gw = New(Deps{
		Config: cfg, Policy: pol, Limiter: lim, Catalog: cat, Upstreams: map[string]Caller{"up": s.caller},
		Metrics: s.m, Tracer: noop.NewTracerProvider().Tracer("t"), Propagator: propagation.TraceContext{},
		Log: slog.New(slog.DiscardHandler), Audit: s.audit,
	})
	desc, err := json.Marshal(descriptor)
	if err != nil {
		tb.Fatal(err)
	}
	d, err := cat.Replace("up", []catalog.Tool{{
		Name: "up__t", Upstream: "up", Original: "t", Pin: catalog.PinHash("t", desc), Descriptor: desc,
	}})
	if err != nil {
		tb.Fatal(err)
	}
	s.gw.Apply(d)
	s.srv = httptest.NewServer(s.gw.Handler())
	tb.Cleanup(s.srv.Close)
	return s
}

type exchange struct {
	status       int
	contentType  string
	cacheControl string
	body         string
}

func (s *diffSide) do(t *testing.T, headers map[string]string, body string) exchange {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.srv.URL+"/mcp", strings.NewReader(body))
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
	return exchange{
		status:       resp.StatusCode,
		contentType:  resp.Header.Get("Content-Type"),
		cacheControl: resp.Header.Get("Cache-Control"),
		body:         string(b),
	}
}

const statelessMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
	`"io.modelcontextprotocol/clientInfo":{"name":"diff","version":"1.0"},` +
	`"io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}`

func statelessHeaders() map[string]string {
	return map[string]string{
		"Mcp-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "up__t",
	}
}

func callBody(id, params string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"up__t",` + params + `}}`
}

func TestFastPathMatchesSDKPath(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	sdk := newDiffSide(t, true, schema)
	fast := newDiffSide(t, false, schema)
	cases := []struct {
		name string
		id   string
		body string
	}{
		{"text", `1`, `"arguments":{"mode":"text"},` + statelessMeta},
		{"empty content", `"req-2"`, `"arguments":{"mode":"empty"},` + statelessMeta},
		{"tool error", `3`, `"arguments":{"mode":"tool_error"},` + statelessMeta},
		{"structured", `4`, `"arguments":{"mode":"structured","x":[1,2.50,"<>"]},` + statelessMeta},
		{"input required", `5`, `"arguments":{"mode":"input"},` + statelessMeta},
		{"load shedding", `6`, `"arguments":{"mode":"shed"},` + statelessMeta},
		{"upstream claims input", `7`, `"arguments":{"mode":"liar"},` + statelessMeta},
		{"content and input", `8`, `"arguments":{"mode":"both"},` + statelessMeta},
		{"upstream failure", `9`, `"arguments":{"mode":"upstream_err"},` + statelessMeta},
		{"retry with state", `10`, `"arguments":{"mode":"text"},"requestState":"st-1",` +
			`"inputResponses":{"ask":{"action":"accept","content":{"name":"ada"}}},` + statelessMeta},
		{"large id", `9007199254740991`, `"arguments":{"mode":"text"},` + statelessMeta},
		{"negative id", `-4`, `"arguments":{"mode":"text"},` + statelessMeta},
	}
	for _, tc := range cases {
		body := callBody(tc.id, tc.body)
		want := sdk.do(t, statelessHeaders(), body)
		got := fast.do(t, statelessHeaders(), body)
		if got != want {
			t.Errorf("%s: response differs\nsdk:  %+v\nfast: %+v", tc.name, want, got)
		}
		if w, g := sdk.audit.take(), fast.audit.take(); !reflect.DeepEqual(w, g) {
			t.Errorf("%s: audit differs\nsdk:  %+v\nfast: %+v", tc.name, w, g)
		}
		if w, g := sdk.caller.take(), fast.caller.take(); !reflect.DeepEqual(w, g) {
			t.Errorf("%s: upstream call differs\nsdk:  %+v\nfast: %+v", tc.name, w, g)
		}
	}
	if n := testutil.ToFloat64(fast.m.CallDispatch.WithLabelValues("fast")); n != float64(len(cases)) {
		t.Fatalf("fast dispatches = %v, want %d", n, len(cases))
	}
	if n := testutil.ToFloat64(sdk.m.CallDispatch.WithLabelValues("fast")); n != 0 {
		t.Fatalf("disabled gateway took the fast path %v times", n)
	}
}

func TestFastPathDelegatesWhatItCannotProve(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	sdk := newDiffSide(t, true, schema)
	fast := newDiffSide(t, false, schema)
	without := func(k string) map[string]string {
		h := statelessHeaders()
		delete(h, k)
		return h
	}
	with := func(k, v string) map[string]string {
		h := statelessHeaders()
		h[k] = v
		return h
	}
	args := `"arguments":{"mode":"text"}`
	cases := []struct {
		name    string
		headers map[string]string
		body    string
	}{
		{"legacy protocol", with("Mcp-Protocol-Version", "2025-11-25"), callBody(`1`, args)},
		{"no protocol header", without("Mcp-Protocol-Version"), callBody(`1`, args+`,`+statelessMeta)},
		{"missing method header", without("Mcp-Method"), callBody(`1`, args+`,`+statelessMeta)},
		{"missing name header", without("Mcp-Name"), callBody(`1`, args+`,`+statelessMeta)},
		{"meta version mismatch", with("Mcp-Protocol-Version", "2026-07-29"), callBody(`1`, args+`,`+statelessMeta)},
		{"no capabilities", statelessHeaders(), callBody(`1`, args+
			`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`)},
		{"null client info", statelessHeaders(), callBody(`1`, args+
			`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",`+
			`"io.modelcontextprotocol/clientInfo":null,"io.modelcontextprotocol/clientCapabilities":{}}`)},
		{"bad capabilities", statelessHeaders(), callBody(`1`, args+
			`,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",`+
			`"io.modelcontextprotocol/clientCapabilities":{"sampling":5}}`)},
		{"fractional id", statelessHeaders(), callBody(`1.5`, args+`,`+statelessMeta)},
		{"exponent id", statelessHeaders(), callBody(`1e3`, args+`,`+statelessMeta)},
		{"escaped id", statelessHeaders(), callBody(`"a`+string(rune(92))+`u0042"`, args+`,`+statelessMeta)},
		{"null arguments", statelessHeaders(), callBody(`1`, `"arguments":null,`+statelessMeta)},
		{"param header", with("Mcp-Param-Region", "eu"), callBody(`1`, args+`,`+statelessMeta)},
		{"wrong accept", with("Accept", "application/json"), callBody(`1`, args+`,`+statelessMeta)},
		{"last event id", with("Last-Event-Id", "1"), callBody(`1`, args+`,`+statelessMeta)},
	}
	for _, tc := range cases {
		want := sdk.do(t, tc.headers, tc.body)
		got := fast.do(t, tc.headers, tc.body)
		if got != want {
			t.Errorf("%s: response differs\nsdk:  %+v\nfast: %+v", tc.name, want, got)
		}
		if w, g := sdk.audit.take(), fast.audit.take(); !reflect.DeepEqual(w, g) {
			t.Errorf("%s: audit differs\nsdk:  %+v\nfast: %+v", tc.name, w, g)
		}
		sdk.caller.take()
		fast.caller.take()
	}
	if n := testutil.ToFloat64(fast.m.CallDispatch.WithLabelValues("fast")); n != 0 {
		t.Fatalf("ineligible requests took the fast path %v times", n)
	}
}

func TestFastPathSkipsToolsWithParamHeaders(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{
		"type":       "object",
		"properties": map[string]any{"region": map[string]any{"type": "string", "x-mcp-header": "Region"}},
	}}
	fast := newDiffSide(t, false, schema)
	fast.do(t, statelessHeaders(), callBody(`1`, `"arguments":{"mode":"text"},`+statelessMeta))
	if n := testutil.ToFloat64(fast.m.CallDispatch.WithLabelValues("sdk")); n != 1 {
		t.Fatalf("tool with parameter headers dispatched via sdk %v times, want 1", n)
	}
}

func TestFastPathKeepsUpstreamServerInfo(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	sdk := newDiffSide(t, true, schema)
	fast := newDiffSide(t, false, schema)
	body := callBody(`1`, `"arguments":{"mode":"foreign_info"},`+statelessMeta)
	if want, got := sdk.do(t, statelessHeaders(), body), fast.do(t, statelessHeaders(), body); got != want {
		t.Fatalf("response differs\nsdk:  %+v\nfast: %+v", want, got)
	}
	if w, g := sdk.audit.take(), fast.audit.take(); !reflect.DeepEqual(w, g) {
		t.Fatalf("audit differs\nsdk:  %+v\nfast: %+v", w, g)
	}
}

func TestCallResultWireCoversEveryField(t *testing.T) {
	t.Parallel()
	mirrored := map[string]bool{}
	for f := range reflect.TypeFor[callResultWire]().Fields() {
		mirrored[f.Name] = true
	}
	for f := range reflect.TypeFor[mcp.CallToolResult]().Fields() {
		if f.IsExported() && !mirrored[f.Name] {
			t.Errorf("mcp.CallToolResult.%s is not mirrored by callResultWire", f.Name)
		}
	}
}

func BenchmarkToolsCallDispatch(b *testing.B) {
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	body := []byte(callBody(`1`, `"arguments":{"mode":"text","q":"weather in lisbon"},`+statelessMeta))
	for _, path := range []struct {
		name    string
		disable bool
	}{{"fast", false}, {"sdk", true}} {
		b.Run(path.name, func(b *testing.B) {
			s := newDiffSide(b, path.disable, schema)
			h := s.gw.Handler()
			b.ReportAllocs()
			for b.Loop() {
				req := httptest.NewRequestWithContext(
					b.Context(), http.MethodPost, "http://127.0.0.1/mcp", bytes.NewReader(body),
				)
				for k, v := range statelessHeaders() {
					req.Header.Set(k, v)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("status %d: %s", rec.Code, rec.Body.String())
				}
				s.audit.take()
				s.caller.take()
			}
		})
	}
}

func TestClientCapabilitiesReachTheUpstream(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	for _, disable := range []bool{false, true} {
		s := newDiffSide(t, disable, schema)
		s.do(t, statelessHeaders(), callBody(`1`, `"arguments":{"mode":"text"},`+statelessMeta))
		calls := s.caller.take()
		if len(calls) != 1 {
			t.Fatalf("disable=%t: %d upstream calls", disable, len(calls))
		}
		raw, ok := calls[0].Meta[metaClientCapabilities].(json.RawMessage)
		if !ok || string(compact(raw)) != `{"elicitation":{}}` {
			t.Fatalf("disable=%t: capabilities not forwarded: %#v", disable, calls[0].Meta)
		}
	}
}
