package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

type echoArgs struct {
	Text string `json:"text"`
}

type headerLog struct {
	mu   sync.Mutex
	seen []string
}

func (h *headerLog) add(v string) {
	h.mu.Lock()
	h.seen = append(h.seen, v)
	h.mu.Unlock()
}

func (h *headerLog) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.seen...)
}

func fakeUpstream(t *testing.T, hl *headerLog) *httptest.Server {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	mcp.AddTool(
		s,
		&mcp.Tool{Name: "echo", Description: "echo text"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
		},
	)
	mcp.AddTool(
		s,
		&mcp.Tool{Name: "secret", Description: "hidden"},
		func(context.Context, *mcp.CallToolRequest, echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "secret"}}}, nil, nil
		},
	)
	h := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hl.add(r.Header.Get("Authorization"))
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConfig(t *testing.T, upURL string) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.AdminListen = "127.0.0.1:0"
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Server.ResyncDebounce = 0
	cfg.Auth.Mode = config.AuthModeNone
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.Audit.ChainID = "test"
	cfg.Audit.FlushInterval = 5 * time.Millisecond
	cfg.Upstreams = []config.Upstream{{
		ID: "fake", Transport: config.TransportStreamable, URL: upURL,
		Auth: config.UpstreamAuth{Type: config.UpstreamAuthBearer, Token: "gateway-own-token"},
	}}
	cfg.Policy.Rules = []config.Rule{{Name: "echo-only", Tools: []string{"fake__echo"}, Effect: config.EffectAllow}}
	cfg.RateLimits.Rules = []config.RateRule{
		{Name: "tight", Tools: []string{"*"}, Per: config.PerSubject, Rate: "100/m", Burst: 100},
	}
	return cfg
}

func startApp(t *testing.T, cfg config.Config) string {
	t.Helper()
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		if u.Timeout == 0 {
			u.Timeout = 5 * time.Second
			u.MaxConcurrency = 16
			u.Breaker = config.Breaker{Failures: 5, OpenFor: time.Second}
			u.RestartBackoff = 50 * time.Millisecond
			u.RestartMax = time.Second
		}
	}
	log := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(t.Context())
	a, err := Build(ctx, cfg, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Addr("data") != "" && a.Catalog().Snapshot().Len() > 0 {
			return "http://" + a.Addr("data") + "/mcp"
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("gateway did not become ready")
	return ""
}

type authTransport struct{ token string }

func (a authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+a.token)
	return http.DefaultTransport.RoundTrip(r2)
}

func connect(t *testing.T, url, version string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	var opts *mcp.ClientSessionOptions
	if version != "" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: version}
	}
	cs, err := c.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint: url, HTTPClient: &http.Client{Transport: authTransport{token: "client-token-must-not-leak"}},
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestGatewayEndToEnd(t *testing.T) {
	hl := &headerLog{}
	up := fakeUpstream(t, hl)
	cfg := testConfig(t, up.URL)
	url := startApp(t, cfg)
	for _, version := range []string{"", "2025-11-25"} {
		t.Run("protocol="+version, func(t *testing.T) {
			cs := connect(t, url, version)
			res, err := cs.ListTools(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Tools) != 1 || res.Tools[0].Name != "fake__echo" {
				names := make([]string, 0, len(res.Tools))
				for _, tl := range res.Tools {
					names = append(names, tl.Name)
				}
				t.Fatalf("visible tools = %v, want [fake__echo]", names)
			}
			out, err := cs.CallTool(
				t.Context(),
				&mcp.CallToolParams{Name: "fake__echo", Arguments: map[string]any{"text": "hi"}},
			)
			if err != nil {
				t.Fatal(err)
			}
			tc, ok := out.Content[0].(*mcp.TextContent)
			if out.IsError || !ok || tc.Text != "hi" {
				b, err := json.Marshal(out)
				t.Fatalf("unexpected result %s (%v)", b, err)
			}
			_, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "fake__secret", Arguments: map[string]any{}})
			if err == nil || !strings.Contains(err.Error(), "denied") {
				t.Fatalf("expected policy denial, got %v", err)
			}
		})
	}
	for _, h := range hl.all() {
		if strings.Contains(h, "client-token-must-not-leak") {
			t.Fatalf("downstream token reached upstream: %q", h)
		}
		if h != "Bearer gateway-own-token" {
			t.Fatalf("upstream saw Authorization %q, want gateway credential", h)
		}
	}
	if len(hl.all()) == 0 {
		t.Fatal("upstream saw no requests")
	}
}

func TestAuditChainVerifies(t *testing.T) {
	hl := &headerLog{}
	up := fakeUpstream(t, hl)
	cfg := testConfig(t, up.URL)
	cfg.RateLimits.Rules = nil
	url := startApp(t, cfg)
	cs := connect(t, url, "")
	for range 5 {
		if _, err := cs.CallTool(
			t.Context(),
			&mcp.CallToolParams{Name: "fake__echo", Arguments: map[string]any{"text": "x"}},
		); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	f, err := os.Open(cfg.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := audit.Verify(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events < 10 {
		t.Fatalf("expected intent+outcome per call, got %d events", rep.Events)
	}
}

func TestRateLimitReturns429(t *testing.T) {
	hl := &headerLog{}
	up := fakeUpstream(t, hl)
	cfg := testConfig(t, up.URL)
	cfg.RateLimits.Rules = []config.RateRule{
		{Name: "tight", Tools: []string{"fake__*"}, Per: config.PerSubjectTool, Rate: "2/m", Burst: 2},
	}
	url := startApp(t, cfg)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake__echo","arguments":{"text":"x"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"raw","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	codes := make([]int, 0, 3)
	var last *http.Response
	for range 3 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "fake__echo")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
		last = resp
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("status codes = %v, want [200 200 429]", codes)
	}
	if last.Header.Get("Retry-After") == "" || last.Header.Get("RateLimit-Policy") == "" {
		t.Fatalf("missing rate limit headers: %v", last.Header)
	}
}
