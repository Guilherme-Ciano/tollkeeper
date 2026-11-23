package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type mapTokenVerifier map[string]identity.Principal

func (m mapTokenVerifier) Verify(_ context.Context, raw string) (identity.Principal, error) {
	p, ok := m[raw]
	if !ok {
		return identity.Principal{}, authn.ErrInvalidToken
	}
	return p, nil
}

type tenantDirectoryCaller struct {
	mu      sync.Mutex
	calls   []upstream.Call
	stateIn string
}

func (c *tenantDirectoryCaller) CallTool(_ context.Context, call upstream.Call) (*mcp.CallToolResult, error) {
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.stateIn = call.RequestState
	c.mu.Unlock()
	if call.Tool == "step" && call.RequestState == "" {
		var res mcp.CallToolResult
		if err := json.Unmarshal([]byte(scripted["input"]), &res); err != nil {
			return nil, err
		}
		return &res, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "ok:" + call.RequestState}},
	}, nil
}

func (c *tenantDirectoryCaller) ReadResource(
	_ context.Context,
	call upstream.ResourceCall,
) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{URI: call.URI, Text: "secret-of-" + call.URI}},
	}, nil
}

func (c *tenantDirectoryCaller) GetPrompt(
	_ context.Context,
	call upstream.PromptCall,
) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{
		Messages: []*mcp.PromptMessage{{Role: "assistant", Content: &mcp.TextContent{Text: "prompt-" + call.Name}}},
	}, nil
}

func sendAuthRPC(t *testing.T, url, token, method, name, params string) (status int, respBody string) {
	t.Helper()
	if params != "" {
		params += ","
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + params + statelessMeta + `}}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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

type multiTenantEnv struct {
	srv     *httptest.Server
	auditor *recordingAuditor
	alpha   *tenantDirectoryCaller
	beta    *tenantDirectoryCaller
}

func newMultiTenantEnv(t *testing.T, rateRules []config.RateRule) *multiTenantEnv {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Auth.Resource = cfg.Server.PublicURL
	cfg.Auth.RequiredScopes = []string{"mcp:tools"}
	cfg.Audit.Enabled = true

	pol, err := policy.New(config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:      "tenant-a-only",
				Subjects:  config.Subjects{ScopesAny: []string{"tenant:a"}},
				Tools:     []string{"alpha__*"},
				Resources: []string{"file:///a/*"},
				Prompts:   []string{"alpha__*"},
				Effect:    config.EffectAllow,
			},
			{
				Name:      "tenant-b-only",
				Subjects:  config.Subjects{ScopesAny: []string{"tenant:b"}},
				Tools:     []string{"beta__*"},
				Resources: []string{"file:///b/*"},
				Prompts:   []string{"beta__*"},
				Effect:    config.EffectAllow,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{Rules: rateRules}, ratelimit.NewStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(10)
	dir := catalog.NewDirectory(10)
	alpha := &tenantDirectoryCaller{}
	beta := &tenantDirectoryCaller{}
	aud := &recordingAuditor{}
	verifier := mapTokenVerifier{
		"tok-a": {
			Subject:  "alice",
			ClientID: "app-a",
			Scopes:   []string{"mcp:tools", "tenant:a"},
			Claims:   map[string]any{"tenant": "a"},
		},
		"tok-a-other-client": {
			Subject:  "alice",
			ClientID: "app-other",
			Scopes:   []string{"mcp:tools", "tenant:a"},
			Claims:   map[string]any{"tenant": "a"},
		},
		"tok-a-other-sub": {
			Subject:  "charlie",
			ClientID: "app-a",
			Scopes:   []string{"mcp:tools", "tenant:a"},
			Claims:   map[string]any{"tenant": "a"},
		},
		"tok-b": {
			Subject:  "bob",
			ClientID: "app-b",
			Scopes:   []string{"mcp:tools", "tenant:b"},
			Claims:   map[string]any{"tenant": "b"},
		},
	}
	g := New(Deps{
		Config:     cfg,
		Verifier:   verifier,
		Policy:     pol,
		Limiter:    lim,
		Audit:      aud,
		Catalog:    cat,
		Directory:  dir,
		Upstreams:  map[string]Caller{"alpha": alpha, "beta": beta},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     noop.NewTracerProvider().Tracer("t"),
		Propagator: propagation.TraceContext{},
		Log:        slog.New(slog.DiscardHandler),
		StateKey:   bytes.Repeat([]byte{9}, MinStateKeyLen),
	})
	da, err := cat.Replace("alpha", []catalog.Tool{
		makeTool(t, "alpha", "read", "Alpha read"),
		makeTool(t, "alpha", "step", "Alpha multi-turn"),
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := cat.Replace("beta", []catalog.Tool{
		makeTool(t, "beta", "read", "Beta read"),
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(da)
	g.Apply(db)
	promptA, err := json.Marshal(&mcp.Prompt{Name: "alpha__greet"})
	if err != nil {
		t.Fatal(err)
	}
	promptB, err := json.Marshal(&mcp.Prompt{Name: "beta__greet"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := dir.Replace("alpha", []catalog.Entry{
		{
			Kind:       catalog.KindResource,
			Name:       "file:///a/secret.txt",
			Descriptor: json.RawMessage(`{"uri":"file:///a/secret.txt","name":"a-secret"}`),
		},
		{
			Kind:       catalog.KindPrompt,
			Name:       "alpha__greet",
			Original:   "greet",
			Descriptor: promptA,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dir.Replace("beta", []catalog.Entry{
		{
			Kind:       catalog.KindResource,
			Name:       "file:///b/secret.txt",
			Descriptor: json.RawMessage(`{"uri":"file:///b/secret.txt","name":"b-secret"}`),
		},
		{
			Kind:       catalog.KindPrompt,
			Name:       "beta__greet",
			Original:   "greet",
			Descriptor: promptB,
		},
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return &multiTenantEnv{srv: srv, auditor: aud, alpha: alpha, beta: beta}
}

func TestMultiTenantCatalogAndInvocationIsolation(t *testing.T) {
	t.Parallel()
	env := newMultiTenantEnv(t, nil)

	status, bodyA := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/list", "", "")
	if status != http.StatusOK || !strings.Contains(bodyA, "alpha__read") || strings.Contains(bodyA, "beta__read") {
		t.Fatalf("tenant A tools/list leaked or missed: %d %s", status, bodyA)
	}
	status, bodyB := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-b", "tools/list", "", "")
	if status != http.StatusOK || !strings.Contains(bodyB, "beta__read") || strings.Contains(bodyB, "alpha__read") {
		t.Fatalf("tenant B tools/list leaked or missed: %d %s", status, bodyB)
	}

	status, resA := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "resources/list", "", "")
	if status != http.StatusOK || !strings.Contains(resA, "file:///a/secret.txt") || strings.Contains(resA, "/b/") {
		t.Fatalf("tenant A resources/list leaked: %d %s", status, resA)
	}
	status, prmA := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "prompts/list", "", "")
	if status != http.StatusOK || !strings.Contains(prmA, "alpha__greet") || strings.Contains(prmA, "beta__greet") {
		t.Fatalf("tenant A prompts/list leaked: %d %s", status, prmA)
	}

	_, denyForeign := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/call", "beta__read",
		`"name":"beta__read","arguments":{}`)
	_, denyGhost := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/call", "ghost__missing",
		`"name":"ghost__missing","arguments":{}`)
	if denyForeign != denyGhost {
		t.Fatalf("cross-tenant denial differs from missing tool (oracle leak):\nforeign=%s\nghost=%s",
			denyForeign, denyGhost)
	}
	status, readForeign := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "resources/read", "file:///b/secret.txt",
		`"uri":"file:///b/secret.txt"`)
	if status != http.StatusBadRequest ||
		!strings.Contains(readForeign, "-32602") ||
		strings.Contains(readForeign, "secret-of-") {
		t.Fatalf("cross-tenant resource read was not masked: %d %s", status, readForeign)
	}
}

func TestMultiTenantRateLimitIsolation(t *testing.T) {
	t.Parallel()
	env := newMultiTenantEnv(t, []config.RateRule{{
		Name:  "per-tenant-subject",
		Per:   "subject",
		Rate:  "1/m",
		Burst: 2,
	}})

	for range 2 {
		if st, body := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/call", "alpha__read",
			`"name":"alpha__read","arguments":{}`); st != http.StatusOK {
			t.Fatalf("tenant A within burst got %d %s", st, body)
		}
	}
	if st, body := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/call", "alpha__read",
		`"name":"alpha__read","arguments":{}`); st != http.StatusTooManyRequests {
		t.Fatalf("tenant A over burst got %d %s, want 429", st, body)
	}
	if st, body := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-b", "tools/call", "beta__read",
		`"name":"beta__read","arguments":{}`); st != http.StatusOK {
		t.Fatalf("tenant B was starved by tenant A: %d %s", st, body)
	}
}

func TestMultiTenantRequestStateCannotReplayAcrossTenantsOrClients(t *testing.T) {
	t.Parallel()
	env := newMultiTenantEnv(t, nil)

	st, body := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/call", "alpha__step",
		`"name":"alpha__step","arguments":{}`)
	if st != http.StatusOK {
		t.Fatalf("initial step call: %d %s", st, body)
	}
	var envResp struct {
		Result struct {
			RequestState string `json:"requestState"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &envResp); err != nil {
		t.Fatalf("decode response %s: %v", body, err)
	}
	sealed := envResp.Result.RequestState
	if !strings.HasPrefix(sealed, statePrefix) {
		t.Fatalf("expected sealed requestState, got %q", sealed)
	}

	replayParams := `"name":"alpha__step","arguments":{},"requestState":` + strconv.Quote(sealed)

	for name, tc := range map[string]struct {
		tok    string
		status int
		want   string
	}{
		"other tenant":  {"tok-b", http.StatusOK, "denied by policy"},
		"other client":  {"tok-a-other-client", http.StatusBadRequest, "invalid or expired requestState"},
		"other subject": {"tok-a-other-sub", http.StatusBadRequest, "invalid or expired requestState"},
	} {
		st, rb := sendAuthRPC(t, env.srv.URL+"/mcp", tc.tok, "tools/call", "alpha__step", replayParams)
		if st != tc.status || !strings.Contains(rb, tc.want) {
			t.Errorf("%s replay = %d %s, want %d containing %q", name, st, rb, tc.status, tc.want)
		}
	}

	st, okBody := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/call", "alpha__step", replayParams)
	if st != http.StatusOK || !strings.Contains(okBody, "ok:st-1") {
		t.Fatalf("legitimate owner replay failed: %d %s", st, okBody)
	}
}

func TestMultiTenantAuditAttributionUnderConcurrency(t *testing.T) {
	t.Parallel()
	env := newMultiTenantEnv(t, nil)

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if st, body := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-a", "tools/call", "alpha__read",
				`"name":"alpha__read","arguments":{}`); st != http.StatusOK {
				t.Errorf("tenant A failed: %d %s", st, body)
			}
		})
		wg.Go(func() {
			if st, body := sendAuthRPC(t, env.srv.URL+"/mcp", "tok-b", "tools/call", "beta__read",
				`"name":"beta__read","arguments":{}`); st != http.StatusOK {
				t.Errorf("tenant B failed: %d %s", st, body)
			}
		})
	}
	wg.Wait()

	events := env.auditor.take()
	if len(events) == 0 {
		t.Fatal("no audit events recorded")
	}
	for _, ev := range events {
		if ev.Phase != audit.PhaseIntent && ev.Phase != audit.PhaseOutcome {
			continue
		}
		if ev.Subject == "alice" && ev.Tool != "alpha__read" {
			t.Fatalf("alice attributed to foreign tool %q", ev.Tool)
		}
		if ev.Subject == "bob" && ev.Tool != "beta__read" {
			t.Fatalf("bob attributed to foreign tool %q", ev.Tool)
		}
	}
}
