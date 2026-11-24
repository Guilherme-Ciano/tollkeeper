package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type tokenSubjectVerifier struct{}

func (tokenSubjectVerifier) Verify(_ context.Context, tok string) (identity.Principal, error) {
	sub, tenant, _ := strings.Cut(tok, "@")
	return identity.Principal{Subject: sub, Tenant: tenant, ClientID: "cli-1", Scopes: []string{"mcp:tools"}}, nil
}

type fakeTaskUpstream struct {
	mu           sync.Mutex
	innerCalls   int
	taskRPCs     int
	lastMethod   string
	lastInnerID  string
	statusByTask map[string]string
}

func (f *fakeTaskUpstream) CallTool(_ context.Context, _ upstream.Call) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "sync"}}}, nil
}

func (f *fakeTaskUpstream) CallTaskTool(_ context.Context, _ upstream.Call) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.innerCalls++
	if f.statusByTask == nil {
		f.statusByTask = map[string]string{}
	}
	f.statusByTask["inner-task-42"] = "working"
	return json.RawMessage(`{"resultType":"task","taskId":"inner-task-42","status":"working"}`), nil
}

func (f *fakeTaskUpstream) TaskRPC(_ context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.taskRPCs++
	f.lastMethod = method
	var p map[string]any
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	id, ok := p["taskId"].(string)
	if !ok {
		return nil, ErrTaskHandle
	}
	f.lastInnerID = id
	switch method {
	case MethodTasksUpdate:
		f.statusByTask[id] = "completed"
		return json.RawMessage(`{"taskId":"` + id + `","status":"completed"}`), nil
	case MethodTasksCancel:
		f.statusByTask[id] = "cancelled"
		return json.RawMessage(`{"taskId":"` + id + `","status":"cancelled"}`), nil
	default:
		st := f.statusByTask[id]
		if st == "completed" {
			return json.RawMessage(
				`{"taskId":"` + id + `","status":"completed","result":{"content":[{"type":"text","text":"done"}]}}`,
			), nil
		}
		return json.RawMessage(`{"taskId":"` + id + `","status":"` + st + `"}`), nil
	}
}

func postTaskRPC(t *testing.T, url, bearer, body string) (status int, respBody string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", protocolStateless)
	req.Header.Set("Authorization", "Bearer "+bearer)
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

func TestTasksExtensionLifecycleAndOwnershipIsolation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return now }

	cfg := config.Defaults()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Server.TasksEnabled = true
	cfg.Server.TaskTTL = 10 * time.Minute
	cfg.Server.StampProvenance = true
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Audit.Enabled = false

	pol, err := policy.New(config.Policy{
		Default: config.EffectDeny,
		Rules:   []config.Rule{{Name: "allow-all", Tools: []string{"*"}, Effect: config.EffectAllow}},
	})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(clock))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(16)
	up := &fakeTaskUpstream{}
	m := telemetry.NewMetrics()
	g := New(Deps{
		Config:     cfg,
		Verifier:   tokenSubjectVerifier{},
		Policy:     pol,
		Limiter:    lim,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"jobs": up},
		Metrics:    m,
		Tracer:     noop.NewTracerProvider().Tracer("t"),
		Propagator: propagation.TraceContext{},
		Log:        slog.New(slog.DiscardHandler),
		Now:        clock,
		StateKey:   []byte("0123456789abcdef0123456789abcdef"),
	})
	desc, err := json.Marshal(&mcp.Tool{Name: "jobs__run", InputSchema: map[string]any{"type": "object"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := cat.Replace("jobs", []catalog.Tool{
		{
			Name:       "jobs__run",
			Upstream:   "jobs",
			Original:   "run",
			Pin:        "pin-jobs-1",
			Descriptor: desc,
			Metadata: catalog.Metadata{
				Trust:          config.TrustTrusted,
				Classification: config.ClassInternal,
				Impact:         config.ImpactWrite,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(d)
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)

	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jobs__run","arguments":{"job":"etl"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}}}`
	st, respBody := postTaskRPC(t, srv.URL+"/mcp", "alice@acme", callBody)
	if st != http.StatusOK {
		t.Fatalf("task tools/call status %d: %s", st, respBody)
	}
	var createResp struct {
		Result struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			Status     string `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(respBody), &createResp); err != nil {
		t.Fatalf("unmarshal create task response %s: %v", respBody, err)
	}
	if createResp.Result.ResultType != "task" || !strings.HasPrefix(createResp.Result.TaskID, taskPrefix) {
		t.Fatalf("expected sealed tkt1 task handle, got %+v", createResp.Result)
	}
	if strings.Contains(respBody, "inner-task-42") {
		t.Fatalf("raw upstream taskId leaked to client: %s", respBody)
	}
	sealedID := createResp.Result.TaskID

	getBody := `{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"taskId":"` + sealedID + `"}}`
	st, foreignBody := postTaskRPC(t, srv.URL+"/mcp", "bob@acme", getBody)
	if st != http.StatusBadRequest || !strings.Contains(foreignBody, `"code":-32602`) {
		t.Fatalf("foreign subject must be rejected with 400/-32602, got %d %s", st, foreignBody)
	}
	if up.taskRPCs != 0 {
		t.Fatalf("foreign subject reached upstream: %d", up.taskRPCs)
	}

	st, tenantBody := postTaskRPC(t, srv.URL+"/mcp", "alice@globex", getBody)
	if st != http.StatusBadRequest || !strings.Contains(tenantBody, `"code":-32602`) {
		t.Fatalf("foreign tenant must be rejected with 400/-32602, got %d %s", st, tenantBody)
	}

	st, ownerGet := postTaskRPC(t, srv.URL+"/mcp", "alice@acme", getBody)
	if st != http.StatusOK || !strings.Contains(ownerGet, `"status":"working"`) ||
		!strings.Contains(ownerGet, sealedID) {
		t.Fatalf("owner tasks/get failed: %d %s", st, ownerGet)
	}
	if up.lastInnerID != "inner-task-42" {
		t.Fatalf("upstream did not receive unsealed inner taskId: %q", up.lastInnerID)
	}

	updateBody := `{"jsonrpc":"2.0","id":3,"method":"tasks/update","params":{"taskId":"` + sealedID + `","inputResponses":{"confirm":true}}}`
	st, updResp := postTaskRPC(t, srv.URL+"/mcp", "alice@acme", updateBody)
	if st != http.StatusOK || !strings.Contains(updResp, `"status":"completed"`) {
		t.Fatalf("owner tasks/update failed: %d %s", st, updResp)
	}

	st, doneResp := postTaskRPC(t, srv.URL+"/mcp", "alice@acme", getBody)
	if st != http.StatusOK || !strings.Contains(doneResp, `"tollkeeper.provenance"`) {
		t.Fatalf("completed task result should carry provenance stamp: %d %s", st, doneResp)
	}

	cancelBody := `{"jsonrpc":"2.0","id":4,"method":"tasks/cancel","params":{"taskId":"` + sealedID + `"}}`
	st, cancelResp := postTaskRPC(t, srv.URL+"/mcp", "alice@acme", cancelBody)
	if st != http.StatusOK || !strings.Contains(cancelResp, `"status":"cancelled"`) {
		t.Fatalf("owner tasks/cancel failed: %d %s", st, cancelResp)
	}

	now = now.Add(11 * time.Minute)
	st, expResp := postTaskRPC(t, srv.URL+"/mcp", "alice@acme", getBody)
	if st != http.StatusBadRequest || !strings.Contains(expResp, `"code":-32602`) {
		t.Fatalf("expired taskId should fail with 400/-32602, got %d %s", st, expResp)
	}
}

func TestUpstreamStreamableHTTPTaskRPC(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			ID     uint64         `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if env.Method == MethodTasksGet {
			w.Header().Set("Content-Type", "text/event-stream")
			if _, werr := w.Write(
				[]byte(
					"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"taskId\":\"t-1\",\"status\":\"working\"}}\n\n",
				),
			); werr != nil {
				t.Errorf("write sse: %v", werr)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      env.ID,
			"result":  map[string]any{"resultType": "task", "taskId": "t-1", "status": "working"},
		}); err != nil {
			t.Errorf("encode json: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	ucfg := config.Upstream{
		ID:             "jobs",
		Transport:      config.TransportStreamable,
		URL:            srv.URL,
		Timeout:        5 * time.Second,
		MaxConcurrency: 4,
		Breaker:        config.Breaker{Failures: 5, OpenFor: 10 * time.Second},
	}
	defCfg := config.Defaults()
	u := upstream.New(
		ucfg,
		defCfg.Naming(),
		nil,
		slog.New(slog.DiscardHandler),
		upstream.Hooks{},
		"test",
	)
	res, err := u.CallTaskTool(t.Context(), upstream.Call{Tool: "run", Arguments: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("CallTaskTool failed: %v", err)
	}
	if !strings.Contains(string(res), `"taskId":"t-1"`) {
		t.Fatalf("unexpected CallTaskTool result: %s", string(res))
	}
	got, err := u.TaskRPC(t.Context(), MethodTasksGet, json.RawMessage(`{"taskId":"t-1"}`))
	if err != nil {
		t.Fatalf("TaskRPC SSE failed: %v", err)
	}
	if !strings.Contains(string(got), `"status":"working"`) {
		t.Fatalf("unexpected TaskRPC SSE result: %s", string(got))
	}
}
