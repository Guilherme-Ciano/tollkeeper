package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
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
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type fakeReader struct {
	scriptedCaller
	mu       sync.Mutex
	prompts  []upstream.PromptCall
	reads    []upstream.ResourceCall
	complete []*mcp.CompleteParams
}

func (f *fakeReader) GetPrompt(_ context.Context, c upstream.PromptCall) (*mcp.GetPromptResult, error) {
	f.mu.Lock()
	f.prompts = append(f.prompts, c)
	f.mu.Unlock()
	if c.RequestState == "" && c.Arguments["ask"] == "yes" {
		return &mcp.GetPromptResult{
			InputRequests: mcp.InputRequestMap{"q": &mcp.ElicitParams{
				Message: "who?", RequestedSchema: map[string]any{"type": "object"},
			}},
			RequestState: "prompt-state",
		}, nil
	}
	return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{
		{Role: "user", Content: &mcp.TextContent{Text: "hello " + c.Arguments["who"]}},
	}}, nil
}

func (f *fakeReader) ReadResource(_ context.Context, c upstream.ResourceCall) (*mcp.ReadResourceResult, error) {
	f.mu.Lock()
	f.reads = append(f.reads, c)
	f.mu.Unlock()
	res := &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{URI: c.URI, MIMEType: "text/plain", Text: "body of " + c.URI}},
	}
	res.CacheScope, res.TTLMs = "public", 60000
	return res, nil
}

func (f *fakeReader) Complete(_ context.Context, p *mcp.CompleteParams) (*mcp.CompleteResult, error) {
	f.mu.Lock()
	f.complete = append(f.complete, p)
	f.mu.Unlock()
	return &mcp.CompleteResult{Completion: mcp.CompletionResultDetails{Values: []string{"ada"}}}, nil
}

type dirFixture struct {
	gw     *Gateway
	srv    *httptest.Server
	reader *fakeReader
	audit  *recordingAuditor
}

func newDirFixture(t *testing.T) *dirFixture {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Auth.Mode = config.AuthModeNone
	cfg.Audit.Enabled = true
	pol, err := policy.New(config.Policy{Default: config.EffectDeny, Rules: []config.Rule{
		{Name: "hide-secret", Resources: []string{"notes://secret"}, Effect: config.EffectDeny},
		{Name: "reads", Prompts: []string{"up__*"}, Resources: []string{"*"}, Effect: config.EffectAllow},
	}})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	dir := catalog.NewDirectory(100)
	prompt, err := json.Marshal(&mcp.Prompt{Name: "up__greet", Arguments: []*mcp.PromptArgument{{Name: "who"}}})
	if err != nil {
		t.Fatal(err)
	}
	res := func(kind catalog.Kind, name, desc string) catalog.Entry {
		return catalog.Entry{Kind: kind, Name: name, Descriptor: json.RawMessage(desc)}
	}
	if _, _, err := dir.Replace("up", []catalog.Entry{
		{Kind: catalog.KindPrompt, Name: "up__greet", Original: "greet", Descriptor: prompt},
		res(catalog.KindResource, "notes://today", `{"uri":"notes://today","name":"today"}`),
		res(catalog.KindResource, "notes://secret", `{"uri":"notes://secret","name":"secret"}`),
		res(catalog.KindTemplate, "notes://day/{d}", `{"uriTemplate":"notes://day/{d}","name":"day"}`),
	}); err != nil {
		t.Fatal(err)
	}
	f := &dirFixture{reader: &fakeReader{}, audit: &recordingAuditor{}}
	gw := New(Deps{
		Config: cfg, Policy: pol, Limiter: lim, Catalog: catalog.New(10), Directory: dir,
		Upstreams: map[string]Caller{"up": f.reader}, Metrics: telemetry.NewMetrics(),
		Tracer: noop.NewTracerProvider().Tracer("t"), Propagator: propagation.TraceContext{},
		Log: slog.New(slog.DiscardHandler), Audit: f.audit, StateKey: diffStateKey,
		Now: func() time.Time { return diffNow },
	})
	f.gw = gw
	f.srv = httptest.NewServer(gw.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func (f *dirFixture) rpc(t *testing.T, method, name, params string) exchange {
	t.Helper()
	h := map[string]string{"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": method}
	if name != "" {
		h["Mcp-Name"] = name
	}
	if params != "" {
		params += ","
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + params + statelessMeta + `}}`
	return (&diffSide{srv: f.srv}).do(t, h, body)
}

func TestDirectoryListsAreFilteredByPolicy(t *testing.T) {
	t.Parallel()
	f := newDirFixture(t)
	prompts := f.rpc(t, "prompts/list", "", "")
	if !strings.Contains(prompts.body, `"name":"up__greet"`) ||
		!strings.Contains(prompts.body, `"cacheScope":"private"`) {
		t.Fatalf("prompts/list: %+v", prompts)
	}
	res := f.rpc(t, "resources/list", "", "")
	if !strings.Contains(res.body, "notes://today") || strings.Contains(res.body, "notes://secret") {
		t.Fatalf("resources/list: %s", res.body)
	}
	tmpl := f.rpc(t, "resources/templates/list", "", "")
	if !strings.Contains(tmpl.body, `"uriTemplate":"notes://day/{d}"`) {
		t.Fatalf("templates: %s", tmpl.body)
	}
}

func TestPromptGetIsAdmittedRoutedAndAudited(t *testing.T) {
	t.Parallel()
	f := newDirFixture(t)
	got := f.rpc(t, "prompts/get", "up__greet", `"name":"up__greet","arguments":{"who":"ada"}`)
	if got.status != 200 || !strings.Contains(got.body, "hello ada") {
		t.Fatalf("prompts/get: %+v", got)
	}
	if len(f.reader.prompts) != 1 || f.reader.prompts[0].Name != "greet" {
		t.Fatalf("upstream saw %+v", f.reader.prompts)
	}
	events := f.audit.take()
	if len(events) != 2 || events[0].Phase != "intent" || events[1].Phase != "outcome" ||
		events[1].Tool != "up__greet" || events[1].ResultHash == "" || events[1].Method != "prompts/get" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestResourceReadRoutesTemplatesAndHidesDeniedURIs(t *testing.T) {
	t.Parallel()
	f := newDirFixture(t)
	got := f.rpc(t, "resources/read", "notes://day/2", `"uri":"notes://day/2"`)
	if got.status != 200 || !strings.Contains(got.body, "body of notes://day/2") ||
		!strings.Contains(got.body, `"cacheScope":"private"`) {
		t.Fatalf("template read: %+v", got)
	}
	secret := f.rpc(t, "resources/read", "notes://secret", `"uri":"notes://secret"`)
	missing := f.rpc(t, "resources/read", "notes://missing", `"uri":"notes://missing"`)
	for _, r := range []exchange{secret, missing} {
		if r.status != 400 || !strings.Contains(r.body, `"code":-32602`) ||
			!strings.Contains(r.body, `"data":{"uri":"notes://`) {
			t.Fatalf("not found: %+v", r)
		}
	}
	if strings.Replace(secret.body, "secret", "missing", 1) != missing.body {
		t.Fatalf("a denied resource is distinguishable from a missing one:\n%s\n%s", secret.body, missing.body)
	}
	if len(f.reader.reads) != 1 {
		t.Fatalf("denied or missing reads reached the upstream: %+v", f.reader.reads)
	}
}

func TestPromptRequestStateIsSealed(t *testing.T) {
	t.Parallel()
	f := newDirFixture(t)
	first := f.rpc(t, "prompts/get", "up__greet", `"name":"up__greet","arguments":{"ask":"yes"}`)
	if !strings.Contains(first.body, `"resultType":"input_required"`) || strings.Contains(first.body, "prompt-state") {
		t.Fatalf("first round: %s", first.body)
	}
	start := strings.Index(first.body, `"requestState":"`) + len(`"requestState":"`)
	tok := first.body[start : start+strings.IndexByte(first.body[start:], '"')]
	f.rpc(t, "prompts/get", "up__greet", `"name":"up__greet","arguments":{"ask":"yes"},"requestState":"`+tok+`"`)
	if n := len(f.reader.prompts); n != 2 || f.reader.prompts[1].RequestState != "prompt-state" {
		t.Fatalf("retry: %+v", f.reader.prompts)
	}
	bad := f.rpc(t, "prompts/get", "up__greet", `"name":"up__greet","requestState":"`+tok+`x"`)
	if bad.status != 400 || len(f.reader.prompts) != 2 {
		t.Fatalf("tampered state: %+v", bad)
	}
}

func TestCompletionUsesTheUpstreamPromptName(t *testing.T) {
	t.Parallel()
	f := newDirFixture(t)
	got := f.rpc(t, "completion/complete", "",
		`"ref":{"type":"ref/prompt","name":"up__greet"},"argument":{"name":"who","value":"a"}`)
	if got.status != 200 || !strings.Contains(got.body, `"ada"`) {
		t.Fatalf("complete: %+v", got)
	}
	if len(f.reader.complete) != 1 || f.reader.complete[0].Ref.Name != "greet" {
		t.Fatalf("upstream saw %+v", f.reader.complete)
	}
	hidden := f.rpc(t, "completion/complete", "",
		`"ref":{"type":"ref/resource","uri":"notes://secret"},"argument":{"name":"x","value":"a"}`)
	if !strings.Contains(hidden.body, `"code":-32602`) || len(f.reader.complete) != 1 {
		t.Fatalf("hidden resource completion: %+v", hidden)
	}
}

func TestResultTypeIsSetEvenWhenTheUpstreamOmitsIt(t *testing.T) {
	t.Parallel()
	f := newDirFixture(t)
	done := f.rpc(t, "prompts/get", "up__greet", `"name":"up__greet","arguments":{"who":"x"}`)
	read := f.rpc(t, "resources/read", "notes://today", `"uri":"notes://today"`)
	for _, r := range []exchange{done, read} {
		if !strings.Contains(r.body, `"resultType":"complete"`) {
			t.Fatalf("missing resultType: %s", r.body)
		}
	}
}
