package upstream

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestDirectoryListsAndReadsFromARealServer(t *testing.T) {
	t.Parallel()
	srv := mcp.NewServer(&mcp.Implementation{Name: "up", Version: "1"}, nil)
	srv.AddPrompt(
		&mcp.Prompt{Name: "greet"},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{
				{Role: "user", Content: &mcp.TextContent{Text: "hi " + req.Params.Arguments["who"]}},
			}}, nil
		},
	)
	read := func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "x"}}}, nil
	}
	srv.AddResource(&mcp.Resource{URI: "notes://today", Name: "today"}, read)
	srv.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "notes://day/{d}", Name: "day"}, read)
	hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	))
	defer hs.Close()
	u := New(
		config.Upstream{
			ID: "notes", MaxConcurrency: 4, Timeout: 5 * time.Second,
			Breaker: config.Breaker{Failures: 5, OpenFor: time.Second},
		},
		nameOnly(),
		func(context.Context) (mcp.Transport, func(), error) {
			return &mcp.StreamableClientTransport{Endpoint: hs.URL}, func() {}, nil
		},
		slog.New(slog.DiscardHandler),
		Hooks{},
		"test",
	)
	cs, cleanup, err := u.connect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer cs.Close()
	u.cs = cs
	entries, err := u.Directory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := map[catalog.Kind]string{}
	for _, e := range entries {
		got[e.Kind] = e.Name + "|" + e.Original
	}
	want := map[catalog.Kind]string{
		catalog.KindPrompt:   "notes__greet|greet",
		catalog.KindResource: "notes://today|notes://today",
		catalog.KindTemplate: "notes://day/{d}|notes://day/{d}",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	pr, err := u.GetPrompt(t.Context(), PromptCall{Name: "greet", Arguments: map[string]string{"who": "ada"}})
	if err != nil || len(pr.Messages) != 1 {
		t.Fatalf("get prompt: %+v %v", pr, err)
	}
	rr, err := u.ReadResource(t.Context(), ResourceCall{URI: "notes://day/7"})
	if err != nil || rr.Contents[0].URI != "notes://day/7" {
		t.Fatalf("read resource: %+v %v", rr, err)
	}
}
