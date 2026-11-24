package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sony/gobreaker/v2"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func newTestMCPServer(t *testing.T, slowTool bool) *mcp.Server {
	t.Helper()
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "test-upstream", Version: "1.0.0"},
		&mcp.ServerOptions{
			CompletionHandler: func(_ context.Context, req *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
				if req.Params.Argument.Value == "fail" {
					return nil, errors.New("completion boom")
				}
				return &mcp.CompleteResult{
					Completion: mcp.CompletionResultDetails{
						Values: []string{"alpha", "beta"},
					},
				}, nil
			},
		},
	)

	srv.AddTool(&mcp.Tool{
		Name:        "read_item",
		Description: "Read an item",
		InputSchema: map[string]any{"type": "object"},
		Annotations: &mcp.ToolAnnotations{
			Title:           "Read Item",
			ReadOnlyHint:    true,
			IdempotentHint:  true,
			DestructiveHint: new(true),
			OpenWorldHint:   new(false),
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if req.Params.Meta != nil {
			if tok, ok := req.Params.Meta["progressToken"]; ok {
				if err := req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
					ProgressToken: tok,
					Progress:      1,
					Total:         2,
					Message:       "halfway",
				}); err != nil {
					t.Logf("notify progress: %v", err)
				}
			}
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
		}, nil
	})

	srv.AddTool(&mcp.Tool{
		Name:        "write_item",
		Description: "Write an item",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if slowTool {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
		return nil, errors.New("backend failure")
	})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "summarize",
		Description: "Summarize text",
	}, func(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "summary",
			Messages: []*mcp.PromptMessage{
				{Role: "user", Content: &mcp.TextContent{Text: "hello"}},
			},
		}, nil
	})

	srv.AddResource(&mcp.Resource{
		URI:      "file:///readme.md",
		Name:     "readme",
		MIMEType: "text/markdown",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: req.Params.URI, Text: "# Readme"},
			},
		}, nil
	})

	srv.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "file:///docs/{id}",
		Name:        "doc",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: req.Params.URI, Text: "doc body"},
			},
		}, nil
	})

	return srv
}

func TestUpstreamLifecycleAndDirectory(t *testing.T) {
	t.Parallel()
	srv := newTestMCPServer(t, false)
	var attempts atomic.Int32
	var srvSessions atomic.Pointer[mcp.ServerSession]

	factory := func(ctx context.Context) (mcp.Transport, func(), error) {
		n := attempts.Add(1)
		if n == 1 {
			return nil, nil, errors.New("initial dial failed")
		}
		ct, st := mcp.NewInMemoryTransports()
		ss, err := srv.Connect(ctx, st, nil)
		if err != nil {
			return nil, nil, err
		}
		srvSessions.Store(ss)
		return ct, func() {
			if err := ss.Close(); err != nil && !errors.Is(err, io.EOF) {
				t.Logf("server session close: %v", err)
			}
		}, nil
	}

	var upEvents atomic.Int32
	var breakerStates atomic.Int32
	cfg := config.Upstream{
		ID:             "demo",
		Transport:      config.TransportStreamable,
		Timeout:        2 * time.Second,
		MaxConcurrency: 2,
		RestartBackoff: 5 * time.Millisecond,
		RestartMax:     20 * time.Millisecond,
		Breaker: config.Breaker{
			Failures: 2,
			OpenFor:  50 * time.Millisecond,
		},
	}

	u := New(cfg, catalog.Naming{Separator: "__"}, factory, slog.New(slog.DiscardHandler), Hooks{
		Up: func(_ string, _ bool) {
			upEvents.Add(1)
		},
		BreakerState: func(_ string, _ int) {
			breakerStates.Add(1)
		},
	}, "1.0.0")

	if u.ID() != "demo" {
		t.Fatalf("ID() = %q", u.ID())
	}
	if u.Up() {
		t.Fatal("expected Up() == false before Run")
	}
	if _, err := u.Tools(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for Tools, got %v", err)
	}
	if _, err := u.Directory(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for Directory, got %v", err)
	}
	if _, err := u.CallTool(t.Context(), Call{Tool: "read_item"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for CallTool, got %v", err)
	}

	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.Run(runCtx)
	}()

	select {
	case <-u.Ready():
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for Ready")
	}

	if !u.Up() || u.Generation() != 1 {
		t.Fatalf("expected Up=true gen=1, got up=%v gen=%d", u.Up(), u.Generation())
	}

	tools, err := u.Tools(t.Context())
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	var foundRead, foundWrite bool
	for _, tl := range tools {
		switch tl.Original {
		case "read_item":
			foundRead = true
			if !tl.Annotations.ReadOnly || tl.Annotations.Destructive || tl.Annotations.OpenWorld {
				t.Fatalf("unexpected read_item annotations: %+v", tl.Annotations)
			}
		case "write_item":
			foundWrite = true
			if !tl.Annotations.Destructive || !tl.Annotations.OpenWorld {
				t.Fatalf("unexpected write_item default annotations: %+v", tl.Annotations)
			}
		}
	}
	if !foundRead || !foundWrite {
		t.Fatalf("missing expected tools: read=%v write=%v", foundRead, foundWrite)
	}

	entries, err := u.Directory(t.Context())
	if err != nil {
		t.Fatalf("Directory: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("expected >= 3 directory entries, got %d", len(entries))
	}

	var gotProgress atomic.Int32
	res, err := u.CallTool(t.Context(), Call{
		Tool:      "read_item",
		Arguments: json.RawMessage(`{}`),
		Progress: func(p *mcp.ProgressNotificationParams) {
			if p != nil && p.Message == "halfway" {
				gotProgress.Add(1)
			}
		},
	})
	if err != nil {
		t.Fatalf("CallTool read_item: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("unexpected CallTool content len: %d", len(res.Content))
	}
	if gotProgress.Load() == 0 {
		t.Fatal("expected progress notification relay")
	}

	promptRes, err := u.GetPrompt(t.Context(), PromptCall{Name: "summarize"})
	if err != nil || promptRes.Description != "summary" {
		t.Fatalf("GetPrompt: res=%+v err=%v", promptRes, err)
	}

	resRead, err := u.ReadResource(t.Context(), ResourceCall{URI: "file:///readme.md"})
	if err != nil || len(resRead.Contents) != 1 {
		t.Fatalf("ReadResource: res=%+v err=%v", resRead, err)
	}

	compRes, err := u.Complete(t.Context(), &mcp.CompleteParams{
		Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "summarize"},
		Argument: mcp.CompleteParamsArgument{Name: "topic", Value: "a"},
	})
	if err != nil || len(compRes.Completion.Values) != 2 {
		t.Fatalf("Complete: res=%+v err=%v", compRes, err)
	}
	if _, err := u.Complete(t.Context(), &mcp.CompleteParams{
		Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "summarize"},
		Argument: mcp.CompleteParamsArgument{Name: "topic", Value: "fail"},
	}); err == nil {
		t.Fatal("expected Complete error")
	}

	if !u.probe(t.Context(), u.session()) {
		t.Fatal("expected probe to succeed")
	}
	canceledCtx, cancelProbe := context.WithCancel(t.Context())
	cancelProbe()
	if u.probe(canceledCtx, u.session()) {
		t.Fatal("expected probe with canceled context to fail")
	}

	u.sem <- struct{}{}
	u.sem <- struct{}{}
	if _, err := u.CallTool(t.Context(), Call{Tool: "read_item"}); !errors.Is(err, ErrSaturated) {
		t.Fatalf("expected ErrSaturated, got %v", err)
	}
	if _, err := u.GetPrompt(t.Context(), PromptCall{Name: "summarize"}); !errors.Is(err, ErrSaturated) {
		t.Fatalf("expected ErrSaturated for GetPrompt, got %v", err)
	}
	<-u.sem
	<-u.sem

	for range 2 {
		if _, err := u.CallTool(t.Context(), Call{Tool: "write_item"}); err == nil {
			t.Fatal("expected write_item error")
		}
	}
	if _, err := u.CallTool(t.Context(), Call{Tool: "write_item"}); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("expected ErrBreakerOpen, got %v", err)
	}
	if breakerStates.Load() == 0 {
		t.Fatal("expected BreakerState hook to fire")
	}

	diag := u.Diagnostics()
	if diag.ID != "demo" || !diag.Up || diag.TotalCalls == 0 || diag.TotalErrors == 0 || diag.BreakerState != "open" {
		t.Fatalf("unexpected diagnostics: %+v", diag)
	}

	if ss := srvSessions.Load(); ss != nil {
		if err := ss.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Logf("close server session: %v", err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for u.Generation() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if u.Generation() < 2 {
		t.Fatalf("expected reconnect to bump generation >= 2, got %d", u.Generation())
	}
	if u.Diagnostics().Reconnects == 0 {
		t.Fatal("expected Reconnects > 0 after disconnect")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
	if upEvents.Load() < 2 {
		t.Fatalf("expected >= 2 Up hook events, got %d", upEvents.Load())
	}
}

func TestUpstreamTimeoutAndHelpers(t *testing.T) {
	t.Parallel()
	srv := newTestMCPServer(t, true)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer func() {
		if cerr := ss.Close(); cerr != nil && !errors.Is(cerr, io.EOF) {
			t.Logf("close server: %v", cerr)
		}
	}()

	cfg := config.Upstream{
		ID:             "slow",
		Transport:      config.TransportStreamable,
		Timeout:        40 * time.Millisecond,
		MaxConcurrency: 2,
		Breaker:        config.Breaker{Failures: 5, OpenFor: time.Second},
	}
	u := New(cfg, catalog.Naming{Separator: "__"}, func(context.Context) (mcp.Transport, func(), error) {
		return ct, func() {}, nil
	}, slog.New(slog.DiscardHandler), Hooks{}, "1.0.0")

	cs, cleanup, err := u.connect(t.Context())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cleanup()
	u.setUp(cs)
	defer func() {
		if cerr := cs.Close(); cerr != nil && !errors.Is(cerr, io.EOF) {
			t.Logf("close client: %v", cerr)
		}
	}()

	if _, err := u.CallTool(t.Context(), Call{Tool: "write_item"}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}

	tctx, tcancel := context.WithTimeoutCause(t.Context(), time.Nanosecond, ErrTimeout)
	defer tcancel()
	<-tctx.Done()
	if err := u.wrap(tctx, "read", "x", errors.New("boom")); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected wrap timeout, got %v", err)
	}
	if err := u.wrap(
		t.Context(),
		"read",
		"x",
		errors.New("boom"),
	); err == nil ||
		!strings.Contains(err.Error(), "read slow/x") {
		t.Fatalf("unexpected wrap generic: %v", err)
	}

	if jitter(0) != 0 || jitter(-time.Second) != 0 {
		t.Fatal("expected jitter(<=0) == 0")
	}
	if j := jitter(10 * time.Millisecond); j < 5*time.Millisecond || j > 10*time.Millisecond {
		t.Fatalf("jitter out of range: %v", j)
	}
	if !sleep(t.Context(), time.Millisecond) {
		t.Fatal("expected sleep to complete")
	}
	cctx, ccancel := context.WithCancel(t.Context())
	ccancel()
	if sleep(cctx, time.Second) {
		t.Fatal("expected canceled sleep to return false")
	}

	if !clientFault(context.Canceled) {
		t.Fatal("context.Canceled should be clientFault")
	}
	if !clientFault(ErrDelegationDenied) {
		t.Fatal("ErrDelegationDenied should be clientFault")
	}
	if !clientFault(&jsonrpc.Error{Code: jsonrpc.CodeInvalidParams}) {
		t.Fatal("CodeInvalidParams should be clientFault")
	}
	if !clientFault(&jsonrpc.Error{Code: CodeMissingCapabilities}) {
		t.Fatal("CodeMissingCapabilities should be clientFault")
	}
	if clientFault(errors.New("server 500")) {
		t.Fatal("generic error should not be clientFault")
	}

	if breakerStateName(gobreaker.StateClosed) != "closed" ||
		breakerStateName(gobreaker.StateHalfOpen) != "half_open" ||
		breakerStateName(gobreaker.StateOpen) != "open" ||
		breakerStateName(gobreaker.State(99)) == "" {
		t.Fatal("unexpected breakerStateName mapping")
	}
	if percentile(nil, 50) != 0 {
		t.Fatal("expected 0 for empty percentile")
	}
	if got := percentile(
		[]time.Duration{10 * time.Millisecond, 20 * time.Millisecond},
		200,
	); got != 20*time.Millisecond {
		t.Fatalf("expected clamped max percentile, got %v", got)
	}

	u.relayProgress(nil)
	u.relayProgress(&mcp.ProgressNotificationParams{ProgressToken: 123})
	u.relayProgress(&mcp.ProgressNotificationParams{ProgressToken: "unknown"})

	u.diag.recordError(nil, time.Now())
	u.diag.recordError(errors.New("err1"), time.Now())
	if u.Diagnostics().LastError != "err1" {
		t.Fatalf("expected LastError=err1, got %q", u.Diagnostics().LastError)
	}
}

func TestTransportFactoryAndPipeLog(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)

	tf, err := Factory(t.Context(), config.Upstream{
		ID:        "stream",
		Transport: config.TransportStreamable,
		URL:       "https://mcp.example.com/rpc",
	}, log, LookupEnv)
	if err != nil {
		t.Fatalf("streamable Factory: %v", err)
	}
	tr, cleanup, err := tf(t.Context())
	if err != nil || tr == nil {
		t.Fatalf("streamable factory invoke: tr=%v err=%v", tr, err)
	}
	cleanup()

	if _, err := Factory(t.Context(), config.Upstream{
		ID:        "bad",
		Transport: "grpc",
	}, log, LookupEnv); !errors.Is(err, ErrUnknownTransport) {
		t.Fatalf("expected ErrUnknownTransport, got %v", err)
	}

	stf, err := Factory(t.Context(), config.Upstream{
		ID:        "stdio",
		Transport: config.TransportStdio,
		Command:   []string{"echo", "hi"},
		Sandbox:   config.StdioSandbox{Mode: config.SandboxModeOff},
	}, log, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("stdio Factory: %v", err)
	}
	str, scleanup, err := stf(t.Context())
	if err != nil || str == nil {
		t.Fatalf("stdio factory invoke: tr=%v err=%v", str, err)
	}
	scleanup()

	if _, err := HTTPClient(t.Context(), config.Upstream{
		ID:  "cc",
		URL: "https://mcp.example.com/rpc",
		Auth: config.UpstreamAuth{
			Type:         config.UpstreamAuthClientCredentials,
			ClientID:     "a",
			ClientSecret: "b",
			TokenURL:     "https://idp.example.com/token",
			Resource:     "https://mcp.example.com",
		},
	}); err != nil {
		t.Fatalf("HTTPClient client_credentials: %v", err)
	}
	if _, err := HTTPClient(t.Context(), config.Upstream{
		ID:  "te",
		URL: "https://mcp.example.com/rpc",
		Auth: config.UpstreamAuth{
			Type:          config.UpstreamAuthTokenExchange,
			TokenURL:      "https://idp.example.com/token",
			ClientID:      "a",
			ClientSecret:  "b",
			TokenExchange: &config.TokenExchange{Timeout: time.Second},
		},
	}); err != nil {
		t.Fatalf("HTTPClient token_exchange: %v", err)
	}
	if _, err := HTTPClient(t.Context(), config.Upstream{
		ID:   "unk",
		URL:  "https://mcp.example.com/rpc",
		Auth: config.UpstreamAuth{Type: "bogus"},
	}); !errors.Is(err, ErrUnknownTransport) {
		t.Fatalf("expected ErrUnknownTransport for unknown auth, got %v", err)
	}

	longLine := strings.Repeat("a", maxStderrLine+128) + "\nshort\n"
	pipeLog(strings.NewReader(longLine), log)

	_, _ = LookupEnv("PATH")
}
