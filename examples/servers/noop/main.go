package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func run() error {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8090", "HTTP listen address")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := mcp.NewServer(&mcp.Implementation{Name: "noop", Version: "1.0.0"}, nil)
	ok := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}
	srv.AddTool(&mcp.Tool{
		Name: "noop", Description: "Returns ok immediately.", InputSchema: map[string]any{"type": "object"},
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return ok, nil })
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, DisableLocalhostProtection: true,
	})
	hs := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.InfoContext(ctx, "noop server listening", slog.String("addr", *listen))
	return serve(ctx, hs, log)
}

func serve(ctx context.Context, hs *http.Server, log *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() { errCh <- hs.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := hs.Shutdown(sctx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		log.InfoContext(ctx, "server stopped")
		return nil
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "noop:", err)
		os.Exit(1)
	}
}
