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
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type note struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type store struct {
	mu    sync.RWMutex
	notes []note
}

type searchIn struct {
	Query string `json:"query" jsonschema:"text to search in titles and bodies"`
}

type searchOut struct {
	Notes []note `json:"notes"`
}

type getIn struct {
	ID string `json:"id" jsonschema:"note id"`
}

type createIn struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func (s *store) search(_ context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, searchOut, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q := strings.ToLower(in.Query)
	out := searchOut{Notes: []note{}}
	for _, n := range s.notes {
		if strings.Contains(strings.ToLower(n.Title+" "+n.Body), q) {
			out.Notes = append(out.Notes, n)
		}
	}
	return nil, out, nil
}

func (s *store) get(_ context.Context, _ *mcp.CallToolRequest, in getIn) (*mcp.CallToolResult, note, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := slices.IndexFunc(s.notes, func(n note) bool { return n.ID == in.ID })
	if i < 0 {
		return nil, note{}, fmt.Errorf("note %q not found", in.ID)
	}
	return nil, s.notes[i], nil
}

func (s *store) create(_ context.Context, _ *mcp.CallToolRequest, in createIn) (*mcp.CallToolResult, note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := note{ID: strconv.Itoa(len(s.notes) + 1), Title: in.Title, Body: in.Body}
	s.notes = append(s.notes, n)
	return nil, n, nil
}

func newServer() *mcp.Server {
	s := &store{notes: []note{
		{ID: "1", Title: "Gateway design", Body: "Hash-chained audit log with Ed25519 checkpoints."},
		{ID: "2", Title: "Groceries", Body: "Coffee, bread, olive oil."},
	}}
	srv := mcp.NewServer(&mcp.Implementation{Name: "notes", Version: "1.0.0"}, nil)
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}
	mcp.AddTool(srv, &mcp.Tool{Name: "search", Description: "Search notes by text.", Annotations: ro}, s.search)
	mcp.AddTool(srv, &mcp.Tool{Name: "get", Description: "Get a note by id.", Annotations: ro}, s.get)
	destructive := false
	mcp.AddTool(srv, &mcp.Tool{
		Name: "create", Description: "Create a note.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
	}, s.create)
	return srv
}

func run() error {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	stdio := fs.Bool("stdio", false, "serve over stdin/stdout")
	listen := fs.String("listen", "127.0.0.1:8083", "HTTP listen address")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := newServer()
	if *stdio {
		if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
			return fmt.Errorf("stdio server: %w", err)
		}
		return nil
	}
	h := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	hs := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.InfoContext(ctx, "notes server listening", slog.String("addr", *listen))
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
		fmt.Fprintln(os.Stderr, "notes:", err)
		os.Exit(1)
	}
}
