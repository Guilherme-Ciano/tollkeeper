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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
)

type fs struct {
	mu    sync.Mutex
	files map[string]string
}

type listOut struct {
	Files []string `json:"files"`
}

type pathIn struct {
	Path string `json:"path"`
}

type readOut struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type deleteOut struct {
	Deleted string `json:"deleted"`
}

func (f *fs) list(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, listOut, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := listOut{Files: []string{}}
	for k := range f.files {
		out.Files = append(out.Files, k)
	}
	sort.Strings(out.Files)
	return nil, out, nil
}

func (f *fs) read(_ context.Context, _ *mcp.CallToolRequest, in pathIn) (*mcp.CallToolResult, readOut, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.files[in.Path]
	if !ok {
		return nil, readOut{}, fmt.Errorf("%s: not found", in.Path)
	}
	return nil, readOut{Path: in.Path, Content: c}, nil
}

func (f *fs) del(_ context.Context, _ *mcp.CallToolRequest, in pathIn) (*mcp.CallToolResult, deleteOut, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[in.Path]; !ok {
		return nil, deleteOut{}, fmt.Errorf("%s: not found", in.Path)
	}
	delete(f.files, in.Path)
	return nil, deleteOut{Deleted: in.Path}, nil
}

func newServer() *mcp.Server {
	f := &fs{
		files: map[string]string{"/docs/readme.md": "# demo", "/tmp/scratch.txt": "scratch", "/tmp/old.log": "old"},
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "files", Version: "1.0.0"}, nil)
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	mcp.AddTool(srv, &mcp.Tool{Name: "list_files", Description: "List files.", Annotations: ro}, f.list)
	mcp.AddTool(srv, &mcp.Tool{Name: "read_file", Description: "Read a file.", Annotations: ro}, f.read)
	yes := true
	mcp.AddTool(srv, &mcp.Tool{
		Name: "delete_file", Description: "Delete a file permanently.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &yes},
	}, f.del)
	return srv
}

func requireToken(v *authn.Verifier, scope string, next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		p, err := v.Verify(r.Context(), raw)
		if err != nil {
			log.WarnContext(r.Context(), "token rejected", slog.String("error", err.Error()))
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if !slices.Contains(p.Scopes, scope) {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
			http.Error(w, "insufficient scope", http.StatusForbidden)
			return
		}
		log.InfoContext(
			r.Context(),
			"authorized upstream call",
			slog.String("sub", p.Subject),
			slog.String("client_id", p.ClientID),
		)
		next.ServeHTTP(w, r)
	})
}

func run() error {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8082", "HTTP listen address")
	issuer := fs.String("issuer", "http://127.0.0.1:9000", "OAuth issuer")
	jwks := fs.String("jwks", "http://127.0.0.1:9000/jwks.json", "JWKS URL")
	audience := fs.String("audience", "http://127.0.0.1:8082/mcp", "expected token audience")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ks := authn.NewKeySet(*jwks, &http.Client{Timeout: 5 * time.Second}, 2*time.Second)
	v := authn.NewVerifier(authn.FromKeySet(ks), authn.VerifierOptions{
		Issuer: *issuer, Audiences: []string{*audience}, Algorithms: []string{"EdDSA"}, Leeway: 30 * time.Second,
	})
	srv := newServer()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, DisableLocalhostProtection: true,
	})
	hs := &http.Server{
		Addr:              *listen,
		Handler:           requireToken(v, "files:upstream", h, log),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.InfoContext(ctx, "files server listening", slog.String("addr", *listen), slog.String("audience", *audience))
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
		fmt.Fprintln(os.Stderr, "files:", err)
		os.Exit(1)
	}
}
