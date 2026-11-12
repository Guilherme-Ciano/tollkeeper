package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestClientFaultExcludedFromBreaker(t *testing.T) {
	t.Parallel()
	cases := map[error]bool{
		context.Canceled: true,
		fmt.Errorf("call: %w", &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams}): true,
		&jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound}:                        true,
		&jsonrpc.Error{Code: jsonrpc.CodeInternalError}:                         false,
		errors.New("connection refused"):                                        false,
	}
	for err, want := range cases {
		if got := clientFault(err); got != want {
			t.Fatalf("clientFault(%v) = %t", err, got)
		}
	}
}

type lineSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *lineSink) Enabled(context.Context, slog.Level) bool { return true }
func (s *lineSink) WithAttrs([]slog.Attr) slog.Handler       { return s }
func (s *lineSink) WithGroup(string) slog.Handler            { return s }
func (s *lineSink) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "line" {
			s.mu.Lock()
			s.lines = append(s.lines, a.Value.String())
			s.mu.Unlock()
		}
		return true
	})
	return nil
}

func TestPipeLogSurvivesLongLines(t *testing.T) {
	t.Parallel()
	sink := &lineSink{}
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		pipeLog(pr, slog.New(sink))
		close(done)
	}()
	huge := strings.Repeat("x", 200<<10)
	for _, chunk := range []string{"first\n", huge + "\n", "after\n"} {
		if _, err := io.WriteString(pw, chunk); err != nil {
			t.Fatalf("writer blocked or failed: %v", err)
		}
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.lines[0] != "first" || sink.lines[len(sink.lines)-1] != "after" {
		t.Fatalf("lines around the oversized one were lost: %d lines", len(sink.lines))
	}
}

func TestBearerNotSentToOtherHostsOrRedirects(t *testing.T) {
	t.Parallel()
	var leaked atomic.Bool
	attacker := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer attacker.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer up.Close()
	hc, err := HTTPClient(t.Context(), config.Upstream{
		ID: "u", URL: up.URL + "/mcp",
		Auth: config.UpstreamAuth{Type: config.UpstreamAuthBearer, Token: "upstream-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, up.URL+"/mcp", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect was followed: %d", resp.StatusCode)
	}
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, attacker.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := hc.Do(req2)
	if err == nil {
		resp2.Body.Close()
	}
	if !errors.Is(err, ErrForeignHost) {
		t.Fatalf("token sent to a foreign host: %v", err)
	}
	if leaked.Load() {
		t.Fatal("upstream credential leaked to another host")
	}
}

func TestStdioEnvAllowlist(t *testing.T) {
	t.Parallel()
	env := StdioEnv(
		config.Upstream{Env: map[string]string{"B": "2", "A": "1"}, EnvPassthrough: []string{"HOME", "MISSING"}},
		func(k string) (string, bool) {
			if k == "HOME" {
				return "/home/x", true
			}
			return "", false
		},
	)
	want := []string{"HOME=/home/x", "A=1", "B=2", "PATH=/usr/local/bin:/usr/bin:/bin"}
	if !slices.Equal(env, want) {
		t.Fatalf("env %v, want %v", env, want)
	}
}

func TestCallToolFailsFastWhenSaturated(t *testing.T) {
	t.Parallel()
	u := New(
		config.Upstream{
			ID:             "u",
			MaxConcurrency: 1,
			Timeout:        time.Second,
			Breaker:        config.Breaker{Failures: 5, OpenFor: time.Second},
		},
		nameOnly(),
		nil,
		slog.New(slog.DiscardHandler),
		Hooks{},
		"test",
	)
	u.sem <- struct{}{}
	u.cs = fakeSession()
	if _, err := u.CallTool(t.Context(), Call{Tool: "t"}); !errors.Is(err, ErrSaturated) {
		t.Fatalf("expected ErrSaturated, got %v", err)
	}
}
