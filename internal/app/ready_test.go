package app

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func runApp(t *testing.T, cfg config.Config) *App {
	t.Helper()
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		u.Timeout, u.MaxConcurrency = 2*time.Second, 16
		u.Breaker = config.Breaker{Failures: 5, OpenFor: time.Second}
		u.RestartBackoff, u.RestartMax = 50*time.Millisecond, time.Second
	}
	ctx, cancel := context.WithCancel(t.Context())
	a, err := Build(ctx, cfg, slog.New(slog.DiscardHandler), "test")
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
	for a.Addr("admin") == "" {
		time.Sleep(time.Millisecond)
	}
	return a
}

func readyStatus(t *testing.T, a *App) int {
	t.Helper()
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://"+a.Addr("admin")+"/readyz",
		http.NoBody,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestReadyOnlyAfterCatalogSync(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})
	cfg := testConfig(t, up.URL)
	cfg.Server.ResyncDebounce = 300 * time.Millisecond
	a := runApp(t, cfg)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if readyStatus(t, a) == http.StatusOK {
			if n := a.Catalog().Snapshot().Len(); n == 0 {
				t.Fatal("readyz reported ready before the upstream's tools were registered")
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("gateway never became ready")
}

func TestNotReadyWithoutReachableUpstream(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1/mcp")
	a := runApp(t, cfg)
	time.Sleep(300 * time.Millisecond)
	if s := readyStatus(t, a); s != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d with no reachable upstream", s)
	}
}
