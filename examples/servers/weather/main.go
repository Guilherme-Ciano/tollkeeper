package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type forecastIn struct {
	City string `json:"city" jsonschema:"city name"`
}

type forecastOut struct {
	City       string `json:"city"`
	TempC      int    `json:"temp_c"`
	Conditions string `json:"conditions"`
}

type slowIn struct {
	City  string `json:"city"`
	Steps int    `json:"steps" jsonschema:"number of progress steps, max 20"`
}

func forecastFor(city string) forecastOut {
	h := fnv.New32a()
	_, _ = h.Write([]byte(city))
	v := h.Sum32()
	conds := []string{"sunny", "cloudy", "rain", "windy", "fog"}
	return forecastOut{City: city, TempC: int(v%35) - 5, Conditions: conds[v%5]}
}

func forecast(_ context.Context, _ *mcp.CallToolRequest, in forecastIn) (*mcp.CallToolResult, forecastOut, error) {
	return nil, forecastFor(in.City), nil
}

func slowForecast(ctx context.Context, req *mcp.CallToolRequest, in slowIn) (*mcp.CallToolResult, forecastOut, error) {
	steps := min(max(in.Steps, 1), 20)
	for i := range steps {
		select {
		case <-ctx.Done():
			return nil, forecastOut{}, fmt.Errorf("cancelled at step %d: %w", i, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
		if tok := req.Params.GetProgressToken(); tok != nil {
			err := req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				ProgressToken: tok, Progress: float64(i + 1), Total: float64(steps),
			})
			if err != nil {
				return nil, forecastOut{}, fmt.Errorf("notify progress: %w", err)
			}
		}
	}
	return nil, forecastFor(in.City), nil
}

func newServer(description string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "weather", Version: "1.0.0"}, nil)
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}
	mcp.AddTool(srv, &mcp.Tool{Name: "forecast", Description: description, Annotations: ro}, forecast)
	mcp.AddTool(
		srv,
		&mcp.Tool{
			Name:        "slow_forecast",
			Description: "Forecast that reports progress and honours cancellation.",
			Annotations: ro,
		},
		slowForecast,
	)
	return srv
}

func run() error {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8081", "HTTP listen address")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	description := "Deterministic fake weather forecast for a city."
	if v := os.Getenv("WEATHER_DESCRIPTION"); v != "" {
		description = v
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := newServer(description)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, DisableLocalhostProtection: true,
	})
	hs := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.InfoContext(ctx, "weather server listening", slog.String("addr", *listen))
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
		fmt.Fprintln(os.Stderr, "weather:", err)
		os.Exit(1)
	}
}
