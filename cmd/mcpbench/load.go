package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
)

const maxInFlight = 2048

type target struct {
	URL   string
	Token string
	Tool  string
}

type result struct {
	Rate        int     `json:"rate"`
	DurationS   float64 `json:"duration_s"`
	Sent        int64   `json:"sent"`
	OK          int64   `json:"ok"`
	Errors      int64   `json:"errors"`
	AchievedRPS float64 `json:"achieved_rps"`
	P50us       int64   `json:"p50_us"`
	P90us       int64   `json:"p90_us"`
	P99us       int64   `json:"p99_us"`
	P999us      int64   `json:"p999_us"`
	MaxUs       int64   `json:"max_us"`
	MeanUs      float64 `json:"mean_us"`
	Overflow    int64   `json:"histogram_overflow"`
	Shed        int64   `json:"shed_over_inflight_cap"`
}

func newClient(conns int) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        conns,
			MaxIdleConnsPerHost: conns,
			MaxConnsPerHost:     conns,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func requestBody(tool string) ([]byte, error) {
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name": tool, "arguments": map[string]any{},
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
				"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "mcpbench", "version": "1"},
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	return b, nil
}

type attack struct {
	t        target
	body     []byte
	client   *http.Client
	hist     *hdrhistogram.Histogram
	mu       sync.Mutex
	ok       atomic.Int64
	errs     atomic.Int64
	shed     atomic.Int64
	inflight atomic.Int64
	overflow atomic.Int64
}

func (a *attack) once(ctx context.Context, intended time.Time) {
	success := a.do(ctx)
	lat := time.Since(intended)
	a.mu.Lock()
	err := a.hist.RecordValue(lat.Microseconds())
	a.mu.Unlock()
	if err != nil {
		a.overflow.Add(1)
	}
	if success {
		a.ok.Add(1)
	} else {
		a.errs.Add(1)
	}
}

func (a *attack) do(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.t.URL, bytes.NewReader(a.body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", a.t.Tool)
	if a.t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.t.Token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK && bytes.Contains(b, []byte(`"result"`)) &&
		!bytes.Contains(b, []byte(`"isError":true`))
}

func run(ctx context.Context, t target, rate int, d time.Duration, client *http.Client) (result, error) {
	body, err := requestBody(t.Tool)
	if err != nil {
		return result{}, err
	}
	a := &attack{t: t, body: body, client: client, hist: hdrhistogram.New(1, 60_000_000, 3)}
	interval := time.Second / time.Duration(rate)
	start := time.Now()
	end := start.Add(d)
	var wg sync.WaitGroup
	var sent int64
	for i := int64(0); ; i++ {
		intended := start.Add(time.Duration(i) * interval)
		if !intended.Before(end) {
			break
		}
		if err := ctx.Err(); err != nil {
			wg.Wait()
			return result{}, fmt.Errorf("attack cancelled: %w", err)
		}
		if wait := time.Until(intended); wait > 0 {
			time.Sleep(wait)
		}
		sent++
		if a.inflight.Add(1) > maxInFlight {
			a.inflight.Add(-1)
			a.errs.Add(1)
			a.shed.Add(1)
			continue
		}
		wg.Go(func() {
			defer a.inflight.Add(-1)
			a.once(ctx, intended)
		})
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	return result{
		Rate:        rate,
		DurationS:   d.Seconds(),
		Sent:        sent,
		OK:          a.ok.Load(),
		Errors:      a.errs.Load(),
		AchievedRPS: float64(a.ok.Load()) / elapsed,
		P50us:       a.hist.ValueAtQuantile(50),
		P90us:       a.hist.ValueAtQuantile(90),
		P99us:       a.hist.ValueAtQuantile(99),
		P999us:      a.hist.ValueAtQuantile(99.9),
		MaxUs:       a.hist.Max(),
		MeanUs:      a.hist.Mean(),
		Overflow:    a.overflow.Load(),
		Shed:        a.shed.Load(),
	}, nil
}
