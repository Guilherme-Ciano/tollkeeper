package upstream

import (
	"slices"
	"sync"
	"time"

	"github.com/sony/gobreaker/v2"
)

const latencyWindow = 128

type Diagnostics struct {
	ID                  string    `json:"id"`
	Transport           string    `json:"transport"`
	Up                  bool      `json:"up"`
	Generation          uint64    `json:"generation"`
	BreakerState        string    `json:"breaker_state"`
	InFlight            int       `json:"in_flight"`
	MaxConcurrency      int       `json:"max_concurrency"`
	TotalCalls          uint64    `json:"total_calls"`
	TotalErrors         uint64    `json:"total_errors"`
	ConsecutiveFailures uint64    `json:"consecutive_failures"`
	Reconnects          uint64    `json:"reconnects"`
	LastError           string    `json:"last_error,omitempty"`
	LastErrorAt         time.Time `json:"last_error_at,omitzero"`
	LastConnectedAt     time.Time `json:"last_connected_at,omitzero"`
	LastProbeAt         time.Time `json:"last_probe_at,omitzero"`
	LastProbeOK         bool      `json:"last_probe_ok"`
	LastLatencyMs       float64   `json:"last_latency_ms"`
	LatencyP50Ms        float64   `json:"latency_p50_ms"`
	LatencyP95Ms        float64   `json:"latency_p95_ms"`
}

type diagTracker struct {
	mu                  sync.Mutex
	totalCalls          uint64
	totalErrors         uint64
	consecutiveFailures uint64
	reconnects          uint64
	lastError           string
	lastErrorAt         time.Time
	lastConnectedAt     time.Time
	lastProbeAt         time.Time
	lastProbeOK         bool
	lastLatency         time.Duration
	samples             [latencyWindow]time.Duration
	sampleCount         int
	sampleCursor        int
}

func (d *diagTracker) recordConnect(now time.Time, reconnect bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastConnectedAt = now.UTC()
	if reconnect {
		d.reconnects++
	}
}

func (d *diagTracker) recordError(err error, now time.Time) {
	if err == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastError = err.Error()
	d.lastErrorAt = now.UTC()
}

func (d *diagTracker) recordProbe(ok bool, err error, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastProbeAt = now.UTC()
	d.lastProbeOK = ok
	if !ok && err != nil {
		d.lastError = err.Error()
		d.lastErrorAt = now.UTC()
	}
}

func (d *diagTracker) recordCall(elapsed time.Duration, err error, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalCalls++
	d.lastLatency = elapsed
	d.samples[d.sampleCursor] = elapsed
	d.sampleCursor = (d.sampleCursor + 1) % latencyWindow
	if d.sampleCount < latencyWindow {
		d.sampleCount++
	}
	if err != nil {
		d.totalErrors++
		d.consecutiveFailures++
		d.lastError = err.Error()
		d.lastErrorAt = now.UTC()
		return
	}
	d.consecutiveFailures = 0
}

func (d *diagTracker) snapshot(
	id, transport string,
	up bool,
	gen uint64,
	breaker gobreaker.State,
	inFlight, maxConc int,
) Diagnostics {
	d.mu.Lock()
	n := d.sampleCount
	buf := make([]time.Duration, n)
	copy(buf, d.samples[:n])
	out := Diagnostics{
		ID:                  id,
		Transport:           transport,
		Up:                  up,
		Generation:          gen,
		BreakerState:        breakerStateName(breaker),
		InFlight:            inFlight,
		MaxConcurrency:      maxConc,
		TotalCalls:          d.totalCalls,
		TotalErrors:         d.totalErrors,
		ConsecutiveFailures: d.consecutiveFailures,
		Reconnects:          d.reconnects,
		LastError:           d.lastError,
		LastErrorAt:         d.lastErrorAt,
		LastConnectedAt:     d.lastConnectedAt,
		LastProbeAt:         d.lastProbeAt,
		LastProbeOK:         d.lastProbeOK,
		LastLatencyMs:       durationMs(d.lastLatency),
	}
	d.mu.Unlock()
	if n > 0 {
		slices.Sort(buf)
		out.LatencyP50Ms = durationMs(percentile(buf, 50))
		out.LatencyP95Ms = durationMs(percentile(buf, 95))
	}
	return out
}

func percentile(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted)*pct + 99) / 100
	idx = max(idx-1, 0)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func durationMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func breakerStateName(s gobreaker.State) string {
	switch s {
	case gobreaker.StateClosed:
		return "closed"
	case gobreaker.StateHalfOpen:
		return "half_open"
	case gobreaker.StateOpen:
		return "open"
	default:
		return s.String()
	}
}

func (u *Upstream) Diagnostics() Diagnostics {
	return u.diag.snapshot(
		u.cfg.ID,
		u.cfg.Transport,
		u.up.Load(),
		u.gen.Load(),
		u.breaker.State(),
		len(u.sem),
		u.cfg.MaxConcurrency,
	)
}
