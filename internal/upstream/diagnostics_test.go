package upstream

import (
	"errors"
	"testing"
	"time"

	"github.com/sony/gobreaker/v2"
)

func TestDiagTrackerPercentilesReconnectsAndWrap(t *testing.T) {
	t.Parallel()
	var dt diagTracker
	base := time.Date(2026, 11, 23, 16, 0, 0, 0, time.UTC)

	dt.recordConnect(base, false)
	dt.recordConnect(base.Add(time.Minute), true)
	dt.recordProbe(true, nil, base.Add(2*time.Minute))

	for i := 1; i <= 150; i++ {
		dt.recordCall(time.Duration(i)*time.Millisecond, nil, base.Add(time.Duration(i)*time.Second))
	}
	errBoom := errors.New("connection reset")
	dt.recordCall(200*time.Millisecond, errBoom, base.Add(3*time.Minute))

	snap := dt.snapshot("crm", "streamable_http", true, 2, gobreaker.StateClosed, 3, 64)
	if snap.TotalCalls != 151 || snap.TotalErrors != 1 || snap.ConsecutiveFailures != 1 {
		t.Fatalf("unexpected call counters: %+v", snap)
	}
	if snap.Reconnects != 1 || snap.BreakerState != "closed" || snap.InFlight != 3 {
		t.Fatalf("unexpected state fields: %+v", snap)
	}
	if snap.LastError != "connection reset" || !snap.LastProbeOK {
		t.Fatalf("unexpected error/probe fields: %+v", snap)
	}
	if snap.LatencyP50Ms <= 0 || snap.LatencyP95Ms < snap.LatencyP50Ms {
		t.Fatalf("invalid latency percentiles: p50=%v p95=%v", snap.LatencyP50Ms, snap.LatencyP95Ms)
	}

	dt.recordCall(5*time.Millisecond, nil, base.Add(4*time.Minute))
	snap2 := dt.snapshot("crm", "streamable_http", true, 2, gobreaker.StateHalfOpen, 0, 64)
	if snap2.ConsecutiveFailures != 0 || snap2.BreakerState != "half_open" {
		t.Fatalf("consecutive failures should reset on success: %+v", snap2)
	}
}
