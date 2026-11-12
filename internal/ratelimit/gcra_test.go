package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func newClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0)}
}

func TestGCRABurstThenDeny(t *testing.T) {
	t.Parallel()
	clk := newClock()
	s := NewStore(clk.Now)
	lim := NewLimit("r", 60, time.Minute, 3)
	for i := range 3 {
		res := s.Allow(t.Context(), []Request{{Key: "k", Limit: lim}})
		if !res.Allowed {
			t.Fatalf("request %d denied within burst", i)
		}
		if res.Remaining != 2-i {
			t.Fatalf("request %d remaining=%d want %d", i, res.Remaining, 2-i)
		}
	}
	res := s.Allow(t.Context(), []Request{{Key: "k", Limit: lim}})
	if res.Allowed {
		t.Fatal("4th request allowed beyond burst")
	}
	if res.RetryAfter != time.Second {
		t.Fatalf("retry after %v, want 1s", res.RetryAfter)
	}
	clk.Advance(time.Second)
	if !s.Allow(t.Context(), []Request{{Key: "k", Limit: lim}}).Allowed {
		t.Fatal("request denied after one emission interval")
	}
	if s.Allow(t.Context(), []Request{{Key: "k", Limit: lim}}).Allowed {
		t.Fatal("second request allowed without refill")
	}
}

func TestGCRASustainedRate(t *testing.T) {
	t.Parallel()
	clk := newClock()
	s := NewStore(clk.Now)
	lim := NewLimit("r", 10, time.Second, 1)
	allowed := 0
	for range 1000 {
		if s.Allow(t.Context(), []Request{{Key: "k", Limit: lim}}).Allowed {
			allowed++
		}
		clk.Advance(10 * time.Millisecond)
	}
	if allowed != 100 {
		t.Fatalf("allowed %d over 10s at 10/s, want 100", allowed)
	}
}

func TestMultiRuleAllOrNothing(t *testing.T) {
	t.Parallel()
	clk := newClock()
	s := NewStore(clk.Now)
	loose := NewLimit("loose", 100, time.Second, 100)
	tight := NewLimit("tight", 1, time.Minute, 1)
	reqs := []Request{{Key: "a", Limit: loose}, {Key: "b", Limit: tight}}
	if !s.Allow(t.Context(), reqs).Allowed {
		t.Fatal("first request denied")
	}
	for range 50 {
		res := s.Allow(t.Context(), reqs)
		if res.Allowed || res.Rule != "tight" {
			t.Fatalf("expected tight denial, got %+v", res)
		}
	}
	res := s.Allow(t.Context(), []Request{{Key: "a", Limit: loose}})
	if !res.Allowed || res.Remaining != 98 {
		t.Fatalf("loose bucket consumed by denied requests: %+v", res)
	}
}

func TestGCRAConcurrentNeverExceedsBurst(t *testing.T) {
	t.Parallel()
	clk := newClock()
	s := NewStore(clk.Now)
	lim := NewLimit("r", 1, time.Hour, 50)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 20 {
				if s.Allow(t.Context(), []Request{{Key: "shared", Limit: lim}}).Allowed {
					allowed.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if got := allowed.Load(); got != 50 {
		t.Fatalf("allowed %d of 1280 concurrent requests, want exactly 50", got)
	}
}

func TestSweepEvictsIdleKeys(t *testing.T) {
	t.Parallel()
	clk := newClock()
	s := NewStore(clk.Now)
	lim := NewLimit("r", 1, time.Second, 1)
	s.Allow(t.Context(), []Request{{Key: "a", Limit: lim}})
	s.Allow(t.Context(), []Request{{Key: "b", Limit: lim}})
	if s.Sweep() != 0 {
		t.Fatal("swept active keys")
	}
	clk.Advance(2 * time.Second)
	if n := s.Sweep(); n != 2 || s.Len() != 0 {
		t.Fatalf("swept %d, len %d", n, s.Len())
	}
}

func TestLimiterKeys(t *testing.T) {
	t.Parallel()
	clk := newClock()
	l, err := New(config.RateLimits{Rules: []config.RateRule{
		{Name: "per-tool", Tools: []string{"weather__*"}, Per: config.PerSubjectTool, Rate: "1/m", Burst: 1},
	}}, NewStore(clk.Now))
	if err != nil {
		t.Fatal(err)
	}
	alice := Subject{Sub: "alice", Tool: "weather__forecast"}
	if !l.Allow(t.Context(), alice).Allowed || l.Allow(t.Context(), alice).Allowed {
		t.Fatal("per subject_tool limit not enforced")
	}
	if !l.Allow(t.Context(), Subject{Sub: "bob", Tool: "weather__forecast"}).Allowed {
		t.Fatal("bob shares alice's bucket")
	}
	if !l.Allow(t.Context(), Subject{Sub: "alice", Tool: "weather__slow"}).Allowed {
		t.Fatal("different tool shares bucket")
	}
	if !l.Allow(t.Context(), Subject{Sub: "alice", Tool: "notes__get"}).Allowed {
		t.Fatal("unmatched tool limited")
	}
	if _, err := New(
		config.RateLimits{Rules: []config.RateRule{{Name: "x", Rate: "fast"}}},
		NewStore(nil),
	); err == nil {
		t.Fatal("bad rate accepted")
	}
}

func BenchmarkGCRA(b *testing.B) {
	s := NewStore(nil)
	lim := NewLimit("r", 1_000_000_000, time.Second, 1_000_000)
	reqs := []Request{{Key: "alice\x00notes__search", Limit: lim}}
	b.Run("single", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			s.Allow(b.Context(), reqs)
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				s.Allow(b.Context(), reqs)
			}
		})
	})
}
