package ratelimit

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type backendFactory func(t *testing.T, clk *fakeClock) Backend

func memoryBackend(_ *testing.T, clk *fakeClock) Backend {
	return NewStore(clk.Now)
}

func miniredisBackend(t *testing.T, clk *fakeClock) Backend {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return NewRedis(client, RedisOptions{Prefix: "t:", Now: clk.Now, Timeout: time.Second, OnError: FallbackDeny})
}

var redisPrefixes atomic.Int64

func realRedisBackend(t *testing.T, clk *fakeClock) Backend {
	t.Helper()
	addr := os.Getenv("TOLLKEEPER_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TOLLKEEPER_TEST_REDIS_ADDR not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { client.Close() })
	prefix := "tollkeeper-test:" + strconv.FormatInt(time.Now().UnixNano(), 36) + ":" +
		strconv.FormatInt(redisPrefixes.Add(1), 10) + ":"
	return NewRedis(client, RedisOptions{Prefix: prefix, Now: clk.Now, Timeout: time.Second, OnError: FallbackDeny})
}

func TestBackendConformance(t *testing.T) {
	t.Parallel()
	backends := map[string]backendFactory{
		"memory":    memoryBackend,
		"miniredis": miniredisBackend,
		"redis":     realRedisBackend,
	}
	for name, factory := range backends {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runConformance(t, factory)
		})
	}
}

func allow(ctx context.Context, b Backend, key string, lim Limit) Result {
	return b.Allow(ctx, []Request{{Key: key, Limit: lim}})
}

func runConformance(t *testing.T, factory backendFactory) {
	t.Run("burst then deny with exact retry", func(t *testing.T) {
		clk := newClock()
		b := factory(t, clk)
		lim := NewLimit("r", 60, time.Minute, 3)
		for i := range 3 {
			res := allow(t.Context(), b, "k", lim)
			if !res.Allowed || res.Remaining != 2-i || res.Rule != "r" {
				t.Fatalf("request %d: %+v", i, res)
			}
		}
		res := allow(t.Context(), b, "k", lim)
		if res.Allowed || res.RetryAfter != time.Second || res.Rule != "r" {
			t.Fatalf("4th request: %+v", res)
		}
		clk.Advance(time.Second)
		if !allow(t.Context(), b, "k", lim).Allowed {
			t.Fatal("denied after one emission interval")
		}
		if allow(t.Context(), b, "k", lim).Allowed {
			t.Fatal("allowed without refill")
		}
	})
	t.Run("sustained rate", func(t *testing.T) {
		clk := newClock()
		b := factory(t, clk)
		lim := NewLimit("r", 10, time.Second, 1)
		allowed := 0
		for range 200 {
			if allow(t.Context(), b, "k", lim).Allowed {
				allowed++
			}
			clk.Advance(10 * time.Millisecond)
		}
		if allowed != 20 {
			t.Fatalf("allowed %d over 2s at 10/s, want 20", allowed)
		}
	})
	t.Run("all or nothing across rules", func(t *testing.T) {
		clk := newClock()
		b := factory(t, clk)
		loose := NewLimit("loose", 100, time.Second, 100)
		tight := NewLimit("tight", 1, time.Minute, 1)
		reqs := []Request{{Key: "a", Limit: loose}, {Key: "b", Limit: tight}}
		if !b.Allow(t.Context(), reqs).Allowed {
			t.Fatal("first request denied")
		}
		for range 20 {
			if res := b.Allow(t.Context(), reqs); res.Allowed || res.Rule != "tight" {
				t.Fatalf("expected tight denial, got %+v", res)
			}
		}
		if res := allow(t.Context(), b, "a", loose); !res.Allowed || res.Remaining != 98 {
			t.Fatalf("denied requests consumed the loose rule: %+v", res)
		}
	})
	t.Run("tightest rule reported on success", func(t *testing.T) {
		clk := newClock()
		b := factory(t, clk)
		res := b.Allow(t.Context(), []Request{
			{Key: "x", Limit: NewLimit("wide", 100, time.Second, 50)},
			{Key: "y", Limit: NewLimit("narrow", 10, time.Second, 2)},
		})
		if !res.Allowed || res.Rule != "narrow" || res.Remaining != 1 {
			t.Fatalf("got %+v", res)
		}
	})
	t.Run("keys are isolated", func(t *testing.T) {
		clk := newClock()
		b := factory(t, clk)
		lim := NewLimit("r", 1, time.Hour, 1)
		if !allow(t.Context(), b, "alice", lim).Allowed || allow(t.Context(), b, "alice", lim).Allowed {
			t.Fatal("alice bucket wrong")
		}
		if !allow(t.Context(), b, "bob", lim).Allowed {
			t.Fatal("bob limited by alice")
		}
	})
	t.Run("concurrent callers never exceed burst", func(t *testing.T) {
		clk := newClock()
		b := factory(t, clk)
		lim := NewLimit("r", 1, time.Hour, 25)
		var allowed atomic.Int64
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				for range 10 {
					if allow(t.Context(), b, "shared", lim).Allowed {
						allowed.Add(1)
					}
				}
			})
		}
		wg.Wait()
		if got := allowed.Load(); got != 25 {
			t.Fatalf("allowed %d, want exactly 25", got)
		}
	})
}

func TestRedisBackendFallback(t *testing.T) {
	t.Parallel()
	clk := newClock()
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond, MaxRetries: -1})
	t.Cleanup(func() { dead.Close() })
	lim := NewLimit("r", 1, time.Hour, 1)
	var failures atomic.Int64
	local := NewRedis(dead, RedisOptions{Now: clk.Now, Timeout: 100 * time.Millisecond, Failed: func(error) { failures.Add(1) }})
	if !allow(t.Context(), local, "k", lim).Allowed {
		t.Fatal("local fallback denied the first request")
	}
	if allow(t.Context(), local, "k", lim).Allowed {
		t.Fatal("local fallback did not enforce the limit")
	}
	deny := NewRedis(dead, RedisOptions{Now: clk.Now, Timeout: 100 * time.Millisecond, OnError: FallbackDeny})
	if res := allow(t.Context(), deny, "k", lim); res.Allowed || res.RetryAfter <= 0 {
		t.Fatalf("deny fallback: %+v", res)
	}
	if failures.Load() != 2 {
		t.Fatalf("failure hook called %d times, want 2", failures.Load())
	}
}

func TestRedisUsesServerTimeWithoutClock(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	b := NewRedis(client, RedisOptions{Timeout: time.Second, OnError: FallbackDeny})
	lim := NewLimit("r", 1, time.Hour, 1)
	if !allow(t.Context(), b, "k", lim).Allowed {
		t.Fatal("first request denied")
	}
	if res := allow(t.Context(), b, "k", lim); res.Allowed || res.RetryAfter <= 0 {
		t.Fatalf("second request: %+v", res)
	}
	ttl := mr.TTL("k")
	if ttl <= 0 || ttl > time.Hour+time.Second {
		t.Fatalf("key ttl %v, want within (0, 1h]", ttl)
	}
}
