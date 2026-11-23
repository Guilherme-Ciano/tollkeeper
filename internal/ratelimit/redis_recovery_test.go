package ratelimit

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestRedisOutageFallbackAndRecovery(t *testing.T) {
	t.Parallel()

	t.Run("local_fallback_then_redis_recovery", func(t *testing.T) {
		t.Parallel()
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{
			Addr:         mr.Addr(),
			DialTimeout:  100 * time.Millisecond,
			ReadTimeout:  100 * time.Millisecond,
			WriteTimeout: 100 * time.Millisecond,
			MaxRetries:   0,
		})
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("close redis client: %v", err)
			}
		})

		var errs atomic.Int32
		backend := NewRedis(client, RedisOptions{
			Prefix:  "tk:rec:",
			Timeout: 150 * time.Millisecond,
			OnError: FallbackLocal,
			Local:   NewStore(nil),
			Failed:  func(error) { errs.Add(1) },
		})
		lim, err := New(config.RateLimits{
			Rules: []config.RateRule{
				{Name: "tenant-cap", Tools: []string{"*"}, Per: config.PerTenant, Rate: "60/m", Burst: 2},
			},
		}, backend)
		if err != nil {
			t.Fatal(err)
		}

		ctx := t.Context()
		if res := lim.Allow(ctx, Subject{Tenant: "acme", Tool: "t"}); !res.Allowed {
			t.Fatalf("initial redis allow failed: %+v", res)
		}

		mr.Close()

		if res := lim.Allow(ctx, Subject{Tenant: "acme", Tool: "t"}); !res.Allowed {
			t.Fatalf("local fallback should admit during outage: %+v", res)
		}
		if errs.Load() == 0 {
			t.Fatal("expected redis backend error hook during outage")
		}

		if err := mr.Restart(); err != nil {
			t.Fatalf("restart miniredis: %v", err)
		}

		if res := lim.Allow(ctx, Subject{Tenant: "globex", Tool: "t"}); !res.Allowed {
			t.Fatalf("first call after redis restart failed: %+v", res)
		}
		if res := lim.Allow(ctx, Subject{Tenant: "globex", Tool: "t"}); !res.Allowed {
			t.Fatalf("second call after redis restart failed: %+v", res)
		}
		if res := lim.Allow(ctx, Subject{Tenant: "globex", Tool: "t"}); res.Allowed {
			t.Fatalf("third call after redis restart should be limited by redis: %+v", res)
		}
	})

	t.Run("deny_fallback_recovers_after_restart", func(t *testing.T) {
		t.Parallel()
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{
			Addr:         mr.Addr(),
			DialTimeout:  100 * time.Millisecond,
			ReadTimeout:  100 * time.Millisecond,
			WriteTimeout: 100 * time.Millisecond,
			MaxRetries:   0,
		})
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("close redis client: %v", err)
			}
		})

		backend := NewRedis(client, RedisOptions{
			Prefix:  "tk:deny:",
			Timeout: 150 * time.Millisecond,
			OnError: FallbackDeny,
		})
		lim, err := New(config.RateLimits{
			Rules: []config.RateRule{
				{Name: "strict", Tools: []string{"*"}, Per: config.PerTenant, Rate: "60/m", Burst: 5},
			},
		}, backend)
		if err != nil {
			t.Fatal(err)
		}

		mr.Close()
		if res := lim.Allow(t.Context(), Subject{Tenant: "acme", Tool: "t"}); res.Allowed {
			t.Fatalf("deny fallback should reject during redis outage: %+v", res)
		}

		if err := mr.Restart(); err != nil {
			t.Fatalf("restart miniredis: %v", err)
		}
		if res := lim.Allow(t.Context(), Subject{Tenant: "acme", Tool: "t"}); !res.Allowed {
			t.Fatalf("should admit again once redis recovers: %+v", res)
		}
	})
}
