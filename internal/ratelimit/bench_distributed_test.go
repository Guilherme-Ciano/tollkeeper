package ratelimit

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func BenchmarkRedisDistributedGCRA(b *testing.B) {
	mr := miniredis.RunT(b)
	const replicas = 4
	limiters := make([]*Limiter, replicas)
	for i := range replicas {
		client := redis.NewClient(&redis.Options{
			Addr:         mr.Addr(),
			PoolSize:     16,
			DialTimeout:  time.Second,
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		})
		b.Cleanup(func() {
			if err := client.Close(); err != nil {
				b.Errorf("close redis client: %v", err)
			}
		})
		backend := NewRedis(client, RedisOptions{
			Prefix:  "tk:bench:",
			Timeout: time.Second,
			OnError: FallbackDeny,
		})
		lim, err := New(config.RateLimits{
			Rules: []config.RateRule{
				{Name: "tenant-cap", Tools: []string{"*"}, Per: config.PerTenant, Rate: "100000/s", Burst: 100000},
				{
					Name:  "tenant-tool",
					Tools: []string{"crm__*"},
					Per:   config.PerTenantTool,
					Rate:  "100000/s",
					Burst: 100000,
				},
			},
		}, backend)
		if err != nil {
			b.Fatal(err)
		}
		limiters[i] = lim
	}

	tenants := make([]string, 16)
	for i := range tenants {
		tenants[i] = fmt.Sprintf("tenant-%02d", i)
	}
	ctx := b.Context()
	var seq atomic.Uint64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := seq.Add(1)
			lim := limiters[n%replicas]
			_ = lim.Allow(ctx, Subject{
				Sub:    "user",
				Tenant: tenants[n%uint64(len(tenants))],
				Tool:   "crm__get",
			})
		}
	})
}
