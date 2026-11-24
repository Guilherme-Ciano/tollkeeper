package ratelimit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestCostBasedGCRAInMemoryAndRedis(t *testing.T) {
	t.Parallel()

	backends := []struct {
		name string
		make func(t *testing.T) Backend
	}{
		{
			name: "memory",
			make: func(t *testing.T) Backend {
				t.Helper()
				now := time.Unix(1_700_000_000, 0)
				return NewStore(func() time.Time { return now })
			},
		},
		{
			name: "redis",
			make: func(t *testing.T) Backend {
				t.Helper()
				mr := miniredis.RunT(t)
				client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: 0})
				t.Cleanup(func() {
					if err := client.Close(); err != nil {
						t.Errorf("close redis client: %v", err)
					}
				})
				return NewRedis(client, RedisOptions{
					Prefix:  "tk:cost:",
					Timeout: 200 * time.Millisecond,
					OnError: FallbackDeny,
				})
			},
		},
	}

	for _, bk := range backends {
		t.Run(bk.name, func(t *testing.T) {
			t.Parallel()
			lim, err := New(config.RateLimits{
				Rules: []config.RateRule{
					{
						Name:     "bulk-impact",
						Tools:    []string{"files__delete*"},
						Per:      config.PerSubject,
						Rate:     "60/h",
						Burst:    5,
						CostExpr: "has(args.paths) ? size(args.paths) : 1",
						MaxCost:  4,
					},
				},
			}, bk.make(t))
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()

			r1 := lim.Allow(ctx, Subject{
				Sub:  "alice",
				Tool: "files__delete_many",
				Args: json.RawMessage(`{"paths":["/a","/b","/c"]}`),
			})
			if !r1.Allowed || r1.Remaining != 2 {
				t.Fatalf("call 1 (cost 3 of 5): expected allowed with remaining 2, got %+v", r1)
			}

			r2 := lim.Allow(ctx, Subject{
				Sub:  "alice",
				Tool: "files__delete_many",
				Args: json.RawMessage(`{"paths":["/d","/e","/f"]}`),
			})
			if r2.Allowed {
				t.Fatalf("call 2 (cost 3 with 2 remaining): expected deny, got %+v", r2)
			}

			r3 := lim.Allow(ctx, Subject{
				Sub:  "alice",
				Tool: "files__delete_many",
				Args: json.RawMessage(`{"paths":["/d","/e"]}`),
			})
			if !r3.Allowed || r3.Remaining != 0 {
				t.Fatalf("call 3 (cost 2 with 2 remaining): expected allow remaining 0, got %+v", r3)
			}

			r4 := lim.Allow(ctx, Subject{
				Sub:  "bob",
				Tool: "files__delete_many",
				Args: json.RawMessage(`{"paths":["/1","/2","/3","/4","/5"]}`),
			})
			if r4.Allowed {
				t.Fatalf("call 4 (cost 5 > max_cost 4): expected deny, got %+v", r4)
			}
		})
	}
}

func TestCostBasedGCRAMultiRuleRollback(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	store := NewStore(func() time.Time { return now })
	lim, err := New(config.RateLimits{
		Rules: []config.RateRule{
			{
				Name:     "wide-budget",
				Tools:    []string{"*"},
				Per:      config.PerSubject,
				Rate:     "60/h",
				Burst:    10,
				CostExpr: "args.amount",
				MaxCost:  10,
			},
			{
				Name:     "tight-budget",
				Tools:    []string{"pay__*"},
				Per:      config.PerSubject,
				Rate:     "60/h",
				Burst:    2,
				CostExpr: "args.amount",
				MaxCost:  2,
			},
		},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	res := lim.Allow(ctx, Subject{Sub: "alice", Tool: "pay__transfer", Args: json.RawMessage(`{"amount":5}`)})
	if res.Allowed || res.Rule != "tight-budget" {
		t.Fatalf("expected tight-budget rejection, got %+v", res)
	}

	check := lim.Allow(ctx, Subject{Sub: "alice", Tool: "notes__add", Args: json.RawMessage(`{"amount":10}`)})
	if !check.Allowed || check.Remaining != 0 {
		t.Fatalf("wide-budget should have rolled back completely, got %+v", check)
	}
}

func TestCostExprCompileAndRuntimeFailClosed(t *testing.T) {
	t.Parallel()
	_, err := New(config.RateLimits{
		Rules: []config.RateRule{
			{
				Name:     "bad-cel",
				Tools:    []string{"*"},
				Per:      config.PerSubject,
				Rate:     "10/m",
				Burst:    5,
				CostExpr: "args.x +",
			},
		},
	}, NewStore(nil))
	if err == nil {
		t.Fatal("expected compile error for invalid cost_expr")
	}

	lim, err := New(config.RateLimits{
		Rules: []config.RateRule{
			{
				Name:     "strict-field",
				Tools:    []string{"*"},
				Per:      config.PerSubject,
				Rate:     "10/m",
				Burst:    5,
				CostExpr: "int(args.units)",
			},
		},
	}, NewStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	res := lim.Allow(t.Context(), Subject{Sub: "alice", Tool: "t", Args: json.RawMessage(`{}`)})
	if res.Allowed || res.Rule != "strict-field" {
		t.Fatalf("missing args.units should fail closed, got %+v", res)
	}
	neg := lim.Allow(t.Context(), Subject{Sub: "alice", Tool: "t", Args: json.RawMessage(`{"units":-3}`)})
	if neg.Allowed {
		t.Fatalf("negative cost should fail closed, got %+v", neg)
	}
}
