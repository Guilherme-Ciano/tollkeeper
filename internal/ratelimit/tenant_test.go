package ratelimit

import (
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestPerTenantAndPerTenantToolIsolation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	lim, err := New(config.RateLimits{
		Rules: []config.RateRule{
			{Name: "tenant-cap", Tools: []string{"*"}, Per: config.PerTenant, Rate: "1/m", Burst: 2},
			{Name: "tenant-tool-cap", Tools: []string{"crm__export"}, Per: config.PerTenantTool, Rate: "1/m", Burst: 1},
		},
	}, store)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}

	ctx := t.Context()
	if res := lim.Allow(ctx, Subject{Sub: "alice", Tenant: "acme", Tool: "crm__export"}); !res.Allowed {
		t.Fatalf("acme first export should be allowed: %+v", res)
	}
	if res := lim.Allow(ctx, Subject{Sub: "alice2", Tenant: "acme", Tool: "crm__export"}); res.Allowed ||
		res.Rule != "tenant-tool-cap" {
		t.Fatalf("acme second export should hit tenant-tool-cap, got %+v", res)
	}
	if res := lim.Allow(ctx, Subject{Sub: "alice3", Tenant: "acme", Tool: "crm__read"}); !res.Allowed {
		t.Fatalf("acme read should still have 1 tenant-cap token, got %+v", res)
	}
	if res := lim.Allow(ctx, Subject{Sub: "alice4", Tenant: "acme", Tool: "crm__read"}); res.Allowed ||
		res.Rule != "tenant-cap" {
		t.Fatalf("acme third call should hit tenant-cap, got %+v", res)
	}

	if res := lim.Allow(ctx, Subject{Sub: "bob", Tenant: "globex", Tool: "crm__export"}); !res.Allowed {
		t.Fatalf("globex should be unaffected by acme exhaustion, got %+v", res)
	}
}
