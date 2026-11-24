package ratelimit

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/common/types"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestCostNumericAndDecodeEdgeCases(t *testing.T) {
	t.Parallel()
	if _, err := compileCostExpr("non-num", `"hello"`); err == nil {
		t.Fatal("expected error when cost_expr returns string")
	}

	if v, err := decodeCostArgs(nil); err != nil || v == nil {
		t.Fatalf("nil args decode: (%v, %v)", v, err)
	}
	if v, err := decodeCostArgs(json.RawMessage("null")); err != nil || v == nil {
		t.Fatalf("null args decode: (%v, %v)", v, err)
	}
	if _, err := decodeCostArgs(json.RawMessage("{invalid")); err == nil {
		t.Fatal("expected error for invalid JSON args")
	}
	big := json.RawMessage(`{"x":"` + strings.Repeat("a", maxCostArgBytes+10) + `"}`)
	if _, err := decodeCostArgs(big); err == nil {
		t.Fatal("expected error for oversized args")
	}

	if n, err := numericCost(types.Uint(7)); err != nil || n != 7 {
		t.Fatalf("uint cost = (%d, %v)", n, err)
	}
	if _, err := numericCost(types.Uint(math.MaxInt32 + 1)); err == nil {
		t.Fatal("expected overflow error for large uint")
	}
	if _, err := numericCost(types.Int(math.MaxInt32 + 1)); err == nil {
		t.Fatal("expected overflow error for large int")
	}
	if n, err := numericCost(types.Double(2.3)); err != nil || n != 3 {
		t.Fatalf("double ceil cost = (%d, %v), want 3", n, err)
	}
	for _, bad := range []any{
		types.Double(math.NaN()),
		types.Double(math.Inf(1)),
		types.Double(-0.5),
		types.Double(float64(math.MaxInt32) + 10),
		types.String("nope"),
	} {
		if _, err := numericCost(bad); err == nil {
			t.Fatalf("expected error for numericCost(%v)", bad)
		}
	}

	now := time.Unix(1_700_000_000, 0)
	lim, err := New(config.RateLimits{
		Rules: []config.RateRule{
			{
				Name:     "zero-floors-to-one",
				Tools:    []string{"*"},
				Per:      config.PerSubject,
				Rate:     "60/m",
				Burst:    5,
				CostExpr: "has(args.items) ? size(args.items) : 0",
			},
		},
	}, NewStore(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	res := lim.Allow(t.Context(), Subject{Sub: "alice", Tool: "t", Args: json.RawMessage(`{"items":[]}`)})
	if !res.Allowed || res.Remaining != 4 {
		t.Fatalf("cost 0 should floor to 1 leaving 4 remaining, got %+v", res)
	}
}
