package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

const (
	costEvalLimit   = 10000
	costEvalTimeout = 50 * time.Millisecond
	maxCostArgBytes = 1 << 20
)

func compileCostExpr(ruleName, expr string) (cel.Program, error) {
	env, err := cel.NewEnv(
		cel.Variable("args", cel.DynType),
		cel.Variable("tool", cel.StringType),
		cel.Variable("sub", cel.StringType),
		cel.Variable("tenant", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("cost cel env: %w", err)
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("rate limit %s cost_expr: %w", ruleName, iss.Err())
	}
	ot := ast.OutputType()
	if ot != cel.IntType && ot != cel.UintType && ot != cel.DoubleType && ot != cel.DynType {
		return nil, fmt.Errorf("rate limit %s cost_expr: must return numeric value, got %s", ruleName, ot)
	}
	prog, err := env.Program(ast, cel.CostLimit(costEvalLimit))
	if err != nil {
		return nil, fmt.Errorf("rate limit %s cost_expr program: %w", ruleName, err)
	}
	return prog, nil
}

func decodeCostArgs(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	if len(raw) > maxCostArgBytes {
		return nil, errors.New("arguments exceed cost evaluation cap")
	}
	var args any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("decode cost arguments: %w", err)
	}
	if args == nil {
		return map[string]any{}, nil
	}
	return args, nil
}

func evalCost(ctx context.Context, prog cel.Program, s Subject, decodedArgs any, maxCost int) (int, error) {
	ectx, cancel := context.WithTimeout(ctx, costEvalTimeout)
	defer cancel()
	out, _, err := prog.ContextEval(ectx, map[string]any{
		"args":   decodedArgs,
		"tool":   s.Tool,
		"sub":    s.Sub,
		"tenant": s.Tenant,
	})
	if err != nil {
		return 0, fmt.Errorf("eval cost_expr: %w", err)
	}
	n, err := numericCost(out)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("computed cost %d must not be negative", n)
	}
	if n == 0 {
		return 1, nil
	}
	if maxCost > 0 && n > maxCost {
		return 0, fmt.Errorf("computed cost %d exceeds max_cost %d", n, maxCost)
	}
	return n, nil
}

func numericCost(v any) (int, error) {
	switch x := v.(type) {
	case types.Int:
		iv := int64(x)
		if iv > math.MaxInt32 {
			return 0, errors.New("computed cost overflows int32")
		}
		return int(iv), nil
	case types.Uint:
		uv := uint64(x)
		if uv > math.MaxInt32 {
			return 0, errors.New("computed cost overflows int32")
		}
		return int(uv), nil
	case types.Double:
		fv := float64(x)
		if math.IsNaN(fv) || math.IsInf(fv, 0) || fv < 0 || fv > math.MaxInt32 {
			return 0, errors.New("computed cost is invalid float")
		}
		return int(math.Ceil(fv)), nil
	default:
		return 0, fmt.Errorf("cost_expr returned non-numeric type %T", v)
	}
}
