package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/google/cel-go/cel"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

type Subject struct {
	Sub      string
	ClientID string
	Tenant   string
	Tool     string
	Upstream string
	Args     json.RawMessage
}

type rule struct {
	limit    Limit
	tools    []string
	per      string
	costProg cel.Program
	maxCost  int
}

type Backend interface {
	Allow(ctx context.Context, reqs []Request) Result
}

type Limiter struct {
	store Backend
	rules []rule
}

func New(cfg config.RateLimits, store Backend) (*Limiter, error) {
	l := &Limiter{store: store}
	for _, r := range cfg.Rules {
		count, per, err := config.ParseRate(r.Rate)
		if err != nil {
			return nil, fmt.Errorf("rate limit %s: %w", r.Name, err)
		}
		tools := r.Tools
		if len(tools) == 0 {
			tools = []string{"*"}
		}
		var costProg cel.Program
		if strings.TrimSpace(r.CostExpr) != "" {
			costProg, err = compileCostExpr(r.Name, r.CostExpr)
			if err != nil {
				return nil, err
			}
		}
		maxCost := r.MaxCost
		if maxCost == 0 {
			maxCost = r.Burst
		}
		l.rules = append(l.rules, rule{
			limit:    NewLimit(r.Name, count, per, r.Burst),
			tools:    tools,
			per:      r.Per,
			costProg: costProg,
			maxCost:  maxCost,
		})
	}
	return l, nil
}

func (l *Limiter) Enabled() bool {
	return l != nil && len(l.rules) > 0
}

func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if ok, err := path.Match(g, name); err == nil && ok {
			return true
		}
	}
	return false
}

func key(r rule, s Subject) string {
	var b strings.Builder
	b.Grow(len(r.limit.Rule) + len(s.Sub) + len(s.Tool) + 8)
	b.WriteString(r.limit.Rule)
	b.WriteByte(0)
	switch r.per {
	case config.PerSubject:
		b.WriteString(s.Sub)
	case config.PerSubjectTool:
		b.WriteString(s.Sub)
		b.WriteByte(0)
		b.WriteString(s.Tool)
	case config.PerClientID:
		b.WriteString(s.ClientID)
	case config.PerTenant:
		b.WriteString(s.Tenant)
	case config.PerTenantTool:
		b.WriteString(s.Tenant)
		b.WriteByte(0)
		b.WriteString(s.Tool)
	case config.PerUpstream:
		b.WriteString(s.Upstream)
	case config.PerTool:
		b.WriteString(s.Tool)
	}
	return b.String()
}

func (l *Limiter) Allow(ctx context.Context, s Subject) Result {
	if !l.Enabled() {
		return Result{Allowed: true}
	}
	reqs := make([]Request, 0, len(l.rules))
	var decodedArgs any
	var argsReady bool
	for _, r := range l.rules {
		if !matchAny(r.tools, s.Tool) {
			continue
		}
		cost := 1
		if r.costProg != nil {
			if !argsReady {
				var err error
				decodedArgs, err = decodeCostArgs(s.Args)
				if err != nil {
					return Result{Allowed: false, Rule: r.limit.Rule, Limit: r.limit, RetryAfter: r.limit.Interval}
				}
				argsReady = true
			}
			c, err := evalCost(ctx, r.costProg, s, decodedArgs, r.maxCost)
			if err != nil {
				return Result{Allowed: false, Rule: r.limit.Rule, Limit: r.limit, RetryAfter: r.limit.Interval}
			}
			cost = c
		}
		reqs = append(reqs, Request{Key: key(r, s), Limit: r.limit, Cost: cost})
	}
	return l.store.Allow(ctx, reqs)
}
