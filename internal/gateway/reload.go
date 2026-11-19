package gateway

import (
	"context"
	"fmt"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
)

const (
	ConfigLoaded   = "config/load"
	ConfigReloaded = "config/reload"
)

func (g *Gateway) Swap(p *policy.Engine, l *ratelimit.Limiter) {
	g.policy.Store(p)
	g.limiter.Store(l)
	g.NotifyListChanged(true, true, true)
}

func (g *Gateway) RecordConfig(ctx context.Context, action, digest, detail string) error {
	if g.audit == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), intentDeadline*10)
	defer cancel()
	err := g.audit.Append(ctx, audit.Event{
		Phase:    audit.PhaseConfig,
		Method:   action,
		Decision: audit.DecisionAllow,
		Rule:     "sha256:" + digest,
		Reason:   detail,
	})
	if err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}
