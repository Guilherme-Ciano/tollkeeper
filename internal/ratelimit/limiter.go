package ratelimit

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

type Subject struct {
	Sub      string
	ClientID string
	Tool     string
	Upstream string
}

type rule struct {
	limit Limit
	tools []string
	per   string
}

type Limiter struct {
	store *Store
	rules []rule
}

func New(cfg config.RateLimits, store *Store) (*Limiter, error) {
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
		l.rules = append(l.rules, rule{limit: NewLimit(r.Name, count, per, r.Burst), tools: tools, per: r.Per})
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
	for _, r := range l.rules {
		if matchAny(r.tools, s.Tool) {
			reqs = append(reqs, Request{Key: key(r, s), Limit: r.limit})
		}
	}
	return l.store.Allow(ctx, reqs)
}
