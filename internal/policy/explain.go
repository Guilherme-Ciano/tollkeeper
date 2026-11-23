package policy

import (
	"context"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
)

type Step struct {
	Rule    string
	Shadow  bool
	Outcome string
}

func (r *rule) globs(kind catalog.Kind) []string {
	switch kind {
	case catalog.KindPrompt:
		return r.cfg.Prompts
	case catalog.KindResource, catalog.KindTemplate:
		return r.cfg.Resources
	default:
		return r.cfg.Tools
	}
}

func (e *Engine) Explain(ctx context.Context, in Input) ([]Step, Decision) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	sc := e.scopeFor(in.Principal.Tenant)
	ev := &evaluation{in: in}
	steps := make([]Step, 0, len(sc.rules))
	for i := range sc.rules {
		r := &sc.rules[i]
		st := Step{Rule: r.cfg.Name, Shadow: r.shadow}
		switch {
		case !globMatch(r.globs(in.Kind), in.Tool.Name):
			st.Outcome = "skipped: no " + kindName(in.Kind) + " glob matches " + in.Tool.Name
		case !subjectsMatch(r.cfg.Subjects, in.Principal):
			st.Outcome = "skipped: subjects do not match"
		default:
			d, done := e.decideRule(ctx, r, ev)
			st.Outcome = explainOutcome(r, d, done)
		}
		steps = append(steps, st)
	}
	return steps, e.Decide(ctx, in)
}

func explainOutcome(r *rule, d Decision, done bool) string {
	switch {
	case !done:
		return "when is false: falls through"
	case d.Effect == StepUp:
		return "when is false: step-up required"
	case d.Reason != reasonMatched:
		return "decides " + d.Effect.String() + ": " + d.Reason
	case r.program == nil:
		return "matches: " + d.Effect.String()
	default:
		return "when is true: " + d.Effect.String()
	}
}
