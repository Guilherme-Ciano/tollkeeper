package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

const (
	costLimit   = 100_000
	evalTimeout = 50 * time.Millisecond
	maxArgBytes = 256 << 10
)

var ErrCompile = errors.New("policy compile error")

type Effect int

const (
	Deny Effect = iota
	Allow
	StepUp
)

func (e Effect) String() string {
	switch e {
	case Allow:
		return "allow"
	case StepUp:
		return "step_up"
	case Deny:
		return "deny"
	}
	return "deny"
}

const (
	reasonMatched = "matched rule"
	fieldSub      = "sub"
	fieldClientID = "client_id"
)

type Decision struct {
	Effect       Effect
	Rule         string
	Reason       string
	StepUpScopes []string
	Shadow       *ShadowHit
}

type ShadowHit struct {
	Rule   string
	Effect Effect
}

type Input struct {
	Principal  identity.Principal
	Method     string
	Kind       catalog.Kind
	Tool       catalog.Tool
	Args       json.RawMessage
	ClientName string
	Now        time.Time
}

type rule struct {
	cfg      config.Rule
	effect   Effect
	program  cel.Program
	usesArgs bool
	shadow   bool
}

type Engine struct {
	rules         []rule
	defaultEffect Effect
}

func newEnv() (*cel.Env, error) {
	env, err := cel.NewEnv(
		cel.Variable("principal", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("tool", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("args", cel.DynType),
		cel.Variable("now", cel.TimestampType),
		ext.Strings(),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	return env, nil
}

func referencesArgs(a *cel.Ast) bool {
	found := false
	celast.PreOrderVisit(a.NativeRep().Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() == celast.IdentKind && e.AsIdent() == "args" {
			found = true
		}
	}))
	return found
}

func New(cfg config.Policy) (*Engine, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	e := &Engine{defaultEffect: Deny}
	if cfg.Default == config.EffectAllow {
		e.defaultEffect = Allow
	}
	var errs []error
	for i := range cfg.Rules {
		rc := cfg.Rules[i]
		r := rule{cfg: rc, effect: Deny, shadow: rc.Mode == config.RuleModeShadow}
		if rc.Effect == config.EffectAllow {
			r.effect = Allow
		}
		if strings.TrimSpace(rc.When) != "" {
			a, iss := env.Compile(rc.When)
			if iss.Err() != nil {
				errs = append(errs, fmt.Errorf("%w: policy.rules[%d] %s: %w", ErrCompile, i, rc.Name, iss.Err()))
				continue
			}
			if a.OutputType() != cel.BoolType {
				errs = append(
					errs,
					fmt.Errorf(
						"%w: policy.rules[%d] %s: when must return bool, got %s",
						ErrCompile,
						i,
						rc.Name,
						a.OutputType(),
					),
				)
				continue
			}
			prg, err := env.Program(a, cel.CostLimit(costLimit), cel.InterruptCheckFrequency(100))
			if err != nil {
				errs = append(errs, fmt.Errorf("%w: policy.rules[%d] %s: %w", ErrCompile, i, rc.Name, err))
				continue
			}
			r.program = prg
			r.usesArgs = referencesArgs(a)
		}
		e.rules = append(e.rules, r)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return e, nil
}

func globMatch(globs []string, s string) bool {
	for _, g := range globs {
		if g == "*" {
			return true
		}
		if ok, err := path.Match(g, s); err == nil && ok {
			return true
		}
	}
	return false
}

func subjectsMatch(s config.Subjects, p identity.Principal) bool {
	if len(s.Subs) > 0 && !globMatch(s.Subs, p.Subject) {
		return false
	}
	if len(s.ClientIDs) > 0 && !globMatch(s.ClientIDs, p.ClientID) {
		return false
	}
	if len(s.Actors) > 0 {
		if p.Actor == nil || !globMatch(s.Actors, p.Actor.Subject) {
			return false
		}
	}
	if len(s.ScopesAny) > 0 && !p.HasAnyScope(s.ScopesAny) {
		return false
	}
	return p.HasAllScopes(s.ScopesAll)
}

func stringSliceAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func actorMap(a *identity.Actor) map[string]any {
	if a == nil {
		return map[string]any{
			fieldSub:      "",
			fieldClientID: "",
			"iss":         "",
			"depth":       0,
			"chain":       []any{},
		}
	}
	chain := a.Chain()
	chainAny := make([]any, len(chain))
	for i, s := range chain {
		chainAny[i] = s
	}
	return map[string]any{
		fieldSub:      a.Subject,
		fieldClientID: a.ClientID,
		"iss":         a.Issuer,
		"depth":       a.Depth(),
		"chain":       chainAny,
	}
}

func activation(in Input, withArgs bool) (map[string]any, error) {
	claims := in.Principal.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	act := map[string]any{
		"principal": map[string]any{
			fieldSub:      in.Principal.Subject,
			fieldClientID: in.Principal.ClientID,
			"tenant":      in.Principal.Tenant,
			"delegated":   in.Principal.Actor != nil,
			"actor":       actorMap(in.Principal.Actor),
			"scopes":      stringSliceAny(in.Principal.Scopes),
			"roles":       stringSliceAny(in.Principal.Roles),
			"groups":      stringSliceAny(in.Principal.Groups),
			"acr":         in.Principal.ACR,
			"amr":         stringSliceAny(in.Principal.AMR),
			"dpop":        in.Principal.DPoPVerified,
			"jkt":         in.Principal.TokenThumbprint,
			"claims":      claims,
		},
		"tool": map[string]any{
			"name":     in.Tool.Name,
			"upstream": in.Tool.Upstream,
			"original": in.Tool.Original,
			"pin_hash": in.Tool.Pin,
			"annotations": map[string]any{
				"readOnlyHint":    in.Tool.Annotations.ReadOnly,
				"destructiveHint": in.Tool.Annotations.Destructive,
				"idempotentHint":  in.Tool.Annotations.Idempotent,
				"openWorldHint":   in.Tool.Annotations.OpenWorld,
			},
		},
		"request": map[string]any{
			"kind":        kindName(in.Kind),
			"method":      in.Method,
			"client_name": in.ClientName,
		},
		"now":  in.Now,
		"args": map[string]any{},
	}
	if withArgs && len(in.Args) > 0 {
		if len(in.Args) > maxArgBytes {
			return nil, fmt.Errorf("arguments exceed %d bytes", maxArgBytes)
		}
		var args any
		if err := json.Unmarshal(in.Args, &args); err != nil {
			return nil, fmt.Errorf("arguments are not valid JSON: %w", err)
		}
		act["args"] = args
	}
	return act, nil
}

type evaluation struct {
	in       Input
	act      map[string]any
	withArgs bool
}

func (ev *evaluation) activation(needArgs bool) (map[string]any, error) {
	if ev.act != nil && (!needArgs || ev.withArgs) {
		return ev.act, nil
	}
	act, err := activation(ev.in, needArgs)
	if err != nil {
		return nil, err
	}
	ev.act, ev.withArgs = act, needArgs
	return act, nil
}

func (r *rule) applies(kind catalog.Kind, name string, p identity.Principal) bool {
	return globMatch(r.globs(kind), name) && subjectsMatch(r.cfg.Subjects, p)
}

func (e *Engine) Decide(ctx context.Context, in Input) Decision {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	ev := &evaluation{in: in}
	var shadow *ShadowHit
	for i := range e.rules {
		r := &e.rules[i]
		if !r.applies(in.Kind, in.Tool.Name, in.Principal) {
			continue
		}
		d, done := e.decideRule(ctx, r, ev)
		switch {
		case !done:
		case r.shadow:
			if shadow == nil {
				shadow = &ShadowHit{Rule: r.cfg.Name, Effect: d.Effect}
			}
		default:
			d.Shadow = shadow
			return d
		}
	}
	return Decision{Effect: e.defaultEffect, Rule: "default", Reason: "no rule matched", Shadow: shadow}
}

func (e *Engine) decideRule(ctx context.Context, r *rule, ev *evaluation) (Decision, bool) {
	if r.program == nil {
		return Decision{Effect: r.effect, Rule: r.cfg.Name, Reason: reasonMatched}, true
	}
	act, err := ev.activation(r.usesArgs)
	if err != nil {
		return Decision{Effect: Deny, Rule: r.cfg.Name, Reason: err.Error()}, true
	}
	ok, err := e.eval(ctx, r, act)
	if err != nil {
		return Decision{Effect: Deny, Rule: r.cfg.Name, Reason: "policy evaluation failed: " + err.Error()}, true
	}
	if ok {
		return Decision{Effect: r.effect, Rule: r.cfg.Name, Reason: reasonMatched}, true
	}
	if len(r.cfg.OnDeny.StepUpScopes) > 0 && !ev.in.Principal.HasAllScopes(r.cfg.OnDeny.StepUpScopes) {
		return Decision{
			Effect:       StepUp,
			Rule:         r.cfg.Name,
			Reason:       "additional scope required",
			StepUpScopes: r.cfg.OnDeny.StepUpScopes,
		}, true
	}
	return Decision{}, false
}

func (e *Engine) eval(ctx context.Context, r *rule, act map[string]any) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, evalTimeout)
	defer cancel()
	out, _, err := r.program.ContextEval(ctx, act)
	if err != nil {
		return false, fmt.Errorf("eval %s: %w", r.cfg.Name, err)
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("eval %s: non-bool result", r.cfg.Name)
	}
	return bool(b), nil
}

func (e *Engine) Visible(p identity.Principal, t catalog.Tool) bool {
	return e.VisibleAs(p, "", t.Name)
}

func (e *Engine) VisibleAs(p identity.Principal, kind catalog.Kind, name string) bool {
	for i := range e.rules {
		r := &e.rules[i]
		if r.shadow || !r.applies(kind, name, p) {
			continue
		}
		if r.effect == Allow {
			return true
		}
		if r.program == nil {
			return false
		}
	}
	return e.defaultEffect == Allow
}

func kindName(k catalog.Kind) string {
	if k == "" {
		return "tool"
	}
	return string(k)
}
