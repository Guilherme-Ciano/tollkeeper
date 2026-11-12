package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

type FixtureFile struct {
	Cases []Fixture `yaml:"cases"`
}

type FixturePrincipal struct {
	Sub      string         `yaml:"sub"`
	ClientID string         `yaml:"client_id"`
	Scopes   []string       `yaml:"scopes"`
	Claims   map[string]any `yaml:"claims"`
}

type FixtureAnnotations struct {
	ReadOnly    bool `yaml:"readOnlyHint"`
	Destructive bool `yaml:"destructiveHint"`
	Idempotent  bool `yaml:"idempotentHint"`
	OpenWorld   bool `yaml:"openWorldHint"`
}

type Fixture struct {
	Name        string             `yaml:"name"`
	Principal   FixturePrincipal   `yaml:"principal"`
	Tool        string             `yaml:"tool"`
	Annotations FixtureAnnotations `yaml:"annotations"`
	Args        map[string]any     `yaml:"args"`
	Now         string             `yaml:"now"`
	Expect      string             `yaml:"expect"`
	Rule        string             `yaml:"rule"`
	Visible     *bool              `yaml:"visible"`
}

type FixtureResult struct {
	Name   string
	Pass   bool
	Got    Decision
	Detail string
}

func ParseFixtures(r io.Reader) (FixtureFile, error) {
	var f FixtureFile
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("parse fixtures: %w", err)
	}
	return f, nil
}

func (fx *Fixture) input(sep string) (Input, error) {
	upstream, original, _ := catalog.Naming{Separator: sep}.Split(fx.Tool)
	in := Input{
		Principal: identity.Principal{
			Subject:  fx.Principal.Sub,
			ClientID: fx.Principal.ClientID,
			Scopes:   fx.Principal.Scopes,
			Claims:   fx.Principal.Claims,
		},
		Method: "tools/call",
		Tool: catalog.Tool{Name: fx.Tool, Upstream: upstream, Original: original, Annotations: catalog.Annotations{
			ReadOnly: fx.Annotations.ReadOnly, Destructive: fx.Annotations.Destructive,
			Idempotent: fx.Annotations.Idempotent, OpenWorld: fx.Annotations.OpenWorld,
		}},
		Now: time.Now(),
	}
	if fx.Now != "" {
		t, err := time.Parse(time.RFC3339, fx.Now)
		if err != nil {
			return in, fmt.Errorf("case %q: now: %w", fx.Name, err)
		}
		in.Now = t
	}
	if fx.Args != nil {
		b, err := json.Marshal(fx.Args)
		if err != nil {
			return in, fmt.Errorf("case %q: args: %w", fx.Name, err)
		}
		in.Args = b
	}
	return in, nil
}

func (e *Engine) RunFixtures(ctx context.Context, f FixtureFile, sep string) ([]FixtureResult, error) {
	out := make([]FixtureResult, 0, len(f.Cases))
	for i := range f.Cases {
		fx := &f.Cases[i]
		in, err := fx.input(sep)
		if err != nil {
			return nil, err
		}
		d := e.Decide(ctx, in)
		r := FixtureResult{Name: fx.Name, Got: d, Pass: true}
		switch {
		case d.Effect.String() != fx.Expect:
			r.Pass, r.Detail = false, fmt.Sprintf(
				"expected %s, got %s (rule %s: %s)",
				fx.Expect,
				d.Effect,
				d.Rule,
				d.Reason,
			)
		case fx.Rule != "" && d.Rule != fx.Rule:
			r.Pass, r.Detail = false, fmt.Sprintf("expected rule %s, got %s", fx.Rule, d.Rule)
		case fx.Visible != nil && e.Visible(in.Principal, in.Tool) != *fx.Visible:
			r.Pass, r.Detail = false, fmt.Sprintf("expected visible=%t", *fx.Visible)
		}
		out = append(out, r)
	}
	return out, nil
}
