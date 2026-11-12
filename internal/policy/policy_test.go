package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

func engine(tb testing.TB, cfg config.Policy) *Engine {
	tb.Helper()
	e, err := New(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	return e
}

func demoPolicy() config.Policy {
	return config.Policy{Default: config.EffectDeny, Rules: []config.Rule{
		{
			Name: "readers", Subjects: config.Subjects{ScopesAny: []string{"mcp:tools"}},
			Tools: []string{"notes__search", "weather__*"}, Effect: config.EffectAllow,
		},
		{
			Name:     "block-mallory",
			Subjects: config.Subjects{Subs: []string{"mallory"}},
			Tools:    []string{"*"},
			Effect:   config.EffectDeny,
		},
		{
			Name:     "unrelated-cel",
			Tools:    []string{"notes__create"},
			When:     `principal.sub != ""`,
			Effect:   config.EffectDeny,
			Subjects: config.Subjects{Subs: []string{"nobody"}},
		},
		{
			Name:     "note-size",
			Subjects: config.Subjects{ScopesAny: []string{"mcp:tools"}},
			Tools:    []string{"notes__create"},
			When:     "has(args.body) && size(args.body) <= 10",
			Effect:   config.EffectAllow,
		},
		{
			Name: "destructive", Tools: []string{"files__delete"}, When: `"files:write" in principal.scopes`,
			Effect: config.EffectAllow, OnDeny: config.OnDeny{StepUpScopes: []string{"files:write"}},
		},
		{
			Name:   "business-hours",
			Tools:  []string{"files__purge"},
			When:   `now.getHours("Europe/Lisbon") >= 9 && now.getHours("Europe/Lisbon") < 18`,
			Effect: config.EffectAllow,
		},
	}}
}

func in(sub string, scopes []string, tool, args string) Input {
	up, name, _ := catalog.Naming{Separator: "__"}.Split(tool)
	return Input{
		Principal: identity.Principal{Subject: sub, Scopes: scopes},
		Method:    "tools/call",
		Tool:      catalog.Tool{Name: tool, Upstream: up, Original: name},
		Args:      json.RawMessage(args),
		Now:       time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC),
	}
}

func TestDecide(t *testing.T) {
	t.Parallel()
	e := engine(t, demoPolicy())
	reader := []string{"mcp:tools"}
	cases := []struct {
		name   string
		input  Input
		effect Effect
		rule   string
	}{
		{"reader search", in("alice", reader, "notes__search", ""), Allow, "readers"},
		{"glob tool", in("alice", reader, "weather__forecast", ""), Allow, "readers"},
		{"no scope", in("alice", nil, "notes__search", ""), Deny, "default"},
		{"unknown tool", in("alice", reader, "notes__drop", ""), Deny, "default"},
		{"first match wins over later deny", in("mallory", reader, "notes__search", ""), Allow, "readers"},
		{"explicit deny", in("mallory", reader, "notes__create", `{"body":"x"}`), Deny, "block-mallory"},
		{"args small", in("alice", reader, "notes__create", `{"body":"short"}`), Allow, "note-size"},
		{"args too big", in("alice", reader, "notes__create", `{"body":"this is far too long"}`), Deny, "default"},
		{"args missing", in("alice", reader, "notes__create", `{}`), Deny, "default"},
		{"args invalid json", in("alice", reader, "notes__create", `{"body":`), Deny, "note-size"},
		{"step up", in("alice", reader, "files__delete", ""), StepUp, "destructive"},
		{"stepped up", in("bob", []string{"files:write"}, "files__delete", ""), Allow, "destructive"},
		{"time based", in("bob", nil, "files__purge", ""), Allow, "business-hours"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := e.Decide(t.Context(), tc.input)
			if d.Effect != tc.effect || d.Rule != tc.rule {
				t.Fatalf("got %s/%s (%s), want %s/%s", d.Effect, d.Rule, d.Reason, tc.effect, tc.rule)
			}
		})
	}
}

func TestArgsActivationAfterArglessRule(t *testing.T) {
	t.Parallel()
	e := engine(t, config.Policy{Default: config.EffectDeny, Rules: []config.Rule{
		{Name: "argless", Tools: []string{"*"}, When: `principal.sub == "nobody"`, Effect: config.EffectAllow},
		{Name: "with-args", Tools: []string{"*"}, When: `args.n == 1`, Effect: config.EffectAllow},
	}})
	d := e.Decide(t.Context(), in("alice", nil, "a__b", `{"n":1}`))
	if d.Effect != Allow || d.Rule != "with-args" {
		t.Fatalf("args not visible to second rule: %+v", d)
	}
}

func TestDefaultAllowAndVisibility(t *testing.T) {
	t.Parallel()
	e := engine(t, config.Policy{Default: config.EffectAllow, Rules: []config.Rule{
		{Name: "hide", Tools: []string{"secret__*"}, Effect: config.EffectDeny},
		{Name: "cond-deny", Tools: []string{"maybe__*"}, When: "true", Effect: config.EffectDeny},
	}})
	p := identity.Principal{Subject: "a"}
	if e.Visible(p, catalog.Tool{Name: "secret__x"}) {
		t.Fatal("unconditionally denied tool visible")
	}
	if !e.Visible(p, catalog.Tool{Name: "open__x"}) || !e.Visible(p, catalog.Tool{Name: "maybe__x"}) {
		t.Fatal("default-allow tool hidden")
	}
	strict := engine(t, demoPolicy())
	if !strict.Visible(identity.Principal{Subject: "a"}, catalog.Tool{Name: "files__delete"}) {
		t.Fatal("step-up tool should stay visible so the caller can get the challenge")
	}
	if strict.Visible(identity.Principal{Subject: "a"}, catalog.Tool{Name: "notes__search"}) {
		t.Fatal("tool visible without scope")
	}
}

func TestCompileErrors(t *testing.T) {
	t.Parallel()
	for _, when := range []string{"1 +", `"string"`, "unknown_var == 1"} {
		_, err := New(
			config.Policy{
				Rules: []config.Rule{{Name: "r", Tools: []string{"*"}, When: when, Effect: config.EffectAllow}},
			},
		)
		if !errors.Is(err, ErrCompile) {
			t.Fatalf("%q: expected compile error, got %v", when, err)
		}
	}
}

func TestCostLimitDenies(t *testing.T) {
	t.Parallel()
	e := engine(t, config.Policy{Rules: []config.Rule{{
		Name: "expensive", Tools: []string{"*"}, Effect: config.EffectAllow,
		When: `args.xs.all(x, args.xs.all(y, args.xs.all(z, x + y + z >= 0)))`,
	}}})
	xs := make([]int, 200)
	b, err := json.Marshal(map[string]any{"xs": xs})
	if err != nil {
		t.Fatal(err)
	}
	d := e.Decide(t.Context(), in("a", nil, "a__b", string(b)))
	if d.Effect != Deny || !strings.Contains(d.Reason, "evaluation failed") {
		t.Fatalf("expensive expression not cut off: %+v", d)
	}
}

func TestFixtures(t *testing.T) {
	t.Parallel()
	e := engine(t, demoPolicy())
	f, err := ParseFixtures(strings.NewReader(`cases:
  - name: ok
    principal: { sub: alice, scopes: ["mcp:tools"] }
    tool: notes__search
    expect: allow
    rule: readers
  - name: wrong expectation
    principal: { sub: alice }
    tool: notes__search
    expect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.RunFixtures(t.Context(), f, "__")
	if err != nil {
		t.Fatal(err)
	}
	if !res[0].Pass || res[1].Pass {
		t.Fatalf("fixture results %+v", res)
	}
	if _, err := ParseFixtures(strings.NewReader("cases:\n  - unexpected_field: typo\n")); err == nil {
		t.Fatal("unknown fixture field accepted")
	}
}

func FuzzPolicyArgs(f *testing.F) {
	e := engine(f, config.Policy{Rules: []config.Rule{
		{
			Name:   "size",
			Tools:  []string{"*"},
			When:   `has(args.body) && size(args.body) < 100`,
			Effect: config.EffectAllow,
		},
		{Name: "nested", Tools: []string{"*"}, When: `has(args.a) && args.a.b.c == "x"`, Effect: config.EffectAllow},
	}})
	for _, s := range []string{`{"body":"x"}`, `{"a":{"b":{"c":"x"}}}`, `{"body":1}`, `[]`, `{"a":null}`, ``} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, args []byte) {
		d := e.Decide(t.Context(), in("a", nil, "a__b", string(args)))
		if d.Effect == StepUp {
			t.Fatal("unexpected step-up")
		}
	})
}

func BenchmarkDecide(b *testing.B) {
	e := engine(b, demoPolicy())
	b.Run("rbac", func(b *testing.B) {
		x := in("alice", []string{"mcp:tools"}, "notes__search", "")
		b.ReportAllocs()
		for b.Loop() {
			e.Decide(b.Context(), x)
		}
	})
	b.Run("cel", func(b *testing.B) {
		x := in("bob", []string{"files:write"}, "files__delete", "")
		b.ReportAllocs()
		for b.Loop() {
			e.Decide(b.Context(), x)
		}
	})
	b.Run("cel_args", func(b *testing.B) {
		x := in("alice", []string{"mcp:tools"}, "notes__create", `{"title":"t","body":"short"}`)
		b.ReportAllocs()
		for b.Loop() {
			e.Decide(b.Context(), x)
		}
	})
}
