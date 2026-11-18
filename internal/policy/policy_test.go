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
	res, err := e.RunFixtures(t.Context(), f, catalog.Naming{Separator: "__"})
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

func TestPolicyFixturesUseConfiguredUpstreamInBareMode(t *testing.T) {
	t.Parallel()
	e := engine(t, config.Policy{Default: config.EffectDeny, Rules: []config.Rule{{
		Name: "notes-only", Tools: []string{"*"}, When: `tool.upstream == "notes"`, Effect: config.EffectAllow,
	}}})
	f, err := ParseFixtures(strings.NewReader(`cases:
  - name: bare name with the separator inside
    tool: search__all
    expect: allow
    rule: notes-only
`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.RunFixtures(t.Context(), f, catalog.Naming{Separator: "__", Bare: true, Upstream: "notes"})
	if err != nil {
		t.Fatal(err)
	}
	if !res[0].Pass {
		t.Fatalf("fixture saw a different upstream than runtime would: %+v", res[0])
	}
}

func TestPromptsAndResourcesNeedTheirOwnGlobs(t *testing.T) {
	t.Parallel()
	e := engine(t, config.Policy{Default: config.EffectDeny, Rules: []config.Rule{
		{Name: "all-tools", Tools: []string{"*"}, Effect: config.EffectAllow},
		{Name: "docs", Resources: []string{"file:///docs/*"}, Effect: config.EffectAllow},
		{
			Name: "prompts-for-writers", Prompts: []string{"notes__*"}, Effect: config.EffectAllow,
			When: `request.kind == "prompt" && "notes:write" in principal.scopes`,
		},
	}})
	p := identity.Principal{Subject: "alice", Scopes: []string{"notes:write"}}
	cases := []struct {
		kind catalog.Kind
		name string
		want Effect
	}{
		{"", "notes__search", Allow},
		{catalog.KindPrompt, "notes__summary", Allow},
		{catalog.KindPrompt, "weather__brief", Deny},
		{catalog.KindResource, "file:///docs/a.md", Allow},
		{catalog.KindResource, "file:///etc/passwd", Deny},
	}
	for _, tc := range cases {
		d := e.Decide(t.Context(), Input{Principal: p, Kind: tc.kind, Tool: catalog.Tool{Name: tc.name}})
		if d.Effect != tc.want {
			t.Errorf("%s %s: %v (%s)", tc.kind, tc.name, d.Effect, d.Rule)
		}
	}
	if e.VisibleAs(p, catalog.KindResource, "file:///etc/passwd") {
		t.Fatal("tools: [*] made a resource visible")
	}
	if !e.VisibleAs(identity.Principal{}, catalog.KindResource, "file:///docs/a.md") {
		t.Fatal("allowed resource hidden")
	}
}

func TestBareStarMatchesURIs(t *testing.T) {
	t.Parallel()
	if !globMatch([]string{"*"}, "test://a/b/c") || globMatch([]string{"test:*"}, "test://a/b") {
		t.Fatal("glob semantics changed")
	}
}

func TestShadowRulesObserveWithoutDeciding(t *testing.T) {
	t.Parallel()
	e := engine(t, config.Policy{Default: config.EffectDeny, Rules: []config.Rule{
		{
			Name:   "block-writes",
			Tools:  []string{"notes__create"},
			Effect: config.EffectDeny,
			Mode:   config.RuleModeShadow,
		},
		{Name: "second-shadow", Tools: []string{"*"}, Effect: config.EffectDeny, Mode: config.RuleModeShadow},
		{Name: "allow-notes", Tools: []string{"notes__*"}, Effect: config.EffectAllow},
	}})
	p := identity.Principal{Subject: "alice"}
	d := e.Decide(t.Context(), Input{Principal: p, Tool: catalog.Tool{Name: "notes__create"}})
	if d.Effect != Allow || d.Rule != "allow-notes" || d.Shadow == nil ||
		d.Shadow.Rule != "block-writes" || d.Shadow.Effect != Deny {
		t.Fatalf("decision %+v shadow %+v", d, d.Shadow)
	}
	d = e.Decide(t.Context(), Input{Principal: p, Tool: catalog.Tool{Name: "weather__now"}})
	if d.Effect != Deny || d.Rule != "default" || d.Shadow == nil || d.Shadow.Rule != "second-shadow" {
		t.Fatalf("default decision %+v shadow %+v", d, d.Shadow)
	}
	shadowOnly := engine(t, config.Policy{Default: config.EffectDeny, Rules: []config.Rule{
		{Name: "would-allow", Tools: []string{"*"}, Effect: config.EffectAllow, Mode: config.RuleModeShadow},
	}})
	if shadowOnly.Visible(p, catalog.Tool{Name: "x__y"}) {
		t.Fatal("a shadow allow rule made a tool visible")
	}
}

func TestExplainTracesEveryRule(t *testing.T) {
	t.Parallel()
	e := engine(t, demoPolicy())
	steps, d := e.Explain(t.Context(), Input{
		Principal: identity.Principal{Subject: "bob", Scopes: []string{"mcp:tools"}},
		Tool:      catalog.Tool{Name: "weather__forecast"},
	})
	if d.Effect != Allow || d.Rule != "readers" || len(steps) != len(demoPolicy().Rules) {
		t.Fatalf("decision %+v, %d steps", d, len(steps))
	}
	if steps[0].Outcome != "matches: allow" || !strings.HasPrefix(steps[1].Outcome, "skipped: subjects") {
		t.Fatalf("steps: %+v", steps)
	}
}
