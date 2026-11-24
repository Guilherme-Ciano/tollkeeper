package identity

import (
	"testing"
)

func TestActorDepthAndChain(t *testing.T) {
	t.Parallel()
	var nilActor *Actor
	if nilActor.Depth() != 0 || nilActor.Chain() != nil {
		t.Fatalf("nil actor should have depth 0 and nil chain")
	}

	chain := &Actor{
		Subject: "agent-1",
		Actor: &Actor{
			Subject: "",
			Actor: &Actor{
				Subject: "orchestrator-2",
			},
		},
	}
	if got := chain.Depth(); got != 3 {
		t.Fatalf("depth = %d, want 3", got)
	}
	gotChain := chain.Chain()
	if len(gotChain) != 2 || gotChain[0] != "agent-1" || gotChain[1] != "orchestrator-2" {
		t.Fatalf("chain = %v, want [agent-1 orchestrator-2]", gotChain)
	}

	loop := &Actor{Subject: "cycle"}
	loop.Actor = loop
	if got := loop.Depth(); got != 16 {
		t.Fatalf("cyclic actor depth = %d, want cap 16", got)
	}
	if got := len(loop.Chain()); got != 16 {
		t.Fatalf("cyclic actor chain len = %d, want cap 16", got)
	}
}

func TestPrincipalScopesAndContext(t *testing.T) {
	t.Parallel()
	p := Principal{
		Subject: "alice",
		Scopes:  []string{"mcp:tools", "notes:read"},
		Actor:   &Actor{Subject: "bot"},
	}
	if p.DelegationDepth() != 1 {
		t.Fatalf("delegation depth = %d, want 1", p.DelegationDepth())
	}
	if !p.HasScope("mcp:tools") || p.HasScope("admin") {
		t.Fatal("HasScope mismatch")
	}
	if !p.HasAllScopes([]string{"mcp:tools", "notes:read"}) || p.HasAllScopes([]string{"mcp:tools", "admin"}) {
		t.Fatal("HasAllScopes mismatch")
	}
	if !p.HasAnyScope([]string{"admin", "notes:read"}) || p.HasAnyScope([]string{"admin", "billing"}) {
		t.Fatal("HasAnyScope mismatch")
	}

	ctx := t.Context()
	if _, ok := FromContext(ctx); ok {
		t.Fatal("empty context should have no principal")
	}
	ctx = WithPrincipal(ctx, p)
	got, ok := FromContext(ctx)
	if !ok || got.Subject != "alice" {
		t.Fatalf("FromContext = (%+v, %v)", got, ok)
	}

	if _, ok := SubjectTokenFrom(ctx); ok {
		t.Fatal("empty subject token should not be found")
	}
	ctx = WithSubjectToken(ctx, "")
	if _, ok := SubjectTokenFrom(ctx); ok {
		t.Fatal("blank subject token should return false")
	}
	ctx = WithSubjectToken(ctx, "raw.jwt.token")
	tok, ok := SubjectTokenFrom(ctx)
	if !ok || tok != "raw.jwt.token" {
		t.Fatalf("SubjectTokenFrom = (%q, %v)", tok, ok)
	}

	anon := Anonymous()
	if anon.Subject != "anonymous" || anon.ClientID != "anonymous" {
		t.Fatalf("unexpected anonymous principal: %+v", anon)
	}
}
