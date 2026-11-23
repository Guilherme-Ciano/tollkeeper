package identity

import (
	"context"
	"slices"
)

type Actor struct {
	Subject  string
	ClientID string
	Issuer   string
	Actor    *Actor
}

func (a *Actor) Depth() int {
	depth := 0
	for cur := a; cur != nil && depth < 16; cur = cur.Actor {
		depth++
	}
	return depth
}

func (a *Actor) Chain() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, a.Depth())
	for cur := a; cur != nil && len(out) < 16; cur = cur.Actor {
		if cur.Subject != "" {
			out = append(out, cur.Subject)
		}
	}
	return out
}

type Principal struct {
	Subject     string
	ClientID    string
	Issuer      string
	Tenant      string
	Actor       *Actor
	Scopes      []string
	Claims      map[string]any
	Fingerprint string
}

func (p Principal) DelegationDepth() int {
	return p.Actor.Depth()
}

func (p Principal) HasScope(s string) bool {
	return slices.Contains(p.Scopes, s)
}

func (p Principal) HasAllScopes(scopes []string) bool {
	for _, s := range scopes {
		if !p.HasScope(s) {
			return false
		}
	}
	return true
}

func (p Principal) HasAnyScope(scopes []string) bool {
	return slices.ContainsFunc(scopes, p.HasScope)
}

type principalKey struct{}

type subjectTokenKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func WithSubjectToken(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, subjectTokenKey{}, raw)
}

func SubjectTokenFrom(ctx context.Context) (string, bool) {
	tok, ok := ctx.Value(subjectTokenKey{}).(string)
	return tok, ok && tok != ""
}

func Anonymous() Principal {
	return Principal{Subject: "anonymous", ClientID: "anonymous"}
}
