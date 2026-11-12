package identity

import (
	"context"
	"slices"
)

type Principal struct {
	Subject     string
	ClientID    string
	Issuer      string
	Scopes      []string
	Claims      map[string]any
	Fingerprint string
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

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func Anonymous() Principal {
	return Principal{Subject: "anonymous", ClientID: "anonymous"}
}
