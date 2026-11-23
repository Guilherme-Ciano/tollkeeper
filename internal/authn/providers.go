package authn

import (
	"math"
	"strings"
	"time"
)

const (
	ProviderGeneric  = ""
	ProviderEntra    = "entra"
	ProviderOkta     = "okta"
	ProviderKeycloak = "keycloak"
	ProviderAuth0    = "auth0"

	schemeHTTPS = "https"
	ktyOKP      = "OKP"
	claimGroups = "groups"
	claimRoles  = "roles"
	claimAZP    = "azp"
	claimScope  = "scope"
)

type ClaimMapping struct {
	TenantClaim   string
	GroupsClaim   string
	RolesClaim    string
	ClientIDClaim string
	ScopeClaim    string
}

func ResolveClaimMapping(provider string, overrides ClaimMapping) ClaimMapping {
	var base ClaimMapping
	switch provider {
	case ProviderEntra:
		base = ClaimMapping{
			TenantClaim:   "tid",
			GroupsClaim:   claimGroups,
			RolesClaim:    claimRoles,
			ClientIDClaim: claimAZP,
			ScopeClaim:    "scp",
		}
	case ProviderOkta:
		base = ClaimMapping{
			TenantClaim:   "org_id",
			GroupsClaim:   claimGroups,
			RolesClaim:    claimRoles,
			ClientIDClaim: "cid",
			ScopeClaim:    "scp",
		}
	case ProviderKeycloak:
		base = ClaimMapping{
			TenantClaim:   "organization",
			GroupsClaim:   claimGroups,
			RolesClaim:    "realm_access.roles",
			ClientIDClaim: claimAZP,
			ScopeClaim:    claimScope,
		}
	case ProviderAuth0:
		base = ClaimMapping{
			TenantClaim:   "org_id",
			GroupsClaim:   claimGroups,
			RolesClaim:    "permissions",
			ClientIDClaim: claimAZP,
			ScopeClaim:    claimScope,
		}
	default:
		base = ClaimMapping{
			GroupsClaim: claimGroups,
			RolesClaim:  claimRoles,
		}
	}
	if overrides.TenantClaim != "" {
		base.TenantClaim = overrides.TenantClaim
	}
	if overrides.GroupsClaim != "" {
		base.GroupsClaim = overrides.GroupsClaim
	}
	if overrides.RolesClaim != "" {
		base.RolesClaim = overrides.RolesClaim
	}
	if overrides.ClientIDClaim != "" {
		base.ClientIDClaim = overrides.ClientIDClaim
	}
	if overrides.ScopeClaim != "" {
		base.ScopeClaim = overrides.ScopeClaim
	}
	return base
}

func lookupClaimPath(claims map[string]any, path string) any {
	if path == "" || claims == nil {
		return nil
	}
	if v, ok := claims[path]; ok {
		return v
	}
	var cur any = claims
	for part := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

func extractStringClaim(claims map[string]any, paths ...string) string {
	for _, p := range paths {
		if v := lookupClaimPath(claims, p); v != nil {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func extractStringSliceClaim(claims map[string]any, path string) []string {
	raw := lookupClaimPath(claims, path)
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		return strings.Fields(v)
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func extractConfirmationJKT(claims map[string]any) string {
	return extractStringClaim(claims, "cnf.jkt")
}

func extractAuthTime(claims map[string]any) time.Time {
	raw := lookupClaimPath(claims, "auth_time")
	switch v := raw.(type) {
	case float64:
		if v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) {
			return time.Unix(int64(v), 0).UTC()
		}
	case int64:
		if v > 0 {
			return time.Unix(v, 0).UTC()
		}
	}
	return time.Time{}
}
