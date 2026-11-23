package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestEnterpriseProviderClaimMappings(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)

	cases := []struct {
		name         string
		provider     string
		claims       jwt.MapClaims
		wantTenant   string
		wantClientID string
		wantRoles    []string
		wantGroups   []string
		wantScopes   []string
		wantJKT      string
		wantACR      string
	}{
		{
			name:     "entra_id",
			provider: ProviderEntra,
			claims: jwt.MapClaims{
				"iss":       "https://login.microsoftonline.com/tenant-1/v2.0",
				"sub":       "user-entra",
				"aud":       "https://gw.example.com/mcp",
				"tid":       "tenant-1",
				"azp":       "app-entra",
				"scp":       "Files.Read Mail.Send",
				"roles":     []string{"MCP.Operator"},
				"groups":    []string{"grp-sec"},
				"acr":       "urn:mace:incommon:iap:silver",
				"amr":       []string{"pwd", "mfa"},
				"auth_time": now.Add(-2 * time.Minute).Unix(),
				"cnf":       map[string]any{"jkt": "thumb-entra"},
				"iat":       now.Unix(),
				"exp":       now.Add(5 * time.Minute).Unix(),
			},
			wantTenant:   "tenant-1",
			wantClientID: "app-entra",
			wantRoles:    []string{"MCP.Operator"},
			wantGroups:   []string{"grp-sec"},
			wantScopes:   []string{"Files.Read", "Mail.Send"},
			wantJKT:      "thumb-entra",
			wantACR:      "urn:mace:incommon:iap:silver",
		},
		{
			name:     "keycloak_nested_realm_roles",
			provider: ProviderKeycloak,
			claims: jwt.MapClaims{
				"iss":          "https://sso.example.com/realms/corp",
				"sub":          "user-kc",
				"aud":          "https://gw.example.com/mcp",
				"organization": "acme-br",
				"azp":          "kc-client",
				"scope":        "openid mcp:tools",
				"realm_access": map[string]any{"roles": []string{"admin", "auditor"}},
				"groups":       []string{"/engineering"},
				"iat":          now.Unix(),
				"exp":          now.Add(5 * time.Minute).Unix(),
			},
			wantTenant:   "acme-br",
			wantClientID: "kc-client",
			wantRoles:    []string{"admin", "auditor"},
			wantGroups:   []string{"/engineering"},
			wantScopes:   []string{"openid", "mcp:tools"},
		},
		{
			name:     "okta_cid_and_scp",
			provider: ProviderOkta,
			claims: jwt.MapClaims{
				"iss":    "https://corp.okta.com/oauth2/default",
				"sub":    "user-okta",
				"aud":    "https://gw.example.com/mcp",
				"org_id": "okta-org",
				"cid":    "okta-client",
				"scp":    []string{"mcp:read", "mcp:write"},
				"groups": []string{"Everyone", "SRE"},
				"iat":    now.Unix(),
				"exp":    now.Add(5 * time.Minute).Unix(),
			},
			wantTenant:   "okta-org",
			wantClientID: "okta-client",
			wantGroups:   []string{"Everyone", "SRE"},
			wantScopes:   []string{"mcp:read", "mcp:write"},
		},
		{
			name:     "auth0_org_and_permissions",
			provider: ProviderAuth0,
			claims: jwt.MapClaims{
				"iss":         "https://corp.us.auth0.com/",
				"sub":         "auth0|123",
				"aud":         "https://gw.example.com/mcp",
				"org_id":      "org_abc",
				"azp":         "auth0-client",
				"scope":       "read:tools",
				"permissions": []string{"delete:records", "read:records"},
				"iat":         now.Unix(),
				"exp":         now.Add(5 * time.Minute).Unix(),
			},
			wantTenant:   "org_abc",
			wantClientID: "auth0-client",
			wantRoles:    []string{"delete:records", "read:records"},
			wantScopes:   []string{"read:tools"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			iss := claimString(tc.claims, "iss")
			v := NewVerifier(fixedKeySource{kid: "k1", key: pub}, VerifierOptions{
				Issuer:     iss,
				Audiences:  []string{"https://gw.example.com/mcp"},
				Algorithms: []string{"EdDSA"},
				Claims:     ResolveClaimMapping(tc.provider, ClaimMapping{}),
				Now:        func() time.Time { return now },
			})
			tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, tc.claims)
			tok.Header["kid"] = "k1"
			signed, err := tok.SignedString(priv)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			p, err := v.Verify(t.Context(), signed)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if p.Tenant != tc.wantTenant || p.ClientID != tc.wantClientID ||
				!slices.Equal(p.Roles, tc.wantRoles) ||
				!slices.Equal(p.Groups, tc.wantGroups) ||
				!slices.Equal(p.Scopes, tc.wantScopes) ||
				p.TokenThumbprint != tc.wantJKT ||
				p.ACR != tc.wantACR {
				t.Fatalf("unexpected principal: %+v", p)
			}
		})
	}
}

func TestDiscoverMetadataOIDCAndFallbackAndMixupProtection(t *testing.T) {
	t.Parallel()

	t.Run("openid_configuration", func(t *testing.T) {
		t.Parallel()
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			if err := json.NewEncoder(w).Encode(DiscoveryMetadata{
				Issuer:  srv.URL,
				JWKSURI: srv.URL + "/keys",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}))
		defer srv.Close()

		meta, err := DiscoverMetadata(t.Context(), srv.URL, srv.Client(), true)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		if meta.JWKSURI != srv.URL+"/keys" {
			t.Fatalf("jwks_uri = %q", meta.JWKSURI)
		}
		if _, err := DiscoverMetadata(t.Context(), srv.URL, srv.Client(), false); !errors.Is(err, ErrDiscovery) {
			t.Fatalf("plain http without allow_insecure = %v, want ErrDiscovery", err)
		}
	})

	t.Run("rfc8414_fallback", func(t *testing.T) {
		t.Parallel()
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/oauth-authorization-server" {
				http.NotFound(w, r)
				return
			}
			if err := json.NewEncoder(w).Encode(DiscoveryMetadata{
				Issuer:  srv.URL,
				JWKSURI: srv.URL + "/jwks.json",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}))
		defer srv.Close()

		meta, err := DiscoverMetadata(t.Context(), srv.URL, srv.Client(), true)
		if err != nil {
			t.Fatalf("fallback discover: %v", err)
		}
		if meta.JWKSURI != srv.URL+"/jwks.json" {
			t.Fatalf("jwks_uri = %q", meta.JWKSURI)
		}
	})

	t.Run("rejects_issuer_mixup", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if err := json.NewEncoder(w).Encode(DiscoveryMetadata{
				Issuer:  "https://evil.example.com",
				JWKSURI: "https://evil.example.com/jwks",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}))
		defer srv.Close()

		_, err := DiscoverMetadata(t.Context(), srv.URL, srv.Client(), true)
		if !errors.Is(err, ErrDiscovery) {
			t.Fatalf("mixup error = %v, want ErrDiscovery", err)
		}
	})
}
