package config

import (
	"strings"
	"testing"
)

func TestDPoPAndEnterpriseProviderValidation(t *testing.T) {
	t.Parallel()
	base := `
server:
  public_url: https://gw.example.com/mcp
upstreams:
  - id: demo
    transport: streamable_http
    url: https://up.example.com/mcp
audit:
  enabled: false
`
	cases := []struct {
		name    string
		auth    string
		wantErr string
	}{
		{
			name: "valid_entra_with_oidc_discovery_and_dpop_required",
			auth: `
auth:
  mode: jwt
  provider: entra
  resource: https://gw.example.com/mcp
  authorization_servers: ["https://login.microsoftonline.com/tenant/v2.0"]
  dpop:
    mode: required
    algorithms: ["ES256", "EdDSA"]
    max_age: 60s
    nonce_required: true
    nonce_ttl: 5m
  jwt:
    issuer: https://login.microsoftonline.com/tenant/v2.0
    audiences: ["https://gw.example.com/mcp"]
`,
		},
		{
			name: "rejects_symmetric_dpop_algorithm",
			auth: `
auth:
  mode: jwt
  resource: https://gw.example.com/mcp
  authorization_servers: ["https://idp.example.com"]
  dpop:
    mode: required
    algorithms: ["HS256"]
  jwt:
    issuer: https://idp.example.com
    jwks_url: https://idp.example.com/jwks
    audiences: ["https://gw.example.com/mcp"]
`,
			wantErr: "auth.dpop.algorithms[0]",
		},
		{
			name: "rejects_unknown_provider",
			auth: `
auth:
  mode: jwt
  provider: unknown-idp
  resource: https://gw.example.com/mcp
  authorization_servers: ["https://idp.example.com"]
  jwt:
    issuer: https://idp.example.com
    jwks_url: https://idp.example.com/jwks
    audiences: ["https://gw.example.com/mcp"]
`,
			wantErr: "auth.provider",
		},
		{
			name: "rejects_plain_http_oidc_discovery_without_allow_insecure",
			auth: `
auth:
  mode: jwt
  resource: https://gw.example.com/mcp
  authorization_servers: ["http://idp.example.com"]
  jwt:
    issuer: http://idp.example.com
    audiences: ["https://gw.example.com/mcp"]
`,
			wantErr: "allow_insecure_jwks",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Parse(
				[]byte(base+tc.auth),
				func(string) (string, bool) { return "", false },
				func() []string { return nil },
			)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
