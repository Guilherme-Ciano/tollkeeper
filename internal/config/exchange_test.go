package config

import (
	"strings"
	"testing"
)

func TestTokenExchangeValidation(t *testing.T) {
	t.Parallel()
	base := `
server:
  public_url: https://gw.example.com
auth:
  mode: none
audit:
  enabled: false
`
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{
			name: "valid with resource",
			extra: `
upstreams:
  - id: crm
    transport: streamable_http
    url: https://crm.example.com/mcp
    auth:
      type: token_exchange
      token_url: https://idp.example.com/oauth/token
      client_id: gw
      client_secret: secret
      resource: https://crm.example.com/mcp
      scopes: ["crm:read"]
      token_exchange:
        intersect_caller_scopes: true
        max_delegation_depth: 1
        cache_ttl: 2m
        timeout: 5s
`,
		},
		{
			name: "valid with audience only",
			extra: `
upstreams:
  - id: crm
    transport: streamable_http
    url: https://crm.example.com/mcp
    auth:
      type: token_exchange
      token_url: https://idp.example.com/oauth/token
      client_id: gw
      client_secret: secret
      token_exchange:
        audience: crm-service
`,
		},
		{
			name: "rejects missing resource and audience",
			extra: `
upstreams:
  - id: crm
    transport: streamable_http
    url: https://crm.example.com/mcp
    auth:
      type: token_exchange
      token_url: https://idp.example.com/oauth/token
      client_id: gw
      client_secret: secret
`,
			wantErr: "requires resource or token_exchange.audience",
		},
		{
			name: "rejects non-loopback plain http token_url",
			extra: `
upstreams:
  - id: crm
    transport: streamable_http
    url: https://crm.example.com/mcp
    auth:
      type: token_exchange
      token_url: http://idp.example.com/token
      client_id: gw
      client_secret: secret
      resource: https://crm.example.com/mcp
`,
			wantErr: "allow_insecure",
		},
		{
			name: "rejects negative delegation depth",
			extra: `
upstreams:
  - id: crm
    transport: streamable_http
    url: https://crm.example.com/mcp
    auth:
      type: token_exchange
      token_url: https://idp.example.com/token
      client_id: gw
      client_secret: secret
      resource: https://crm.example.com/mcp
      token_exchange:
        max_delegation_depth: -1
`,
			wantErr: "max_delegation_depth",
		},
		{
			name: "validates subjects actors glob",
			extra: `
upstreams:
  - id: crm
    transport: streamable_http
    url: https://crm.example.com/mcp
policy:
  default: deny
  rules:
    - name: bad-actor-glob
      tools: ["*"]
      subjects:
        actors: ["[invalid"]
      effect: allow
`,
			wantErr: "subjects.actors",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Parse(
				[]byte(base+tc.extra),
				func(string) (string, bool) { return "", false },
				func() []string { return nil },
			)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
