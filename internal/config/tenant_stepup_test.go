package config

import (
	"strings"
	"testing"
)

func TestTenantPolicyAndStepUpValidation(t *testing.T) {
	t.Parallel()
	base := `
server:
  public_url: https://gw.example.com/mcp
auth:
  mode: none
upstreams:
  - id: crm
    transport: streamable_http
    url: https://crm.example.com/mcp
audit:
  enabled: false
`
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{
			name: "valid_tenant_policies_stepup_and_tenant_rate_limits",
			extra: `
policy:
  default: deny
  tenants:
    acme:
      default: deny
      rules:
        - name: wire-transfer
          tools: ["crm__wire"]
          subjects:
            tenants: ["acme"]
            roles_any: ["finance"]
          effect: allow
          on_deny:
            step_up_scopes: ["payments:approve"]
            acr_values: ["phr"]
            max_age: 5m
            require_dpop: false
rate_limits:
  rules:
    - name: per-tenant
      tools: ["*"]
      per: tenant
      rate: 60/m
      burst: 10
    - name: per-tenant-tool
      tools: ["crm__wire"]
      per: tenant_tool
      rate: 10/m
      burst: 2
`,
		},
		{
			name: "rejects_stepup_on_deny_rule",
			extra: `
policy:
  default: deny
  rules:
    - name: bad-stepup
      tools: ["*"]
      effect: deny
      on_deny:
        acr_values: ["phr"]
`,
			wantErr: "step-up requirements only make sense on allow rules",
		},
		{
			name: "rejects_excessive_max_age",
			extra: `
policy:
  default: deny
  rules:
    - name: bad-age
      tools: ["*"]
      effect: allow
      on_deny:
        max_age: 48h
`,
			wantErr: "on_deny.max_age",
		},
		{
			name: "rejects_duplicate_rule_inside_tenant",
			extra: `
policy:
  default: deny
  tenants:
    acme:
      rules:
        - name: dup
          tools: ["a"]
          effect: allow
        - name: dup
          tools: ["b"]
          effect: allow
`,
			wantErr: "duplicate rule name",
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
