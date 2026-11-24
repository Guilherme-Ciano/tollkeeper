package config

import (
	"strings"
	"testing"
)

func TestApprovalsAndBundleConfigValidation(t *testing.T) {
	t.Parallel()
	base := `
server:
  public_url: https://gw.example.com/mcp
auth:
  mode: none
upstreams:
  - id: demo
    transport: streamable_http
    url: https://up.example.com/mcp
`
	t.Run("valid_approvals_and_bundle", func(t *testing.T) {
		t.Parallel()
		raw := base + `
pinning:
  mode: warn
  file: pins.json
policy:
  default: deny
  rules:
    - name: del-approval
      tools: ["demo__delete"]
      when: "approval.verified && approval.approver != principal.sub"
      effect: allow
      on_deny:
        require_approval: true
        approval_ttl: 5m
        approval_reason: "needs sign-off"
approvals:
  enabled: true
  issuer: https://approvals.example.com
  header: X-Tollkeeper-Approval
  pubkey_files: ["approval.pub"]
  max_ttl: 15m
  single_use: true
  max_entries: 5000
bundle:
  enabled: true
  manifest_file: bundle.sig.json
  pubkey_files: ["bundle.pub"]
  require_pins: true
`
		cfg, err := Parse(
			[]byte(raw),
			func(string) (string, bool) { return "", false },
			func() []string { return nil },
		)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
	})

	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{
			name: "approvals_missing_pubkeys",
			extra: `
approvals:
  enabled: true
`,
			wantErr: "approvals.pubkey_files",
		},
		{
			name: "approvals_ttl_too_large",
			extra: `
approvals:
  enabled: true
  pubkey_files: ["a.pub"]
  max_ttl: 48h
`,
			wantErr: "approvals.max_ttl",
		},
		{
			name: "approvals_require_on_deny_rule",
			extra: `
policy:
  default: deny
  rules:
    - name: bad
      tools: ["*"]
      effect: deny
      on_deny:
        require_approval: true
`,
			wantErr: "on_deny",
		},
		{
			name: "bundle_missing_manifest",
			extra: `
bundle:
  enabled: true
  pubkey_files: ["b.pub"]
`,
			wantErr: "bundle.manifest_file",
		},
		{
			name: "bundle_missing_pubkeys",
			extra: `
bundle:
  enabled: true
  manifest_file: bundle.sig.json
`,
			wantErr: "bundle.pubkey_files",
		},
		{
			name: "bundle_require_pins_without_pinning_file",
			extra: `
bundle:
  enabled: true
  manifest_file: bundle.sig.json
  pubkey_files: ["b.pub"]
  require_pins: true
`,
			wantErr: "bundle.require_pins",
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
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
