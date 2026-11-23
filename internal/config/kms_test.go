package config

import (
	"strings"
	"testing"
)

func TestAuditKMSValidation(t *testing.T) {
	t.Parallel()
	base := `
server:
  public_url: https://gw.example.com
auth:
  mode: none
upstreams:
  - id: demo
    transport: streamable_http
    url: https://up.example.com/mcp
`
	cases := []struct {
		name    string
		audit   string
		wantErr string
	}{
		{
			name: "valid vault https",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  checkpoint:
    every: 100
    kms:
      provider: vault
      key_id: tollkeeper-audit
      timeout: 5s
      vault:
        address: https://vault.example.com
        mount: transit
        token: s.example
`,
		},
		{
			name: "valid aws kms",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  checkpoint:
    every: 100
    kms:
      provider: aws
      key_id: alias/tollkeeper-audit
      aws:
        region: us-east-1
        access_key_id: AKIAEXAMPLE
        secret_access_key: secret
`,
		},
		{
			name: "mutually exclusive with signing_key_file",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  checkpoint:
    every: 100
    signing_key_file: key.pem
    kms:
      provider: vault
      key_id: k
      vault:
        address: https://vault.example.com
        token: tok
`,
			wantErr: "mutually exclusive",
		},
		{
			name: "rejects non-loopback plain http vault",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  checkpoint:
    every: 100
    kms:
      provider: vault
      key_id: k
      vault:
        address: http://vault.example.com:8200
        token: tok
`,
			wantErr: "allow_insecure",
		},
		{
			name: "allows loopback plain http vault for dev",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  checkpoint:
    every: 100
    kms:
      provider: vault
      key_id: k
      vault:
        address: http://127.0.0.1:8200
        token: tok
`,
		},
		{
			name: "rejects missing aws credentials",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  checkpoint:
    every: 100
    kms:
      provider: aws
      key_id: alias/audit
      aws:
        region: us-east-1
`,
			wantErr: "access_key_id",
		},
		{
			name: "rejects unknown provider",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  checkpoint:
    every: 100
    kms:
      provider: gcp
      key_id: k
`,
			wantErr: "must be one of vault|aws",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Parse(
				[]byte(base+tc.audit),
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
