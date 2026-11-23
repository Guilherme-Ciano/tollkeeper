package config

import (
	"strings"
	"testing"
)

func TestAuditVerifyAndRetentionValidation(t *testing.T) {
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
	cases := []struct {
		name    string
		audit   string
		wantErr string
	}{
		{
			name: "valid_verify_and_retention",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  verify:
    enabled: true
    interval: 1m
    max_unsigned: 500
  retention:
    archive_dir: /var/lib/tollkeeper/archives
    max_age: 720h
    max_archives: 30
`,
		},
		{
			name: "rejects_too_fast_verify_interval",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  verify:
    enabled: true
    interval: 1s
`,
			wantErr: "audit.verify.interval",
		},
		{
			name: "requires_archive_dir_when_max_age_set",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  retention:
    max_age: 24h
`,
			wantErr: "audit.retention.archive_dir",
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
