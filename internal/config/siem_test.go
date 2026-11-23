package config

import (
	"strings"
	"testing"
)

func TestAuditSIEMValidation(t *testing.T) {
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
			name: "valid_splunk_hec",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  siem:
    endpoint: https://splunk.example.com:8088/services/collector/event
    format: splunk_hec
    index: mcp_security
    headers:
      Authorization: "Splunk token"
    block_private_ips: true
`,
		},
		{
			name: "valid_cef_loopback",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  siem:
    endpoint: http://127.0.0.1:9000/cef
    format: cef
`,
		},
		{
			name: "rejects_unknown_format",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  siem:
    endpoint: https://siem.example.com/events
    format: syslog
`,
			wantErr: "audit.siem.format",
		},
		{
			name: "rejects_plain_http_non_loopback",
			audit: `
audit:
  enabled: true
  path: audit.jsonl
  siem:
    endpoint: http://siem.example.com/events
    format: json
`,
			wantErr: "allow_insecure",
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
