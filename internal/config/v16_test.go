package config

import (
	"strings"
	"testing"
	"time"
)

func TestV16ConfigValidation(t *testing.T) {
	t.Parallel()
	base := `
server:
  public_url: https://gw.example.com/mcp
  stamp_provenance: true
auth:
  mode: none
upstreams:
  - id: web
    transport: streamable_http
    url: https://up.example.com/mcp
    metadata:
      trust: untrusted
      classification: public
      egress: true
      impact: read
`
	t.Run("valid_full_v16_config", func(t *testing.T) {
		t.Parallel()
		raw := base + `
rate_limits:
  rules:
    - name: bulk-delete-budget
      tools: ["web__*"]
      per: subject
      rate: "100/m"
      burst: 20
      cost_expr: "has(args.ids) ? size(args.ids) : 1"
      max_cost: 10
idempotency:
  enabled: true
  mode: required
  header: Idempotency-Key
  ttl: 5m
  max_entries: 5000
  tools: ["web__delete_*"]
`
		cfg, err := Parse(
			[]byte(raw),
			func(string) (string, bool) { return "", false },
			func() []string { return nil },
		)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validate error: %v", err)
		}
		if !cfg.Server.StampProvenance {
			t.Fatal("expected stamp_provenance=true")
		}
		if cfg.Upstreams[0].Metadata.Trust != TrustUntrusted || !cfg.Upstreams[0].Metadata.Egress {
			t.Fatalf("unexpected upstream metadata: %+v", cfg.Upstreams[0].Metadata)
		}
		if cfg.RateLimits.Rules[0].MaxCost != 10 || cfg.RateLimits.Rules[0].CostExpr == "" {
			t.Fatalf("unexpected rate limit rule: %+v", cfg.RateLimits.Rules[0])
		}
		if !cfg.Idempotency.Enabled || cfg.Idempotency.Mode != IdempotencyModeRequired ||
			cfg.Idempotency.TTL != 5*time.Minute {
			t.Fatalf("unexpected idempotency config: %+v", cfg.Idempotency)
		}
	})

	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "invalid_metadata_trust",
			yaml: `
server:
  public_url: https://gw.example.com/mcp
auth:
  mode: none
upstreams:
  - id: u
    transport: streamable_http
    url: https://up.example.com/mcp
    metadata:
      trust: maybe
`,
			wantErr: "upstreams[0].metadata.trust",
		},
		{
			name: "invalid_metadata_classification",
			yaml: `
server:
  public_url: https://gw.example.com/mcp
auth:
  mode: none
upstreams:
  - id: u
    transport: streamable_http
    url: https://up.example.com/mcp
    metadata:
      classification: top_secret
`,
			wantErr: "upstreams[0].metadata.classification",
		},
		{
			name: "invalid_metadata_impact",
			yaml: `
server:
  public_url: https://gw.example.com/mcp
auth:
  mode: none
upstreams:
  - id: u
    transport: streamable_http
    url: https://up.example.com/mcp
    metadata:
      impact: nuke
`,
			wantErr: "upstreams[0].metadata.impact",
		},
		{
			name: "invalid_rate_max_cost_exceeds_burst",
			yaml: base + `
rate_limits:
  rules:
    - name: r1
      tools: ["*"]
      per: subject
      rate: "10/m"
      burst: 5
      max_cost: 6
`,
			wantErr: "max_cost",
		},
		{
			name: "invalid_rate_negative_max_cost",
			yaml: base + `
rate_limits:
  rules:
    - name: r1
      tools: ["*"]
      per: subject
      rate: "10/m"
      burst: 5
      max_cost: -1
`,
			wantErr: "max_cost",
		},
		{
			name: "invalid_idempotency_mode",
			yaml: base + `
idempotency:
  enabled: true
  mode: magic
`,
			wantErr: "idempotency.mode",
		},
		{
			name: "invalid_idempotency_ttl_too_large",
			yaml: base + `
idempotency:
  enabled: true
  mode: header
  ttl: 48h
`,
			wantErr: "idempotency.ttl",
		},
		{
			name: "invalid_idempotency_max_entries_too_small",
			yaml: base + `
idempotency:
  enabled: true
  mode: canonical_hash
  max_entries: 10
`,
			wantErr: "idempotency.max_entries",
		},
		{
			name: "invalid_idempotency_bad_glob",
			yaml: base + `
idempotency:
  enabled: true
  mode: canonical_hash
  tools: ["[bad"]
`,
			wantErr: "idempotency.tools",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Parse(
				[]byte(tc.yaml),
				func(string) (string, bool) { return "", false },
				func() []string { return nil },
			)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
