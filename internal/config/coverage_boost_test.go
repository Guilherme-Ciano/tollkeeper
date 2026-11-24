package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func minimalValidConfig() Config {
	cfg := Defaults()
	cfg.Server.PublicURL = "https://mcp.example.com"
	cfg.Auth.Mode = AuthModeNone
	cfg.Audit.Enabled = false
	cfg.Pinning.Mode = PinModeOff
	cfg.Upstreams = []Upstream{
		{
			ID:             "svc",
			Transport:      TransportStreamable,
			URL:            "https://up.example.com/mcp",
			Timeout:        5 * time.Second,
			MaxConcurrency: 10,
			Breaker:        Breaker{Failures: 3, OpenFor: 10 * time.Second},
			RestartBackoff: time.Second,
			RestartMax:     10 * time.Second,
			Auth:           UpstreamAuth{Type: UpstreamAuthNone},
			Sandbox: StdioSandbox{
				Mode:    SandboxModeOff,
				Backend: SandboxBackendAuto,
				Network: SandboxNetworkInherit,
			},
		},
	}
	return cfg
}

func TestValidatePolicyStandalone(t *testing.T) {
	t.Parallel()
	valid := Policy{
		Default: EffectDeny,
		Rules: []Rule{
			{
				Name:   "allow-read",
				Tools:  []string{"svc__read"},
				Effect: EffectAllow,
				OnDeny: OnDeny{MaxAge: time.Minute, ApprovalTTL: 5 * time.Minute},
			},
		},
		Tenants: map[string]TenantPolicy{
			"acme": {
				Default: EffectDeny,
				Rules: []Rule{
					{Name: "acme-prompt", Prompts: []string{"svc__*"}, Effect: EffectAllow},
				},
			},
		},
	}
	if err := ValidatePolicy(valid); err != nil {
		t.Fatalf("ValidatePolicy(valid): %v", err)
	}

	invalid := Policy{
		Default: "bogus",
		Rules: []Rule{
			{
				Name:   "dup",
				Effect: EffectDeny,
				Mode:   "bad",
				OnDeny: OnDeny{RequireApproval: true, MaxAge: 48 * time.Hour, ApprovalTTL: -time.Second},
			},
			{
				Name:   "dup",
				Tools:  []string{"svc__a"},
				Effect: EffectAllow,
			},
		},
		Tenants: map[string]TenantPolicy{
			"t1": {Default: "nope"},
		},
	}
	err := ValidatePolicy(invalid)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	for _, want := range []string{"policy.default", "duplicate rule name", "on_deny.max_age", "on_deny.approval_ttl", "policy.tenants.t1.default"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %v", want, err)
		}
	}
}

func TestValidateIntrospectionAndTasks(t *testing.T) {
	t.Parallel()
	cfg := minimalValidConfig()
	cfg.Server.TasksEnabled = true
	cfg.Server.TaskTTL = 30 * time.Minute
	cfg.Auth = Auth{
		Mode:                 AuthModeIntrospection,
		Resource:             "https://mcp.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
		DPoP:                 DPoP{Mode: DPoPModeOff},
		Introspection: Introspection{
			URL:          "https://idp.example.com/introspect",
			ClientID:     "cid",
			ClientSecret: "csec",
			Issuer:       "https://idp.example.com",
			Audiences:    []string{"https://mcp.example.com"},
			CacheTTL:     time.Minute,
			Timeout:      5 * time.Second,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid introspection + tasks failed: %v", err)
	}

	bad := cfg
	bad.Server.TaskTTL = 48 * time.Hour
	bad.Auth.Introspection = Introspection{
		URL:      "http://idp.example.com/introspect",
		Issuer:   "ftp://bad",
		CacheTTL: 2 * time.Hour,
		Timeout:  time.Minute,
	}
	err := bad.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	for _, want := range []string{
		"server.task_ttl",
		"auth.introspection.url",
		"auth.introspection.client_id",
		"auth.introspection.client_secret",
		"auth.introspection.issuer",
		"auth.introspection.audiences",
		"auth.introspection.cache_ttl",
		"auth.introspection.timeout",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %v", want, err)
		}
	}
}

func TestValidateAuditOTLPSIEMAndAnchor(t *testing.T) {
	t.Parallel()
	cfg := minimalValidConfig()
	cfg.Audit.Enabled = true
	cfg.Audit.Path = "audit.jsonl"
	cfg.Audit.OTLP = AuditOTLP{
		Endpoint: "http://collector.example.com/v1/logs",
		Batch:    0,
		Queue:    0,
		Interval: 0,
		Timeout:  2 * time.Minute,
	}
	cfg.Audit.SIEM = AuditSIEM{
		Endpoint: "http://siem.example.com/hec",
		Format:   "xml",
		Batch:    0,
		Queue:    0,
		Interval: 2 * time.Minute,
		Timeout:  0,
	}
	cfg.Audit.Anchor = AuditAnchor{
		Enabled:    true,
		RekorURL:   "https://rekor.example.com",
		TSAURL:     "http://tsa.example.com/ts",
		Every:      -1,
		Interval:   10 * time.Second,
		Timeout:    5 * time.Second,
		MinSpacing: 5 * time.Second,
		MaxBackoff: 2 * time.Hour,
	}

	err := cfg.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	for _, want := range []string{
		"audit.otlp.endpoint",
		"audit.otlp.batch",
		"audit.otlp.interval",
		"audit.otlp.timeout",
		"audit.siem.endpoint",
		"audit.siem.format",
		"audit.siem.batch",
		"audit.siem.interval",
		"audit.siem.timeout",
		"audit.anchor.tsa_url",
		"audit.anchor.every",
		"audit.anchor.interval",
		"audit.anchor.timeout",
		"audit.anchor.min_spacing",
		"audit.anchor.max_backoff",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %v", want, err)
		}
	}

	okOTLP := minimalValidConfig()
	okOTLP.Audit.Enabled = true
	okOTLP.Audit.Path = "audit.jsonl"
	okOTLP.Audit.OTLP.Endpoint = "http://127.0.0.1:4318/v1/logs"
	okOTLP.Audit.SIEM.Endpoint = "http://127.0.0.1:8088/services/collector"
	if err := okOTLP.Validate(); err != nil {
		t.Fatalf("loopback OTLP/SIEM should be valid: %v", err)
	}
}

func TestValidateApprovalsBundleIdempotencyAndMetadata(t *testing.T) {
	t.Parallel()
	cfg := minimalValidConfig()
	cfg.Upstreams[0].Metadata = UpstreamMetadata{
		Trust:          "bad-trust",
		Classification: "bad-class",
		Impact:         "bad-impact",
	}
	cfg.Idempotency = Idempotency{
		Enabled:    true,
		Mode:       IdempotencyModeHeader,
		Header:     "",
		TTL:        48 * time.Hour,
		MaxEntries: 10,
	}
	cfg.Approvals = Approvals{
		Enabled:    true,
		Header:     "",
		MaxTTL:     48 * time.Hour,
		ClockSkew:  10 * time.Minute,
		SingleUse:  true,
		MaxEntries: 10,
	}
	cfg.Bundle = Bundle{
		Enabled:     true,
		RequirePins: true,
	}

	err := cfg.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	for _, want := range []string{
		"metadata.trust",
		"metadata.classification",
		"metadata.impact",
		"idempotency.header",
		"idempotency.ttl",
		"approvals.header",
		"approvals.pubkey_files",
		"approvals.max_ttl",
		"approvals.clock_skew",
		"approvals.max_entries",
		"bundle.manifest_file",
		"bundle.pubkey_files",
		"bundle.require_pins",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %v", want, err)
		}
	}

	okCanon := minimalValidConfig()
	okCanon.Idempotency = Idempotency{
		Enabled:    true,
		Mode:       IdempotencyModeCanonicalHash,
		TTL:        5 * time.Minute,
		MaxEntries: 500,
		Tools:      []string{"svc__*"},
	}
	if err := okCanon.Validate(); err != nil {
		t.Fatalf("canonical_hash idempotency without header should be valid: %v", err)
	}
}
