package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimal = `
server:
  public_url: "https://gw.example.com/mcp"
auth:
  resource: "https://gw.example.com/mcp"
  authorization_servers: ["https://issuer.example.com"]
  jwt:
    issuer: "https://issuer.example.com"
    jwks_url: "https://issuer.example.com/jwks.json"
    audiences: ["https://gw.example.com/mcp"]
upstreams:
  - id: notes
    transport: stdio
    command: ["/bin/notes", "--stdio"]
  - id: files
    transport: streamable_http
    url: "http://files:8082/mcp"
    auth:
      type: client_credentials
      token_url: "http://issuer/token"
      client_id: gw
      client_secret: "${FILES_SECRET}"
rate_limits:
  rules:
    - { name: all, tools: ["*"], per: subject, rate: 600/m, burst: 60 }
`

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestParseDefaultsAndEnv(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(minimal), lookup(map[string]string{"FILES_SECRET": "s3cret"}), func() []string {
		return []string{"TOLLKEEPER_SERVER__LISTEN=:7070", "TOLLKEEPER_AUDIT__RECORD_ARGS=none", "UNRELATED=1"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":7070" || cfg.Audit.RecordArgs != RecordArgsNone {
		t.Fatalf("env overlay not applied: %+v", cfg.Server)
	}
	if cfg.Server.AdminListen != "127.0.0.1:9090" || cfg.Audit.BatchSize != 512 ||
		cfg.Auth.JWT.ClockSkew != 30*time.Second {
		t.Fatal("defaults not applied")
	}
	u := cfg.Upstreams[1]
	if u.Auth.ClientSecret != "s3cret" || u.Timeout != 15*time.Second || u.MaxConcurrency != 64 ||
		u.Breaker.Failures != 5 {
		t.Fatalf("upstream defaults/env: %+v", u)
	}
	if cfg.Upstreams[0].Auth.Type != UpstreamAuthNone {
		t.Fatal("stdio auth default")
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	none := func() []string { return nil }
	if _, err := Parse([]byte(minimal), lookup(nil), none); !errors.Is(err, ErrMissingEnv) {
		t.Fatalf("missing env: %v", err)
	}
	injected, err := Parse([]byte(minimal), lookup(map[string]string{"FILES_SECRET": "x\"\n    type: none\n#"}), none)
	if err != nil {
		t.Fatal(err)
	}
	if got := injected.Upstreams[1].Auth; got.Type != UpstreamAuthClientCredentials ||
		!strings.Contains(got.ClientSecret, "type: none") {
		t.Fatalf("env value changed the YAML structure: %+v", got)
	}
	if _, err := Parse(
		[]byte("server:\n  lsiten: x\n"),
		lookup(nil),
		none,
	); err == nil ||
		!strings.Contains(err.Error(), "lsiten") {
		t.Fatalf("unknown key accepted: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), lookup(nil)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestValidateReportsEveryField(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Server.AdminListen = cfg.Server.Listen
	cfg.Auth.JWT.JWKSURL = "http://issuer/jwks.json"
	cfg.Auth.JWT.Algorithms = []string{"HS256"}
	cfg.Upstreams = []Upstream{
		defaultUpstream(Upstream{ID: "Bad_ID", Transport: "carrier-pigeon"}),
		defaultUpstream(Upstream{ID: "x", Transport: TransportStdio, URL: "http://x"}),
		defaultUpstream(
			Upstream{
				ID:        "x",
				Transport: TransportStreamable,
				URL:       "ftp://x",
				Auth:      UpstreamAuth{Type: UpstreamAuthBearer},
			},
		),
	}
	cfg.Policy.Rules = []Rule{{Name: "r", Tools: []string{"[bad"}, Effect: "maybe"}, {Name: "r"}}
	cfg.RateLimits.Rules = []RateRule{{Name: "x", Per: "galaxy", Rate: "10/fortnight"}}
	cfg.Server.NamespaceTools = false
	cfg.Pinning.Mode = PinModeEnforce
	cfg.RateLimits.Store = RateStoreRedis
	cfg.RateLimits.Redis.Addrs = []string{"a:6379", "b:6379"}
	cfg.Audit.Postgres.DSN = "postgres://x"
	cfg.Audit.Fsync = false
	err := cfg.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	for _, field := range []string{
		"server.admin_listen", "server.public_url", "auth.resource", "auth.jwt.jwks_url", "auth.jwt.algorithms[0]",
		"upstreams[0].id", "upstreams[0].transport", "upstreams[1].command", "upstreams[1].url", "upstreams[2].id",
		"upstreams[2].url", "upstreams[2].auth.token", "policy.rules[0].tools[0]", "policy.rules[0].effect",
		"policy.rules[1].name", "policy.rules[1].tools", "rate_limits.rules[0].per", "rate_limits.rules[0].rate",
		"rate_limits.rules[0].burst", "server.namespace_tools", "pinning.file",
		"rate_limits.redis.key_prefix", "audit.fsync", "audit.chain_id",
	} {
		if !strings.Contains(err.Error(), field+":") {
			t.Errorf("missing error for %s in:\n%v", field, err)
		}
	}
}

func TestParseRate(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]time.Duration{"10/s": time.Second, "600/m": time.Minute, "5/h": time.Hour} {
		if _, per, err := ParseRate(in); err != nil || per != want {
			t.Fatalf("%s: %v %v", in, per, err)
		}
	}
	for _, bad := range []string{"", "10", "0/s", "-1/s", "x/s", "10/d"} {
		if _, _, err := ParseRate(bad); !errors.Is(err, ErrBadRate) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestComposeConfigValidates(t *testing.T) {
	t.Parallel()
	cfg, err := Load("../../deploy/compose/gateway.yaml", lookup(map[string]string{"FILES_CLIENT_SECRET": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSeparatorMustNotOverlapUpstreamIDs(t *testing.T) {
	t.Parallel()
	for sep, ok := range map[string]bool{"__": true, ".": true, "--": false, "x": false, "a1": false, "::": true} {
		cfg := Defaults()
		cfg.Server.NamespaceSeparator = sep
		err := cfg.Validate()
		has := err != nil && strings.Contains(err.Error(), "server.namespace_separator")
		if has == ok {
			t.Fatalf("separator %q: valid=%t, err=%v", sep, ok, err)
		}
	}
}

func TestHardeningValidation(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Auth.JWT.JWKSMinRetry = 0
	cfg.Server.Pprof = true
	cfg.Server.AdminListen = "0.0.0.0:9090"
	cfg.RateLimits.Rules = []RateRule{
		{Name: "too-fast", Per: PerSubject, Rate: "2000000000/s", Burst: 1},
		{Name: "huge-burst", Per: PerSubject, Rate: "1/h", Burst: 2_000_000_000},
	}
	err := cfg.Validate()
	for _, field := range []string{"auth.jwt.jwks_min_retry", "server.pprof", "rate_limits.rules[0].rate", "rate_limits.rules[1].burst"} {
		if err == nil || !strings.Contains(err.Error(), field+":") {
			t.Errorf("missing error for %s: %v", field, err)
		}
	}
	if Defaults().Server.AdminListen != "127.0.0.1:9090" {
		t.Fatal("admin listener must default to loopback")
	}
}
