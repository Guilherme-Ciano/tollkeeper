package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid config")
	ErrBadRate  = errors.New("rate must look like 600/m, 10/s or 1000/h")
	upstreamIDs = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string {
	return e.Field + ": " + e.Reason
}

func (e *FieldError) Unwrap() error {
	return ErrInvalid
}

type validator struct {
	errs []error
}

func (v *validator) add(field, format string, args ...any) {
	v.errs = append(v.errs, &FieldError{Field: field, Reason: fmt.Sprintf(format, args...)})
}

func (v *validator) require(field, value string) {
	if strings.TrimSpace(value) == "" {
		v.add(field, "required")
	}
}

func (v *validator) oneOf(field, value string, allowed ...string) {
	if !slices.Contains(allowed, value) {
		v.add(field, "must be one of %s, got %q", strings.Join(allowed, "|"), value)
	}
}

func (v *validator) url(field, raw string, schemes ...string) {
	if raw == "" {
		v.add(field, "required")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !slices.Contains(schemes, u.Scheme) {
		v.add(field, "must be an absolute %s URL, got %q", strings.Join(schemes, "/"), raw)
	}
}

func (v *validator) globs(field string, patterns []string) {
	for i, p := range patterns {
		if _, err := path.Match(p, ""); err != nil || p == "" {
			v.add(fmt.Sprintf("%s[%d]", field, i), "invalid glob %q", p)
		}
	}
}

func (c *Config) Validate() error {
	v := &validator{}
	c.validateServer(v)
	c.validateAuth(v)
	c.validateUpstreams(v)
	c.validatePolicy(v)
	c.validateRateLimits(v)
	c.validateIdempotency(v)
	c.validateApprovals(v)
	c.validateBundle(v)
	c.validateAudit(v)
	c.validatePinning(v)
	if !c.Server.NamespaceTools && len(c.Upstreams) != 1 {
		v.add("server.namespace_tools", "false is only allowed with exactly one upstream, got %d", len(c.Upstreams))
	}
	v.oneOf("telemetry.log_format", c.Telemetry.LogFormat, "json", "text")
	v.oneOf("telemetry.log_level", c.Telemetry.LogLevel, "debug", "info", "warn", "error")
	if c.Telemetry.SampleRatio < 0 || c.Telemetry.SampleRatio > 1 {
		v.add("telemetry.sample_ratio", "must be within [0,1]")
	}
	return errors.Join(v.errs...)
}

func hashTagged(prefix string) bool {
	_, rest, ok := strings.Cut(prefix, "{")
	if !ok {
		return false
	}
	tag, _, ok := strings.Cut(rest, "}")
	return ok && tag != ""
}

func (c *Config) validatePinning(v *validator) {
	v.oneOf("pinning.mode", c.Pinning.Mode, PinModeOff, PinModeWarn, PinModeEnforce)
	if c.Pinning.Mode == PinModeEnforce && c.Pinning.File == "" {
		v.add("pinning.file", "required when pinning.mode is enforce")
	}
	if c.Pinning.Mode != PinModeOff && c.Pinning.ReloadInterval < 100*time.Millisecond {
		v.add("pinning.reload_interval", "must be at least 100ms")
	}
}

func (c *Config) validateServer(v *validator) {
	v.require("server.listen", c.Server.Listen)
	v.require("server.admin_listen", c.Server.AdminListen)
	if c.Server.Pprof && !Loopback(c.Server.AdminListen) {
		v.add("server.pprof", "only allowed when server.admin_listen is a loopback address")
	}
	if c.Server.Listen != "" && c.Server.Listen == c.Server.AdminListen {
		v.add("server.admin_listen", "must differ from server.listen")
	}
	v.url("server.public_url", c.Server.PublicURL, "http", "https")
	if c.Server.MaxBodyBytes <= 0 || c.Server.MaxBodyBytes > 64<<20 {
		v.add("server.max_body_bytes", "must be within (0, 64MiB]")
	}
	if c.Server.RequestStateTTL <= 0 || c.Server.RequestStateTTL > 24*time.Hour {
		v.add("server.request_state_ttl", "must be within (0, 24h]")
	}
	if c.Server.TasksEnabled && (c.Server.TaskTTL <= 0 || c.Server.TaskTTL > 24*time.Hour) {
		v.add("server.task_ttl", "must be within (0, 24h]")
	}
	sep := c.Server.NamespaceSeparator
	if sep == "" || strings.ContainsAny(sep, " *?[]") ||
		!strings.ContainsFunc(
			sep,
			func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' },
		) {
		v.add("server.namespace_separator",
			"must be non-empty, contain no spaces or glob characters, and contain a character upstream ids cannot use")
	}
}

func (c *Config) validateAuth(v *validator) {
	v.oneOf("auth.mode", c.Auth.Mode, AuthModeJWT, AuthModeIntrospection, AuthModeNone)
	v.oneOf(
		"auth.provider",
		c.Auth.Provider,
		AuthProviderGeneric,
		AuthProviderEntra,
		AuthProviderOkta,
		AuthProviderKeycloak,
		AuthProviderAuth0,
	)
	if c.Auth.Mode == AuthModeNone {
		return
	}
	c.validateDPoP(v)
	v.url("auth.resource", c.Auth.Resource, "http", "https")
	if len(c.Auth.AuthorizationServers) == 0 {
		v.add("auth.authorization_servers", "at least one authorization server is required")
	}
	for i, as := range c.Auth.AuthorizationServers {
		v.url(fmt.Sprintf("auth.authorization_servers[%d]", i), as, "http", "https")
	}
	if c.Auth.Mode == AuthModeIntrospection {
		c.validateIntrospection(v)
		return
	}
	v.url("auth.jwt.issuer", c.Auth.JWT.Issuer, "http", "https")
	if c.Auth.JWT.JWKSURL != "" {
		v.url("auth.jwt.jwks_url", c.Auth.JWT.JWKSURL, "http", "https")
		if strings.HasPrefix(c.Auth.JWT.JWKSURL, "http://") && !c.Auth.JWT.AllowInsecure {
			v.add("auth.jwt.jwks_url", "plain http requires auth.jwt.allow_insecure_jwks: true")
		}
	} else if strings.HasPrefix(c.Auth.JWT.Issuer, "http://") && !c.Auth.JWT.AllowInsecure {
		v.add("auth.jwt.issuer", "plain http OIDC discovery requires auth.jwt.allow_insecure_jwks: true")
	}
	if len(c.Auth.JWT.Audiences) == 0 {
		v.add("auth.jwt.audiences", "at least one audience is required (RFC 8707)")
	}
	if len(c.Auth.JWT.Audiences) > 0 && !slices.Contains(c.Auth.JWT.Audiences, c.Auth.Resource) {
		v.add("auth.jwt.audiences", "must include auth.resource %q", c.Auth.Resource)
	}
	if len(c.Auth.JWT.Algorithms) == 0 {
		v.add("auth.jwt.algorithms", "at least one algorithm is required")
	}
	for i, a := range c.Auth.JWT.Algorithms {
		v.oneOf(
			fmt.Sprintf("auth.jwt.algorithms[%d]", i),
			a,
			"RS256",
			"RS384",
			"RS512",
			"PS256",
			"ES256",
			"ES384",
			"EdDSA",
		)
	}
	if c.Auth.JWT.JWKSMinRetry < time.Second {
		v.add("auth.jwt.jwks_min_retry", "must be at least 1s to bound refetches for unknown key ids")
	}
	if c.Auth.JWT.ClockSkew < 0 || c.Auth.JWT.ClockSkew > 5*time.Minute {
		v.add("auth.jwt.clock_skew", "must be within [0, 5m]")
	}
}

func (c *Config) validateDPoP(v *validator) {
	d := c.Auth.DPoP
	v.oneOf("auth.dpop.mode", d.Mode, DPoPModeOff, DPoPModeOptional, DPoPModeRequired)
	if d.Mode == DPoPModeOff {
		return
	}
	if len(d.Algorithms) == 0 {
		v.add("auth.dpop.algorithms", "at least one asymmetric algorithm is required")
	}
	for i, a := range d.Algorithms {
		v.oneOf(
			fmt.Sprintf("auth.dpop.algorithms[%d]", i),
			a,
			"ES256",
			"ES384",
			"EdDSA",
			"RS256",
			"RS384",
			"RS512",
			"PS256",
			"PS384",
			"PS512",
		)
	}
	if d.MaxAge <= 0 || d.MaxAge > 10*time.Minute {
		v.add("auth.dpop.max_age", "must be within (0, 10m]")
	}
	if d.NonceRequired && (d.NonceTTL <= 0 || d.NonceTTL > time.Hour) {
		v.add("auth.dpop.nonce_ttl", "must be within (0, 1h]")
	}
}

func (c *Config) validateUpstreams(v *validator) {
	if len(c.Upstreams) == 0 {
		v.add("upstreams", "at least one upstream is required")
	}
	seen := map[string]bool{}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		f := fmt.Sprintf("upstreams[%d]", i)
		c.validateUpstreamID(v, f, u.ID, seen)
		v.oneOf(f+".transport", u.Transport, TransportStdio, TransportStreamable)
		validateTransport(v, f, u)
		validateUpstreamMetadata(v, f+".metadata", u.Metadata)
		for name := range u.Env {
			if strings.ContainsAny(name, "= \x00") || name == "" {
				v.add(f+".env", "invalid variable name %q", name)
			}
		}
		if u.Timeout <= 0 {
			v.add(f+".timeout", "must be positive")
		}
		if u.MaxConcurrency <= 0 {
			v.add(f+".max_concurrency", "must be positive")
		}
	}
}

func (c *Config) validateUpstreamID(v *validator, f, id string, seen map[string]bool) {
	if !upstreamIDs.MatchString(id) {
		v.add(f+".id", "must match %s, got %q", upstreamIDs.String(), id)
	}
	if c.Server.NamespaceSeparator != "" && strings.Contains(id, c.Server.NamespaceSeparator) {
		v.add(f+".id", "must not contain the namespace separator %q", c.Server.NamespaceSeparator)
	}
	if seen[id] {
		v.add(f+".id", "duplicate id %q", id)
	}
	seen[id] = true
}

func validateUpstreamMetadata(v *validator, f string, m UpstreamMetadata) {
	if m.Trust != "" {
		v.oneOf(f+".trust", m.Trust, TrustTrusted, TrustUntrusted)
	}
	if m.Classification != "" {
		v.oneOf(f+".classification", m.Classification, ClassPublic, ClassInternal, ClassConfidential, ClassRestricted)
	}
	if m.Impact != "" {
		v.oneOf(f+".impact", m.Impact, ImpactRead, ImpactWrite, ImpactDestructive)
	}
}

func (c *Config) validateIdempotency(v *validator) {
	if !c.Idempotency.Enabled {
		return
	}
	v.oneOf(
		"idempotency.mode",
		c.Idempotency.Mode,
		IdempotencyModeHeader,
		IdempotencyModeRequired,
		IdempotencyModeCanonicalHash,
	)
	if c.Idempotency.Mode != IdempotencyModeCanonicalHash {
		v.require("idempotency.header", c.Idempotency.Header)
	}
	if c.Idempotency.TTL <= 0 || c.Idempotency.TTL > 24*time.Hour {
		v.add("idempotency.ttl", "must be within (0, 24h]")
	}
	if c.Idempotency.MaxEntries < 100 {
		v.add("idempotency.max_entries", "must be at least 100")
	}
	v.globs("idempotency.tools", c.Idempotency.Tools)
}

func validateTransport(v *validator, f string, u *Upstream) {
	switch u.Transport {
	case TransportStdio:
		if len(u.Command) == 0 || u.Command[0] == "" {
			v.add(f+".command", "required for stdio transport")
		}
		if u.URL != "" {
			v.add(f+".url", "not allowed for stdio transport")
		}
		if u.Auth.Type != UpstreamAuthNone {
			v.add(f+".auth.type", "stdio upstreams take credentials through env, not auth")
		}
		validateSandbox(v, f+".sandbox", u.Sandbox)
	case TransportStreamable:
		v.url(f+".url", u.URL, "http", "https")
		if len(u.Command) > 0 {
			v.add(f+".command", "not allowed for streamable_http transport")
		}
		if u.Sandbox.Configured() {
			v.add(f+".sandbox", "only allowed for stdio transport")
		}
		validateUpstreamAuth(v, f+".auth", u.Auth)
	}
}

func validateSandbox(v *validator, f string, s StdioSandbox) {
	mode := s.Mode
	if mode == "" {
		mode = SandboxModeOff
	}
	v.oneOf(f+".mode", mode, SandboxModeOff, SandboxModeWarn, SandboxModeEnforce)
	backend := s.Backend
	if backend == "" {
		backend = SandboxBackendAuto
	}
	v.oneOf(f+".backend", backend, SandboxBackendAuto, SandboxBackendOS, SandboxBackendBwrap)
	netMode := s.Network
	if netMode == "" {
		netMode = SandboxNetworkInherit
	}
	v.oneOf(f+".network", netMode, SandboxNetworkInherit, SandboxNetworkNone)
	if strings.ContainsRune(s.WorkDir, '\x00') {
		v.add(f+".workdir", "must not contain NUL bytes")
	}
	validateSandboxPaths(v, f+".read_only_paths", s.ReadOnlyPaths)
	validateSandboxPaths(v, f+".read_write_paths", s.ReadWritePaths)
	validateSandboxLimits(v, f+".rlimits", s.RLimits)
}

func validateSandboxPaths(v *validator, f string, paths []string) {
	for i, p := range paths {
		if strings.TrimSpace(p) == "" || strings.ContainsRune(p, '\x00') || !strings.HasPrefix(p, "/") {
			v.add(fmt.Sprintf("%s[%d]", f, i), "must be a clean absolute path starting with /")
		}
	}
}

func validateSandboxLimits(v *validator, f string, l SandboxLimits) {
	if l.MaxMemoryMB < 0 {
		v.add(f+".max_memory_mb", "must be non-negative")
	}
	if l.MaxOpenFiles < 0 {
		v.add(f+".max_open_files", "must be non-negative")
	}
	if l.MaxProcesses < 0 {
		v.add(f+".max_processes", "must be non-negative")
	}
	if l.MaxFileSizeMB < 0 {
		v.add(f+".max_file_size_mb", "must be non-negative")
	}
}

func validateUpstreamAuth(v *validator, f string, a UpstreamAuth) {
	v.oneOf(
		f+".type",
		a.Type,
		UpstreamAuthNone,
		UpstreamAuthBearer,
		UpstreamAuthClientCredentials,
		UpstreamAuthTokenExchange,
	)
	switch a.Type {
	case UpstreamAuthBearer:
		v.require(f+".token", a.Token)
	case UpstreamAuthClientCredentials:
		v.url(f+".token_url", a.TokenURL, "http", "https")
		v.require(f+".client_id", a.ClientID)
		v.require(f+".client_secret", a.ClientSecret)
		if a.Resource != "" {
			v.url(f+".resource", a.Resource, "http", "https")
		}
	case UpstreamAuthTokenExchange:
		validateTokenExchange(v, f, a)
	}
}

func validateTokenExchange(v *validator, f string, a UpstreamAuth) {
	v.url(f+".token_url", a.TokenURL, "http", "https")
	v.require(f+".client_id", a.ClientID)
	v.require(f+".client_secret", a.ClientSecret)
	if a.Resource != "" {
		v.url(f+".resource", a.Resource, "http", "https")
	}
	te := a.TokenExchange
	allowInsecure := te != nil && te.AllowInsecure
	if strings.HasPrefix(a.TokenURL, "http://") && !allowInsecure && !Loopback(hostPort(a.TokenURL)) {
		v.add(
			f+".token_url",
			"plain http to a non-loopback token endpoint requires auth.token_exchange.allow_insecure: true",
		)
	}
	audience := ""
	if te != nil {
		audience = strings.TrimSpace(te.Audience)
		if te.MaxDelegationDepth < 0 {
			v.add(f+".token_exchange.max_delegation_depth", "must not be negative")
		}
		if te.CacheTTL < 0 || te.CacheTTL > time.Hour {
			v.add(f+".token_exchange.cache_ttl", "must be within [0, 1h]")
		}
		if te.Timeout < 0 || te.Timeout > 30*time.Second {
			v.add(f+".token_exchange.timeout", "must be within [0, 30s]")
		}
		for i, iss := range te.AllowedIssuers {
			v.url(fmt.Sprintf("%s.token_exchange.allowed_issuers[%d]", f, i), iss, "http", "https")
		}
	}
	if a.Resource == "" && audience == "" {
		v.add(f, "token_exchange requires resource or token_exchange.audience to scope the downstream token")
	}
}

func ValidatePolicy(p Policy) error {
	if p.Default == "" {
		p.Default = EffectDeny
	}
	v := &validator{}
	c := Config{Policy: p}
	c.validatePolicy(v)
	return errors.Join(v.errs...)
}

func (c *Config) validatePolicy(v *validator) {
	v.oneOf("policy.default", c.Policy.Default, EffectAllow, EffectDeny)
	validatePolicyRules(v, "policy.rules", c.Policy.Rules)
	for tenantID, tp := range c.Policy.Tenants {
		prefix := "policy.tenants." + tenantID
		if strings.TrimSpace(tenantID) == "" {
			v.add("policy.tenants", "tenant id must not be empty")
			continue
		}
		if tp.Default != "" {
			v.oneOf(prefix+".default", tp.Default, EffectAllow, EffectDeny)
		}
		validatePolicyRules(v, prefix+".rules", tp.Rules)
	}
}

func validatePolicyRules(v *validator, prefix string, rules []Rule) {
	names := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		f := fmt.Sprintf("%s[%d]", prefix, i)
		v.require(f+".name", r.Name)
		if names[r.Name] {
			v.add(f+".name", "duplicate rule name %q", r.Name)
		}
		names[r.Name] = true
		if len(r.Tools) == 0 && len(r.Prompts) == 0 && len(r.Resources) == 0 {
			v.add(f+".tools", "at least one tool, prompt or resource glob is required")
		}
		v.globs(f+".tools", r.Tools)
		v.globs(f+".prompts", r.Prompts)
		v.globs(f+".resources", r.Resources)
		v.globs(f+".subjects.subs", r.Subjects.Subs)
		v.globs(f+".subjects.client_ids", r.Subjects.ClientIDs)
		v.globs(f+".subjects.actors", r.Subjects.Actors)
		v.globs(f+".subjects.tenants", r.Subjects.Tenants)
		v.oneOf(f+".effect", r.Effect, EffectAllow, EffectDeny)
		if r.Mode != "" {
			v.oneOf(f+".mode", r.Mode, RuleModeEnforce, RuleModeShadow)
		}
		validateOnDeny(v, f, r)
	}
}

func validateOnDeny(v *validator, f string, r *Rule) {
	od := r.OnDeny
	hasStepUp := len(od.StepUpScopes) > 0 || len(od.ACRValues) > 0 || od.MaxAge != 0 ||
		od.RequireDPoP || od.RequireApproval
	if hasStepUp && r.Effect != EffectAllow {
		v.add(f+".on_deny", "step-up requirements only make sense on allow rules")
	}
	if od.MaxAge < 0 || od.MaxAge > 24*time.Hour {
		v.add(f+".on_deny.max_age", "must be within [0, 24h]")
	}
	if od.ApprovalTTL < 0 || od.ApprovalTTL > 24*time.Hour {
		v.add(f+".on_deny.approval_ttl", "must be within [0, 24h]")
	}
}

func (c *Config) validateApprovals(v *validator) {
	if !c.Approvals.Enabled {
		return
	}
	v.require("approvals.header", c.Approvals.Header)
	if len(c.Approvals.PubKeyFiles) == 0 && strings.TrimSpace(c.Approvals.PubKeyDir) == "" {
		v.add("approvals.pubkey_files", "at least one pubkey_files entry or pubkey_dir is required")
	}
	if c.Approvals.MaxTTL <= 0 || c.Approvals.MaxTTL > 24*time.Hour {
		v.add("approvals.max_ttl", "must be within (0, 24h]")
	}
	if c.Approvals.ClockSkew < 0 || c.Approvals.ClockSkew > 5*time.Minute {
		v.add("approvals.clock_skew", "must be within [0, 5m]")
	}
	if c.Approvals.SingleUse && c.Approvals.MaxEntries < 100 {
		v.add("approvals.max_entries", "must be at least 100")
	}
}

func (c *Config) validateBundle(v *validator) {
	if !c.Bundle.Enabled {
		return
	}
	v.require("bundle.manifest_file", c.Bundle.ManifestFile)
	if len(c.Bundle.PubKeyFiles) == 0 && strings.TrimSpace(c.Bundle.PubKeyDir) == "" {
		v.add("bundle.pubkey_files", "at least one pubkey_files entry or pubkey_dir is required")
	}
	if c.Bundle.RequirePins && strings.TrimSpace(c.Pinning.File) == "" {
		v.add("bundle.require_pins", "requires pinning.file to be set")
	}
}

func (c *Config) validateRateLimits(v *validator) {
	v.oneOf("rate_limits.store", c.RateLimits.Store, RateStoreMemory, RateStoreRedis)
	if c.RateLimits.Store == RateStoreRedis {
		r := c.RateLimits.Redis
		if len(r.Addrs) == 0 {
			v.add("rate_limits.redis.addrs", "required when rate_limits.store is redis")
		}
		v.oneOf("rate_limits.redis.on_error", r.OnError, RedisOnErrorLocal, RedisOnErrorDeny)
		if len(r.Addrs) > 1 && !hashTagged(r.KeyPrefix) {
			v.add("rate_limits.redis.key_prefix",
				"must contain a hash tag such as {tollkeeper}: when several addresses select Redis Cluster, "+
					"so all keys of one call share a slot")
		}
		if r.Timeout <= 0 || r.Timeout > 5*time.Second {
			v.add("rate_limits.redis.timeout", "must be within (0, 5s]")
		}
	}
	for i, r := range c.RateLimits.Rules {
		validateRateRule(v, fmt.Sprintf("rate_limits.rules[%d]", i), r)
	}
}

func validateRateRule(v *validator, f string, r RateRule) {
	v.require(f+".name", r.Name)
	v.globs(f+".tools", r.Tools)
	v.oneOf(
		f+".per",
		r.Per,
		PerGlobal,
		PerSubject,
		PerSubjectTool,
		PerClientID,
		PerTenant,
		PerTenantTool,
		PerUpstream,
		PerTool,
	)
	if count, per, err := ParseRate(r.Rate); err != nil {
		v.add(f+".rate", "%v", err)
	} else if interval := per / time.Duration(count); interval < time.Microsecond {
		v.add(f+".rate", "faster than one call per microsecond is not supported")
	} else if r.Burst > 0 && int64(r.Burst) > math.MaxInt64/2/int64(interval) {
		v.add(f+".burst", "too large for rate %s", r.Rate)
	}
	if r.Burst < 1 {
		v.add(f+".burst", "must be at least 1")
	}
	if r.MaxCost < 0 {
		v.add(f+".max_cost", "must be non-negative")
	}
	if r.MaxCost > 0 && r.Burst > 0 && r.MaxCost > r.Burst {
		v.add(f+".max_cost", "cannot exceed burst (%d)", r.Burst)
	}
}

func (c *Config) validateAudit(v *validator) {
	if !c.Audit.Enabled {
		return
	}
	c.validateAuditOTLP(v)
	c.validateAuditSIEM(v)
	if c.Audit.Postgres.DSN != "" && (c.Audit.Postgres.Timeout <= 0 || c.Audit.Postgres.Timeout > time.Minute) {
		v.add("audit.postgres.timeout", "must be within (0, 1m]")
	}
	if c.Audit.Postgres.DSN != "" && c.Audit.ChainID == "" {
		v.add("audit.chain_id", "required and unique per replica when audit.postgres.dsn is set, e.g. ${POD_NAME}")
	}
	if c.Audit.Postgres.DSN != "" && !c.Audit.Fsync {
		v.add(
			"audit.fsync",
			"must be true when audit.postgres.dsn is set, or a crash leaves Postgres ahead of the file",
		)
	}
	v.require("audit.path", c.Audit.Path)
	v.oneOf("audit.on_backpressure", c.Audit.OnBackpressure, BackpressureFailClosed, BackpressureFailOpen)
	v.oneOf("audit.record_args", c.Audit.RecordArgs, RecordArgsNone, RecordArgsHash, RecordArgsFull)
	if c.Audit.Buffer < 1 {
		v.add("audit.buffer", "must be at least 1")
	}
	if c.Audit.BatchSize < 1 {
		v.add("audit.batch_size", "must be at least 1")
	}
	if c.Audit.FlushInterval <= 0 {
		v.add("audit.flush_interval", "must be positive")
	}
	c.validateAuditCheckpoint(v)
	c.validateAnchor(v)
	c.validateAuditVerifyAndRetention(v)
}

func (c *Config) validateAuditVerifyAndRetention(v *validator) {
	av := c.Audit.Verify
	if av.Enabled && (av.Interval < 5*time.Second || av.Interval > 24*time.Hour) {
		v.add("audit.verify.interval", "must be within [5s, 24h]")
	}
	ar := c.Audit.Retention
	if ar.MaxAge < 0 {
		v.add("audit.retention.max_age", "must not be negative")
	}
	if ar.MaxArchives < 0 {
		v.add("audit.retention.max_archives", "must not be negative")
	}
	if (ar.MaxAge > 0 || ar.MaxArchives > 0) && strings.TrimSpace(ar.ArchiveDir) == "" {
		v.add("audit.retention.archive_dir", "required when max_age or max_archives is set")
	}
}

func (c *Config) validateAuditCheckpoint(v *validator) {
	ck := c.Audit.Checkpoint
	hasKMS := ck.KMS != nil && ck.KMS.Provider != ""
	if ck.SigningKeyFile != "" && hasKMS {
		v.add("audit.checkpoint", "signing_key_file and kms.provider are mutually exclusive")
	}
	if (ck.SigningKeyFile != "" || hasKMS) && ck.Every < 1 && ck.Interval <= 0 {
		v.add("audit.checkpoint", "set every or interval when a signing key is configured")
	}
	if ck.KMS != nil && (ck.KMS.Provider != "" || ck.KMS.KeyID != "") {
		validateAuditKMS(v, ck.KMS)
	}
}

func validateAuditKMS(v *validator, k *AuditKMS) {
	v.oneOf("audit.checkpoint.kms.provider", k.Provider, KMSProviderVault, KMSProviderAWS)
	v.require("audit.checkpoint.kms.key_id", k.KeyID)
	if k.Timeout < 0 || k.Timeout > time.Minute {
		v.add("audit.checkpoint.kms.timeout", "must be within [0, 1m]")
	}
	switch k.Provider {
	case KMSProviderVault:
		v.url("audit.checkpoint.kms.vault.address", k.Vault.Address, "http", "https")
		if strings.HasPrefix(k.Vault.Address, "http://") && !k.AllowInsecure && !Loopback(hostPort(k.Vault.Address)) {
			v.add(
				"audit.checkpoint.kms.vault.address",
				"plain http to a non-loopback Vault requires audit.checkpoint.kms.allow_insecure: true",
			)
		}
		v.require("audit.checkpoint.kms.vault.token", k.Vault.Token)
	case KMSProviderAWS:
		v.require("audit.checkpoint.kms.aws.region", k.AWS.Region)
		v.require("audit.checkpoint.kms.aws.access_key_id", k.AWS.AccessKeyID)
		v.require("audit.checkpoint.kms.aws.secret_access_key", k.AWS.SecretAccessKey)
		if k.AWS.Endpoint != "" {
			v.url("audit.checkpoint.kms.aws.endpoint", k.AWS.Endpoint, "http", "https")
			if strings.HasPrefix(k.AWS.Endpoint, "http://") && !k.AllowInsecure &&
				!Loopback(hostPort(k.AWS.Endpoint)) {
				v.add(
					"audit.checkpoint.kms.aws.endpoint",
					"plain http to a non-loopback endpoint requires audit.checkpoint.kms.allow_insecure: true",
				)
			}
		}
	}
}

func (c *Config) validateAnchor(v *validator) {
	a := c.Audit.Anchor
	if !a.Enabled {
		return
	}
	if u, err := url.Parse(a.RekorURL); err != nil || !safeLogURL(u) {
		v.add("audit.anchor.rekor_url", "must be an https URL (http only for loopback) without credentials, "+
			"query or fragment")
	}
	if u, err := url.Parse(a.TSAURL); a.TSAURL != "" && (err != nil || !safeLogURL(u)) {
		v.add("audit.anchor.tsa_url", "must be an https URL (http only for loopback) without credentials, "+
			"query or fragment")
	}
	if c.Audit.Checkpoint.SigningKeyFile == "" {
		v.add("audit.checkpoint.signing_key_file", "required when audit.anchor.enabled is true")
	}
	if len(a.TrustFiles) == 0 {
		v.add("audit.anchor.trust_files", "at least one Sigstore trusted_root.json or PEM log key is required")
	}
	if a.Every < 0 {
		v.add("audit.anchor.every", "must not be negative")
	}
	if a.Every == 0 && a.Interval <= 0 {
		v.add("audit.anchor", "set every or interval")
	}
	if a.Interval != 0 && a.Interval < time.Minute {
		v.add("audit.anchor.interval", "must be 0 or at least 1m to respect the public log's rate limits")
	}
	if a.Timeout < 20*time.Second || a.Timeout > 5*time.Minute {
		v.add("audit.anchor.timeout", "must be within [20s, 5m]; Rekor v2 answers once the entry is in a checkpoint")
	}
	if u, err := url.Parse(a.RekorURL); a.MinSpacing < time.Minute && (err != nil || u.Scheme != "http") {
		v.add("audit.anchor.min_spacing", "must be at least 1m except for a loopback test log")
	}
	if a.MaxBackoff < time.Second || a.MaxBackoff > time.Hour {
		v.add("audit.anchor.max_backoff", "must be within [1s, 1h]")
	}
}

func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func ParseRate(s string) (count int, per time.Duration, err error) {
	n, unit, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, 0, fmt.Errorf("%q: %w", s, ErrBadRate)
	}
	count, err = strconv.Atoi(n)
	if err != nil || count < 1 {
		return 0, 0, fmt.Errorf("%q: %w", s, ErrBadRate)
	}
	switch unit {
	case "s":
		per = time.Second
	case "m":
		per = time.Minute
	case "h":
		per = time.Hour
	default:
		return 0, 0, fmt.Errorf("%q: %w", s, ErrBadRate)
	}
	return count, per, nil
}

func safeLogURL(u *url.URL) bool {
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	default:
		return false
	}
}

func (c *Config) validateIntrospection(v *validator) {
	in := c.Auth.Introspection
	v.url("auth.introspection.url", in.URL, "http", "https")
	if strings.HasPrefix(in.URL, "http://") && !in.AllowInsecure {
		v.add("auth.introspection.url", "plain http requires auth.introspection.allow_insecure: true")
	}
	v.require("auth.introspection.client_id", in.ClientID)
	v.require("auth.introspection.client_secret", in.ClientSecret)
	if in.Issuer != "" {
		v.url("auth.introspection.issuer", in.Issuer, "http", "https")
	}
	if !slices.Contains(in.Audiences, c.Auth.Resource) {
		v.add("auth.introspection.audiences", "must include auth.resource %q (RFC 8707)", c.Auth.Resource)
	}
	if in.CacheTTL <= 0 || in.CacheTTL > time.Hour {
		v.add("auth.introspection.cache_ttl", "must be within (0, 1h]")
	}
	if in.Timeout <= 0 || in.Timeout > 30*time.Second {
		v.add("auth.introspection.timeout", "must be within (0, 30s]")
	}
}

func (c *Config) validateAuditOTLP(v *validator) {
	o := c.Audit.OTLP
	if o.Endpoint == "" {
		return
	}
	v.url("audit.otlp.endpoint", o.Endpoint, "http", "https")
	if strings.HasPrefix(o.Endpoint, "http://") && !o.AllowInsecure && !Loopback(hostPort(o.Endpoint)) {
		v.add("audit.otlp.endpoint", "plain http to a non-loopback collector requires audit.otlp.allow_insecure: true")
	}
	if o.Batch < 1 || o.Batch > 10000 {
		v.add("audit.otlp.batch", "must be within [1, 10000]")
	}
	if o.Queue < o.Batch || o.Queue > 1_000_000 {
		v.add("audit.otlp.queue", "must be within [batch, 1000000]")
	}
	if o.Interval <= 0 || o.Interval > time.Minute {
		v.add("audit.otlp.interval", "must be within (0, 1m]")
	}
	if o.Timeout <= 0 || o.Timeout > time.Minute {
		v.add("audit.otlp.timeout", "must be within (0, 1m]")
	}
}

func (c *Config) validateAuditSIEM(v *validator) {
	s := c.Audit.SIEM
	if s.Endpoint == "" {
		return
	}
	v.url("audit.siem.endpoint", s.Endpoint, "http", "https")
	if strings.HasPrefix(s.Endpoint, "http://") && !s.AllowInsecure && !Loopback(hostPort(s.Endpoint)) {
		v.add("audit.siem.endpoint", "plain http to a non-loopback SIEM requires audit.siem.allow_insecure: true")
	}
	v.oneOf("audit.siem.format", s.Format, SIEMFormatJSON, SIEMFormatSplunkHEC, SIEMFormatCEF)
	if s.Batch < 1 || s.Batch > 10000 {
		v.add("audit.siem.batch", "must be within [1, 10000]")
	}
	if s.Queue < s.Batch || s.Queue > 1_000_000 {
		v.add("audit.siem.queue", "must be within [batch, 1000000]")
	}
	if s.Interval <= 0 || s.Interval > time.Minute {
		v.add("audit.siem.interval", "must be within (0, 1m]")
	}
	if s.Timeout <= 0 || s.Timeout > time.Minute {
		v.add("audit.siem.timeout", "must be within (0, 1m]")
	}
}

func hostPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
