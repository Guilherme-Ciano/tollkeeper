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
	c.validateAudit(v)
	v.oneOf("telemetry.log_format", c.Telemetry.LogFormat, "json", "text")
	v.oneOf("telemetry.log_level", c.Telemetry.LogLevel, "debug", "info", "warn", "error")
	if c.Telemetry.SampleRatio < 0 || c.Telemetry.SampleRatio > 1 {
		v.add("telemetry.sample_ratio", "must be within [0,1]")
	}
	return errors.Join(v.errs...)
}

func (c *Config) validateServer(v *validator) {
	v.require("server.listen", c.Server.Listen)
	v.require("server.admin_listen", c.Server.AdminListen)
	if c.Server.Pprof && !loopback(c.Server.AdminListen) {
		v.add("server.pprof", "only allowed when server.admin_listen is a loopback address")
	}
	if c.Server.Listen != "" && c.Server.Listen == c.Server.AdminListen {
		v.add("server.admin_listen", "must differ from server.listen")
	}
	v.url("server.public_url", c.Server.PublicURL, "http", "https")
	if c.Server.MaxBodyBytes <= 0 || c.Server.MaxBodyBytes > 64<<20 {
		v.add("server.max_body_bytes", "must be within (0, 64MiB]")
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
	v.oneOf("auth.mode", c.Auth.Mode, AuthModeJWT, AuthModeNone)
	if c.Auth.Mode != AuthModeJWT {
		return
	}
	v.url("auth.resource", c.Auth.Resource, "http", "https")
	if len(c.Auth.AuthorizationServers) == 0 {
		v.add("auth.authorization_servers", "at least one authorization server is required")
	}
	for i, as := range c.Auth.AuthorizationServers {
		v.url(fmt.Sprintf("auth.authorization_servers[%d]", i), as, "http", "https")
	}
	v.url("auth.jwt.issuer", c.Auth.JWT.Issuer, "http", "https")
	v.url("auth.jwt.jwks_url", c.Auth.JWT.JWKSURL, "http", "https")
	if strings.HasPrefix(c.Auth.JWT.JWKSURL, "http://") && !c.Auth.JWT.AllowInsecure {
		v.add("auth.jwt.jwks_url", "plain http requires auth.jwt.allow_insecure_jwks: true")
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
	case TransportStreamable:
		v.url(f+".url", u.URL, "http", "https")
		if len(u.Command) > 0 {
			v.add(f+".command", "not allowed for streamable_http transport")
		}
		validateUpstreamAuth(v, f+".auth", u.Auth)
	}
}

func validateUpstreamAuth(v *validator, f string, a UpstreamAuth) {
	v.oneOf(f+".type", a.Type, UpstreamAuthNone, UpstreamAuthBearer, UpstreamAuthClientCredentials)
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
	}
}

func (c *Config) validatePolicy(v *validator) {
	v.oneOf("policy.default", c.Policy.Default, EffectAllow, EffectDeny)
	names := map[string]bool{}
	for i := range c.Policy.Rules {
		r := &c.Policy.Rules[i]
		f := fmt.Sprintf("policy.rules[%d]", i)
		v.require(f+".name", r.Name)
		if names[r.Name] {
			v.add(f+".name", "duplicate rule name %q", r.Name)
		}
		names[r.Name] = true
		if len(r.Tools) == 0 {
			v.add(f+".tools", "at least one tool glob is required")
		}
		v.globs(f+".tools", r.Tools)
		v.globs(f+".subjects.subs", r.Subjects.Subs)
		v.globs(f+".subjects.client_ids", r.Subjects.ClientIDs)
		v.oneOf(f+".effect", r.Effect, EffectAllow, EffectDeny)
		if len(r.OnDeny.StepUpScopes) > 0 && r.Effect != EffectAllow {
			v.add(f+".on_deny", "step_up_scopes only make sense on allow rules")
		}
	}
}

func (c *Config) validateRateLimits(v *validator) {
	for i, r := range c.RateLimits.Rules {
		f := fmt.Sprintf("rate_limits.rules[%d]", i)
		v.require(f+".name", r.Name)
		v.globs(f+".tools", r.Tools)
		v.oneOf(f+".per", r.Per, PerGlobal, PerSubject, PerSubjectTool, PerClientID, PerUpstream, PerTool)
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
	}
}

func (c *Config) validateAudit(v *validator) {
	if !c.Audit.Enabled {
		return
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
	if c.Audit.Checkpoint.SigningKeyFile != "" && c.Audit.Checkpoint.Every < 1 && c.Audit.Checkpoint.Interval <= 0 {
		v.add("audit.checkpoint", "set every or interval when a signing key is configured")
	}
}

func loopback(addr string) bool {
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
