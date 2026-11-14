package config

import (
	"time"
)

type Config struct {
	Server     Server     `koanf:"server"`
	Auth       Auth       `koanf:"auth"`
	Upstreams  []Upstream `koanf:"upstreams"`
	Policy     Policy     `koanf:"policy"`
	RateLimits RateLimits `koanf:"rate_limits"`
	Audit      Audit      `koanf:"audit"`
	Telemetry  Telemetry  `koanf:"telemetry"`
	Pinning    Pinning    `koanf:"pinning"`
	Digest     string     `koanf:"-"`
}

const (
	PinModeOff     = "off"
	PinModeWarn    = "warn"
	PinModeEnforce = "enforce"
)

type Pinning struct {
	Mode           string        `koanf:"mode"`
	File           string        `koanf:"file"`
	ReloadInterval time.Duration `koanf:"reload_interval"`
}

type Server struct {
	Listen             string        `koanf:"listen"`
	AdminListen        string        `koanf:"admin_listen"`
	PublicURL          string        `koanf:"public_url"`
	MaxBodyBytes       int64         `koanf:"max_body_bytes"`
	NamespaceSeparator string        `koanf:"namespace_separator"`
	NamespaceTools     bool          `koanf:"namespace_tools"`
	ResyncDebounce     time.Duration `koanf:"resync_debounce"`
	ShutdownDrainDelay time.Duration `koanf:"shutdown_drain_delay"`
	ShutdownTimeout    time.Duration `koanf:"shutdown_timeout"`
	AllowLocalhostHost bool          `koanf:"allow_localhost_host"`
	Pprof              bool          `koanf:"pprof"`
}

type Auth struct {
	Mode                 string   `koanf:"mode"`
	Resource             string   `koanf:"resource"`
	AuthorizationServers []string `koanf:"authorization_servers"`
	ScopesSupported      []string `koanf:"scopes_supported"`
	RequiredScopes       []string `koanf:"required_scopes"`
	JWT                  JWT      `koanf:"jwt"`
}

type JWT struct {
	Issuer        string        `koanf:"issuer"`
	JWKSURL       string        `koanf:"jwks_url"`
	Audiences     []string      `koanf:"audiences"`
	Algorithms    []string      `koanf:"algorithms"`
	ClockSkew     time.Duration `koanf:"clock_skew"`
	JWKSRefresh   time.Duration `koanf:"jwks_refresh"`
	JWKSMinRetry  time.Duration `koanf:"jwks_min_retry"`
	AllowInsecure bool          `koanf:"allow_insecure_jwks"`
	Types         []string      `koanf:"types"`
}

type Upstream struct {
	ID             string            `koanf:"id"`
	Transport      string            `koanf:"transport"`
	Command        []string          `koanf:"command"`
	Env            map[string]string `koanf:"env"`
	EnvPassthrough []string          `koanf:"env_passthrough"`
	URL            string            `koanf:"url"`
	Timeout        time.Duration     `koanf:"timeout"`
	MaxConcurrency int               `koanf:"max_concurrency"`
	Breaker        Breaker           `koanf:"breaker"`
	Auth           UpstreamAuth      `koanf:"auth"`
	RestartBackoff time.Duration     `koanf:"restart_backoff"`
	RestartMax     time.Duration     `koanf:"restart_max"`
}

type Breaker struct {
	Failures uint32        `koanf:"failures"`
	OpenFor  time.Duration `koanf:"open_for"`
}

type UpstreamAuth struct {
	Type         string   `koanf:"type"`
	Token        string   `koanf:"token"`
	TokenURL     string   `koanf:"token_url"`
	ClientID     string   `koanf:"client_id"`
	ClientSecret string   `koanf:"client_secret"`
	Scopes       []string `koanf:"scopes"`
	Resource     string   `koanf:"resource"`
}

type Policy struct {
	Default string `koanf:"default"`
	Rules   []Rule `koanf:"rules"`
}

type Rule struct {
	Name     string   `koanf:"name"`
	Subjects Subjects `koanf:"subjects"`
	Tools    []string `koanf:"tools"`
	When     string   `koanf:"when"`
	Effect   string   `koanf:"effect"`
	OnDeny   OnDeny   `koanf:"on_deny"`
}

type Subjects struct {
	Subs      []string `koanf:"subs"`
	ClientIDs []string `koanf:"client_ids"`
	ScopesAny []string `koanf:"scopes_any"`
	ScopesAll []string `koanf:"scopes_all"`
}

type OnDeny struct {
	StepUpScopes []string `koanf:"step_up_scopes"`
}

const (
	RateStoreMemory = "memory"
	RateStoreRedis  = "redis"

	RedisOnErrorLocal = "local"
	RedisOnErrorDeny  = "deny"
)

type RateLimits struct {
	Store string      `koanf:"store"`
	Redis RedisLimits `koanf:"redis"`
	Rules []RateRule  `koanf:"rules"`
}

type RedisLimits struct {
	Addrs     []string      `koanf:"addrs"`
	Username  string        `koanf:"username"`
	Password  string        `koanf:"password"`
	DB        int           `koanf:"db"`
	TLS       bool          `koanf:"tls"`
	KeyPrefix string        `koanf:"key_prefix"`
	Timeout   time.Duration `koanf:"timeout"`
	OnError   string        `koanf:"on_error"`
}

type RateRule struct {
	Name  string   `koanf:"name"`
	Tools []string `koanf:"tools"`
	Per   string   `koanf:"per"`
	Rate  string   `koanf:"rate"`
	Burst int      `koanf:"burst"`
}

type Audit struct {
	Enabled        bool          `koanf:"enabled"`
	Path           string        `koanf:"path"`
	ChainID        string        `koanf:"chain_id"`
	OnBackpressure string        `koanf:"on_backpressure"`
	Buffer         int           `koanf:"buffer"`
	BatchSize      int           `koanf:"batch_size"`
	FlushInterval  time.Duration `koanf:"flush_interval"`
	Fsync          bool          `koanf:"fsync"`
	RecordArgs     string        `koanf:"record_args"`
	Checkpoint     Checkpoint    `koanf:"checkpoint"`
}

type Checkpoint struct {
	Every          int           `koanf:"every"`
	Interval       time.Duration `koanf:"interval"`
	SigningKeyFile string        `koanf:"signing_key_file"`
}

type Telemetry struct {
	ServiceName  string  `koanf:"service_name"`
	OTLPEndpoint string  `koanf:"otlp_endpoint"`
	SampleRatio  float64 `koanf:"sample_ratio"`
	LogLevel     string  `koanf:"log_level"`
	LogFormat    string  `koanf:"log_format"`
}

func Defaults() Config {
	return Config{
		Server: Server{
			Listen:             ":8080",
			AdminListen:        "127.0.0.1:9090",
			MaxBodyBytes:       1 << 20,
			NamespaceSeparator: "__",
			NamespaceTools:     true,
			ResyncDebounce:     250 * time.Millisecond,
			ShutdownDrainDelay: 0,
			ShutdownTimeout:    20 * time.Second,
		},
		Auth: Auth{
			Mode: AuthModeJWT,
			JWT: JWT{
				Algorithms:   []string{"RS256", "ES256", "EdDSA"},
				ClockSkew:    30 * time.Second,
				JWKSRefresh:  10 * time.Minute,
				JWKSMinRetry: 5 * time.Second,
			},
		},
		Policy: Policy{Default: EffectDeny},
		RateLimits: RateLimits{
			Store: RateStoreMemory,
			Redis: RedisLimits{KeyPrefix: "tollkeeper:rl:", Timeout: 50 * time.Millisecond, OnError: RedisOnErrorLocal},
		},
		Audit: Audit{
			Enabled:        true,
			Path:           "audit.jsonl",
			OnBackpressure: BackpressureFailClosed,
			Buffer:         65536,
			BatchSize:      512,
			FlushInterval:  50 * time.Millisecond,
			Fsync:          true,
			RecordArgs:     RecordArgsHash,
			Checkpoint:     Checkpoint{Every: 1000, Interval: 30 * time.Second},
		},
		Pinning: Pinning{Mode: PinModeWarn, ReloadInterval: 5 * time.Second},
		Telemetry: Telemetry{
			ServiceName: "tollkeeper",
			SampleRatio: 1.0,
			LogLevel:    "info",
			LogFormat:   "json",
		},
	}
}

func defaultUpstream(u Upstream) Upstream {
	if u.Timeout == 0 {
		u.Timeout = 15 * time.Second
	}
	if u.MaxConcurrency == 0 {
		u.MaxConcurrency = 64
	}
	if u.Breaker.Failures == 0 {
		u.Breaker.Failures = 5
	}
	if u.Breaker.OpenFor == 0 {
		u.Breaker.OpenFor = 30 * time.Second
	}
	if u.RestartBackoff == 0 {
		u.RestartBackoff = 500 * time.Millisecond
	}
	if u.RestartMax == 0 {
		u.RestartMax = 30 * time.Second
	}
	if u.Auth.Type == "" {
		u.Auth.Type = UpstreamAuthNone
	}
	return u
}

const (
	AuthModeJWT  = "jwt"
	AuthModeNone = "none"

	TransportStdio      = "stdio"
	TransportStreamable = "streamable_http"

	UpstreamAuthNone              = "none"
	UpstreamAuthBearer            = "bearer"
	UpstreamAuthClientCredentials = "client_credentials"

	EffectAllow = "allow"
	EffectDeny  = "deny"

	PerGlobal      = "global"
	PerSubject     = "subject"
	PerSubjectTool = "subject_tool"
	PerClientID    = "client_id"
	PerUpstream    = "upstream"
	PerTool        = "tool"

	BackpressureFailClosed = "fail_closed"
	BackpressureFailOpen   = "fail_open"

	RecordArgsNone = "none"
	RecordArgsHash = "hash"
	RecordArgsFull = "full"
)
