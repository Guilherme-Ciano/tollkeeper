package config

import (
	"time"
)

type Config struct {
	Server      Server      `koanf:"server"`
	Auth        Auth        `koanf:"auth"`
	Upstreams   []Upstream  `koanf:"upstreams"`
	Policy      Policy      `koanf:"policy"`
	RateLimits  RateLimits  `koanf:"rate_limits"`
	Idempotency Idempotency `koanf:"idempotency"`
	Approvals   Approvals   `koanf:"approvals"`
	Bundle      Bundle      `koanf:"bundle"`
	Audit       Audit       `koanf:"audit"`
	Telemetry   Telemetry   `koanf:"telemetry"`
	Pinning     Pinning     `koanf:"pinning"`
	Digest      string      `koanf:"-"`
}

const (
	IdempotencyModeHeader        = "header"
	IdempotencyModeRequired      = "required"
	IdempotencyModeCanonicalHash = "canonical_hash"
)

type Idempotency struct {
	Enabled    bool          `koanf:"enabled"`
	Mode       string        `koanf:"mode"`
	Header     string        `koanf:"header"`
	TTL        time.Duration `koanf:"ttl"`
	MaxEntries int           `koanf:"max_entries"`
	Tools      []string      `koanf:"tools"`
}

type Approvals struct {
	Enabled     bool          `koanf:"enabled"`
	Issuer      string        `koanf:"issuer"`
	Header      string        `koanf:"header"`
	PubKeyFiles []string      `koanf:"pubkey_files"`
	PubKeyDir   string        `koanf:"pubkey_dir"`
	MaxTTL      time.Duration `koanf:"max_ttl"`
	ClockSkew   time.Duration `koanf:"clock_skew"`
	SingleUse   bool          `koanf:"single_use"`
	MaxEntries  int           `koanf:"max_entries"`
}

type Bundle struct {
	Enabled      bool     `koanf:"enabled"`
	ManifestFile string   `koanf:"manifest_file"`
	PubKeyFiles  []string `koanf:"pubkey_files"`
	PubKeyDir    string   `koanf:"pubkey_dir"`
	RequirePins  bool     `koanf:"require_pins"`
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
	ReportToken    string        `koanf:"report_token"`
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
	DisableFastPath    bool          `koanf:"disable_fast_path"`
	RequestStateKey    string        `koanf:"request_state_key_file"`
	RequestStateTTL    time.Duration `koanf:"request_state_ttl"`
	TasksEnabled       bool          `koanf:"tasks_enabled"`
	TaskTTL            time.Duration `koanf:"task_ttl"`
	StampProvenance    bool          `koanf:"stamp_provenance"`
	Pprof              bool          `koanf:"pprof"`
}

const (
	DPoPModeOff      = "off"
	DPoPModeOptional = "optional"
	DPoPModeRequired = "required"

	AuthProviderGeneric  = ""
	AuthProviderEntra    = "entra"
	AuthProviderOkta     = "okta"
	AuthProviderKeycloak = "keycloak"
	AuthProviderAuth0    = "auth0"
)

type Auth struct {
	Mode                 string        `koanf:"mode"`
	Provider             string        `koanf:"provider"`
	Resource             string        `koanf:"resource"`
	AuthorizationServers []string      `koanf:"authorization_servers"`
	ScopesSupported      []string      `koanf:"scopes_supported"`
	RequiredScopes       []string      `koanf:"required_scopes"`
	Claims               AuthClaims    `koanf:"claims"`
	DPoP                 DPoP          `koanf:"dpop"`
	JWT                  JWT           `koanf:"jwt"`
	Introspection        Introspection `koanf:"introspection"`
}

type AuthClaims struct {
	Tenant   string `koanf:"tenant"`
	Groups   string `koanf:"groups"`
	Roles    string `koanf:"roles"`
	ClientID string `koanf:"client_id"`
	Scope    string `koanf:"scope"`
}

type DPoP struct {
	Mode          string        `koanf:"mode"`
	Algorithms    []string      `koanf:"algorithms"`
	MaxAge        time.Duration `koanf:"max_age"`
	NonceRequired bool          `koanf:"nonce_required"`
	NonceTTL      time.Duration `koanf:"nonce_ttl"`
}

type Introspection struct {
	URL           string        `koanf:"url"`
	ClientID      string        `koanf:"client_id"`
	ClientSecret  string        `koanf:"client_secret"`
	Issuer        string        `koanf:"issuer"`
	Audiences     []string      `koanf:"audiences"`
	CacheTTL      time.Duration `koanf:"cache_ttl"`
	Timeout       time.Duration `koanf:"timeout"`
	AllowInsecure bool          `koanf:"allow_insecure"`
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

type UpstreamMetadata struct {
	Trust          string `koanf:"trust"`
	Classification string `koanf:"classification"`
	Egress         bool   `koanf:"egress"`
	Impact         string `koanf:"impact"`
}

type Upstream struct {
	ID              string            `koanf:"id"`
	Transport       string            `koanf:"transport"`
	Command         []string          `koanf:"command"`
	Env             map[string]string `koanf:"env"`
	EnvPassthrough  []string          `koanf:"env_passthrough"`
	Sandbox         StdioSandbox      `koanf:"sandbox"`
	URL             string            `koanf:"url"`
	BlockPrivateIPs bool              `koanf:"block_private_ips"`
	Metadata        UpstreamMetadata  `koanf:"metadata"`
	Timeout         time.Duration     `koanf:"timeout"`
	MaxConcurrency  int               `koanf:"max_concurrency"`
	Breaker         Breaker           `koanf:"breaker"`
	Auth            UpstreamAuth      `koanf:"auth"`
	RestartBackoff  time.Duration     `koanf:"restart_backoff"`
	RestartMax      time.Duration     `koanf:"restart_max"`
}

type StdioSandbox struct {
	Mode           string        `koanf:"mode"`
	Backend        string        `koanf:"backend"`
	WorkDir        string        `koanf:"workdir"`
	Network        string        `koanf:"network"`
	ReadOnlyPaths  []string      `koanf:"read_only_paths"`
	ReadWritePaths []string      `koanf:"read_write_paths"`
	RLimits        SandboxLimits `koanf:"rlimits"`
}

type SandboxLimits struct {
	MaxMemoryMB   int64 `koanf:"max_memory_mb"`
	MaxOpenFiles  int64 `koanf:"max_open_files"`
	MaxProcesses  int64 `koanf:"max_processes"`
	MaxFileSizeMB int64 `koanf:"max_file_size_mb"`
}

func (l SandboxLimits) Any() bool {
	return l.MaxMemoryMB > 0 || l.MaxOpenFiles > 0 || l.MaxProcesses > 0 || l.MaxFileSizeMB > 0
}

func (s StdioSandbox) Configured() bool {
	return (s.Mode != "" && s.Mode != SandboxModeOff) ||
		(s.Backend != "" && s.Backend != SandboxBackendAuto) ||
		s.WorkDir != "" ||
		(s.Network != "" && s.Network != SandboxNetworkInherit) ||
		len(s.ReadOnlyPaths) > 0 ||
		len(s.ReadWritePaths) > 0 ||
		s.RLimits.Any()
}

type Breaker struct {
	Failures uint32        `koanf:"failures"`
	OpenFor  time.Duration `koanf:"open_for"`
}

type UpstreamAuth struct {
	Type          string         `koanf:"type"`
	Token         string         `koanf:"token"`
	TokenURL      string         `koanf:"token_url"`
	ClientID      string         `koanf:"client_id"`
	ClientSecret  string         `koanf:"client_secret"`
	Scopes        []string       `koanf:"scopes"`
	Resource      string         `koanf:"resource"`
	TokenExchange *TokenExchange `koanf:"token_exchange"`
}

type TokenExchange struct {
	Audience              string        `koanf:"audience"`
	SubjectTokenType      string        `koanf:"subject_token_type"`
	RequestedTokenType    string        `koanf:"requested_token_type"`
	ActorToken            string        `koanf:"actor_token"`
	ActorTokenType        string        `koanf:"actor_token_type"`
	IntersectCallerScopes bool          `koanf:"intersect_caller_scopes"`
	MaxDelegationDepth    int           `koanf:"max_delegation_depth"`
	AllowedIssuers        []string      `koanf:"allowed_issuers"`
	DiscoveryScopes       []string      `koanf:"discovery_scopes"`
	CacheTTL              time.Duration `koanf:"cache_ttl"`
	Timeout               time.Duration `koanf:"timeout"`
	AllowInsecure         bool          `koanf:"allow_insecure"`
}

type Policy struct {
	Default string                  `koanf:"default"`
	Rules   []Rule                  `koanf:"rules"`
	Tenants map[string]TenantPolicy `koanf:"tenants"`
}

type TenantPolicy struct {
	Default string `koanf:"default"`
	Rules   []Rule `koanf:"rules"`
}

type Rule struct {
	Name      string   `koanf:"name"`
	Subjects  Subjects `koanf:"subjects"`
	Tools     []string `koanf:"tools"`
	Prompts   []string `koanf:"prompts"`
	Resources []string `koanf:"resources"`
	When      string   `koanf:"when"`
	Mode      string   `koanf:"mode"`
	Effect    string   `koanf:"effect"`
	OnDeny    OnDeny   `koanf:"on_deny"`
}

type Subjects struct {
	Subs      []string `koanf:"subs"`
	ClientIDs []string `koanf:"client_ids"`
	Actors    []string `koanf:"actors"`
	Tenants   []string `koanf:"tenants"`
	RolesAny  []string `koanf:"roles_any"`
	GroupsAny []string `koanf:"groups_any"`
	ScopesAny []string `koanf:"scopes_any"`
	ScopesAll []string `koanf:"scopes_all"`
}

type OnDeny struct {
	StepUpScopes    []string      `koanf:"step_up_scopes"`
	ACRValues       []string      `koanf:"acr_values"`
	MaxAge          time.Duration `koanf:"max_age"`
	RequireDPoP     bool          `koanf:"require_dpop"`
	RequireApproval bool          `koanf:"require_approval"`
	ApprovalTTL     time.Duration `koanf:"approval_ttl"`
	ApprovalReason  string        `koanf:"approval_reason"`
}

const (
	RuleModeEnforce = "enforce"
	RuleModeShadow  = "shadow"
)

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
	Name     string   `koanf:"name"`
	Tools    []string `koanf:"tools"`
	Per      string   `koanf:"per"`
	Rate     string   `koanf:"rate"`
	Burst    int      `koanf:"burst"`
	CostExpr string   `koanf:"cost_expr"`
	MaxCost  int      `koanf:"max_cost"`
}

type Audit struct {
	Enabled        bool           `koanf:"enabled"`
	Path           string         `koanf:"path"`
	ChainID        string         `koanf:"chain_id"`
	OnBackpressure string         `koanf:"on_backpressure"`
	Buffer         int            `koanf:"buffer"`
	BatchSize      int            `koanf:"batch_size"`
	FlushInterval  time.Duration  `koanf:"flush_interval"`
	Fsync          bool           `koanf:"fsync"`
	RecordArgs     string         `koanf:"record_args"`
	Checkpoint     Checkpoint     `koanf:"checkpoint"`
	Postgres       AuditPostgres  `koanf:"postgres"`
	Anchor         AuditAnchor    `koanf:"anchor"`
	OTLP           AuditOTLP      `koanf:"otlp"`
	SIEM           AuditSIEM      `koanf:"siem"`
	Verify         AuditVerify    `koanf:"verify"`
	Retention      AuditRetention `koanf:"retention"`
}

const (
	SIEMFormatJSON      = "json"
	SIEMFormatSplunkHEC = "splunk_hec"
	SIEMFormatCEF       = "cef"
)

type AuditSIEM struct {
	Endpoint        string            `koanf:"endpoint"`
	Format          string            `koanf:"format"`
	Headers         map[string]string `koanf:"headers"`
	Index           string            `koanf:"index"`
	Sourcetype      string            `koanf:"sourcetype"`
	Batch           int               `koanf:"batch"`
	Queue           int               `koanf:"queue"`
	Interval        time.Duration     `koanf:"interval"`
	Timeout         time.Duration     `koanf:"timeout"`
	BlockPrivateIPs bool              `koanf:"block_private_ips"`
	AllowInsecure   bool              `koanf:"allow_insecure"`
}

type AuditVerify struct {
	Enabled     bool          `koanf:"enabled"`
	Interval    time.Duration `koanf:"interval"`
	MaxUnsigned uint64        `koanf:"max_unsigned"`
	PubKeyDir   string        `koanf:"pubkey_dir"`
}

type AuditRetention struct {
	ArchiveDir  string        `koanf:"archive_dir"`
	MaxAge      time.Duration `koanf:"max_age"`
	MaxArchives int           `koanf:"max_archives"`
}

type AuditOTLP struct {
	Endpoint      string            `koanf:"endpoint"`
	Headers       map[string]string `koanf:"headers"`
	Batch         int               `koanf:"batch"`
	Queue         int               `koanf:"queue"`
	Interval      time.Duration     `koanf:"interval"`
	Timeout       time.Duration     `koanf:"timeout"`
	AllowInsecure bool              `koanf:"allow_insecure"`
}

type AuditAnchor struct {
	Enabled    bool          `koanf:"enabled"`
	RekorURL   string        `koanf:"rekor_url"`
	TrustFiles []string      `koanf:"trust_files"`
	TSAURL     string        `koanf:"tsa_url"`
	Origin     string        `koanf:"origin"`
	Every      int           `koanf:"every"`
	Interval   time.Duration `koanf:"interval"`
	Timeout    time.Duration `koanf:"timeout"`
	MaxBackoff time.Duration `koanf:"max_backoff"`
	MinSpacing time.Duration `koanf:"min_spacing"`
	Required   bool          `koanf:"required"`
}

type AuditPostgres struct {
	DSN     string        `koanf:"dsn"`
	Timeout time.Duration `koanf:"timeout"`
	Migrate bool          `koanf:"migrate"`
}

const (
	KMSProviderVault = "vault"
	KMSProviderAWS   = "aws"
)

type Checkpoint struct {
	Every          int           `koanf:"every"`
	Interval       time.Duration `koanf:"interval"`
	SigningKeyFile string        `koanf:"signing_key_file"`
	KMS            *AuditKMS     `koanf:"kms"`
}

type AuditKMS struct {
	Provider        string        `koanf:"provider"`
	KeyID           string        `koanf:"key_id"`
	Timeout         time.Duration `koanf:"timeout"`
	BlockPrivateIPs bool          `koanf:"block_private_ips"`
	AllowInsecure   bool          `koanf:"allow_insecure"`
	Vault           AuditKMSVault `koanf:"vault"`
	AWS             AuditKMSAWS   `koanf:"aws"`
}

type AuditKMSVault struct {
	Address   string `koanf:"address"`
	Mount     string `koanf:"mount"`
	Token     string `koanf:"token"`
	Namespace string `koanf:"namespace"`
}

type AuditKMSAWS struct {
	Region          string `koanf:"region"`
	Endpoint        string `koanf:"endpoint"`
	AccessKeyID     string `koanf:"access_key_id"`
	SecretAccessKey string `koanf:"secret_access_key"`
	SessionToken    string `koanf:"session_token"`
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
			RequestStateTTL:    10 * time.Minute,
			TaskTTL:            time.Hour,
		},
		Auth: Auth{
			Mode: AuthModeJWT,
			DPoP: DPoP{
				Mode:       DPoPModeOff,
				Algorithms: []string{"ES256", "ES384", "EdDSA", "RS256", "PS256"},
				MaxAge:     60 * time.Second,
				NonceTTL:   5 * time.Minute,
			},
			JWT: JWT{
				Algorithms:   []string{"RS256", "ES256", "EdDSA"},
				ClockSkew:    30 * time.Second,
				JWKSRefresh:  10 * time.Minute,
				JWKSMinRetry: 5 * time.Second,
			},
			Introspection: Introspection{CacheTTL: time.Minute, Timeout: 5 * time.Second},
		},
		Policy: Policy{Default: EffectDeny},
		RateLimits: RateLimits{
			Store: RateStoreMemory,
			Redis: RedisLimits{KeyPrefix: "tollkeeper:rl:", Timeout: 50 * time.Millisecond, OnError: RedisOnErrorLocal},
		},
		Approvals: Approvals{
			Header:     "X-Tollkeeper-Approval",
			MaxTTL:     15 * time.Minute,
			ClockSkew:  30 * time.Second,
			SingleUse:  true,
			MaxEntries: 10000,
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
			Postgres:       AuditPostgres{Timeout: 5 * time.Second},
			OTLP:           AuditOTLP{Batch: 512, Queue: 10000, Interval: 2 * time.Second, Timeout: 5 * time.Second},
			SIEM: AuditSIEM{
				Format: SIEMFormatJSON, Batch: 256, Queue: 10000, Interval: 2 * time.Second, Timeout: 5 * time.Second,
			},
			Anchor: AuditAnchor{
				Interval: 15 * time.Minute, Timeout: time.Minute, MaxBackoff: 10 * time.Minute, MinSpacing: time.Minute,
			},
			Verify: AuditVerify{Interval: 5 * time.Minute},
		},
		Pinning: Pinning{Mode: PinModeWarn, ReloadInterval: 5 * time.Second},
		Idempotency: Idempotency{
			Mode:       IdempotencyModeHeader,
			Header:     "Idempotency-Key",
			TTL:        5 * time.Minute,
			MaxEntries: 100000,
			Tools:      []string{"*"},
		},
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
	if u.Sandbox.Mode == "" {
		u.Sandbox.Mode = SandboxModeOff
	}
	if u.Sandbox.Backend == "" {
		u.Sandbox.Backend = SandboxBackendAuto
	}
	if u.Sandbox.Network == "" {
		u.Sandbox.Network = SandboxNetworkInherit
	}
	return u
}

const (
	SandboxModeOff     = "off"
	SandboxModeWarn    = "warn"
	SandboxModeEnforce = "enforce"

	SandboxBackendAuto  = "auto"
	SandboxBackendOS    = "os"
	SandboxBackendBwrap = "bwrap"

	SandboxNetworkInherit = "inherit"
	SandboxNetworkNone    = "none"

	AuthModeJWT           = "jwt"
	AuthModeIntrospection = "introspection"
	AuthModeNone          = "none"

	TransportStdio      = "stdio"
	TransportStreamable = "streamable_http"

	UpstreamAuthNone              = "none"
	UpstreamAuthBearer            = "bearer"
	UpstreamAuthClientCredentials = "client_credentials"
	UpstreamAuthTokenExchange     = "token_exchange"

	EffectAllow = "allow"
	EffectDeny  = "deny"

	PerGlobal      = "global"
	PerSubject     = "subject"
	PerSubjectTool = "subject_tool"
	PerClientID    = "client_id"
	PerTenant      = "tenant"
	PerTenantTool  = "tenant_tool"
	PerUpstream    = "upstream"
	PerTool        = "tool"

	BackpressureFailClosed = "fail_closed"
	BackpressureFailOpen   = "fail_open"

	RecordArgsNone = "none"
	RecordArgsHash = "hash"
	RecordArgsFull = "full"

	TrustTrusted   = "trusted"
	TrustUntrusted = "untrusted"

	ClassPublic       = "public"
	ClassInternal     = "internal"
	ClassConfidential = "confidential"
	ClassRestricted   = "restricted"

	ImpactRead        = "read"
	ImpactWrite       = "write"
	ImpactDestructive = "destructive"
)
