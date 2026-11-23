package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
)

const (
	initProfileLocal    = "local"
	initProfileTeam     = "team"
	initScopeTools      = "mcp:tools"
	initScopeWrite      = "mcp:write"
	initEffectAllow     = "allow"
	initEffectDeny      = "deny"
	initRuleDefault     = "default"
	initRuleReadOnly    = "read-only-tools"
	initRuleWriteStepUp = "writes-need-step-up"
	initToolWriteFile   = "write_file"
	initArgPath         = "path"
)

var ErrInit = errors.New("init failed")

type initOpts struct {
	dir         string
	profile     string
	upstreamID  string
	upstreamURL string
	upstreamCmd []string
	listen      string
	adminListen string
	publicURL   string
	force       bool
}

type initDoc struct {
	Server     initServer     `yaml:"server"`
	Auth       initAuth       `yaml:"auth"`
	Upstreams  []initUpstream `yaml:"upstreams"`
	Policy     initPolicy     `yaml:"policy"`
	RateLimits initRateLimits `yaml:"rate_limits"`
	Audit      initAudit      `yaml:"audit"`
	Pinning    initPinning    `yaml:"pinning"`
}

type initServer struct {
	Listen         string `yaml:"listen"`
	AdminListen    string `yaml:"admin_listen"`
	PublicURL      string `yaml:"public_url"`
	NamespaceTools bool   `yaml:"namespace_tools"`
}

type initAuth struct {
	Mode                 string   `yaml:"mode"`
	Resource             string   `yaml:"resource,omitempty"`
	AuthorizationServers []string `yaml:"authorization_servers,omitempty"`
	ScopesSupported      []string `yaml:"scopes_supported,omitempty"`
	RequiredScopes       []string `yaml:"required_scopes,omitempty"`
	JWT                  *initJWT `yaml:"jwt,omitempty"`
}

type initJWT struct {
	Issuer     string   `yaml:"issuer"`
	JWKSURL    string   `yaml:"jwks_url"`
	Audiences  []string `yaml:"audiences"`
	Algorithms []string `yaml:"algorithms"`
}

type initUpstream struct {
	ID             string   `yaml:"id"`
	Transport      string   `yaml:"transport"`
	Command        []string `yaml:"command,omitempty"`
	EnvPassthrough []string `yaml:"env_passthrough,omitempty"`
	URL            string   `yaml:"url,omitempty"`
	Timeout        string   `yaml:"timeout"`
	MaxConcurrency int      `yaml:"max_concurrency,omitempty"`
}

type initPolicy struct {
	Default string           `yaml:"default"`
	Rules   []initPolicyRule `yaml:"rules"`
}

type initPolicyRule struct {
	Name     string        `yaml:"name"`
	Subjects *initSubjects `yaml:"subjects,omitempty"`
	Tools    []string      `yaml:"tools"`
	When     string        `yaml:"when,omitempty"`
	Effect   string        `yaml:"effect"`
	OnDeny   *initOnDeny   `yaml:"on_deny,omitempty"`
}

type initSubjects struct {
	ScopesAny []string `yaml:"scopes_any,omitempty"`
}

type initOnDeny struct {
	StepUpScopes []string `yaml:"step_up_scopes,omitempty"`
}

type initRateLimits struct {
	Rules []initRateRule `yaml:"rules"`
}

type initRateRule struct {
	Name  string   `yaml:"name"`
	Tools []string `yaml:"tools,omitempty"`
	Per   string   `yaml:"per"`
	Rate  string   `yaml:"rate"`
	Burst int      `yaml:"burst"`
}

type initAudit struct {
	Path       string         `yaml:"path"`
	ChainID    string         `yaml:"chain_id"`
	RecordArgs string         `yaml:"record_args"`
	Checkpoint initCheckpoint `yaml:"checkpoint"`
}

type initCheckpoint struct {
	SigningKeyFile string `yaml:"signing_key_file"`
}

type initPinning struct {
	Mode string `yaml:"mode"`
	File string `yaml:"file"`
}

type initFixtureDoc struct {
	Cases []initFixtureCase `yaml:"cases"`
}

type initFixtureCase struct {
	Name        string                `yaml:"name"`
	Principal   *initFixturePrincipal `yaml:"principal,omitempty"`
	Tool        string                `yaml:"tool"`
	Annotations map[string]bool       `yaml:"annotations,omitempty"`
	Args        map[string]any        `yaml:"args,omitempty"`
	Expect      string                `yaml:"expect"`
	Rule        string                `yaml:"rule,omitempty"`
}

type initFixturePrincipal struct {
	Sub    string   `yaml:"sub"`
	Scopes []string `yaml:"scopes"`
}

func initCmd() *cobra.Command {
	var o initOpts
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a starter config, Ed25519 audit keys and policy test fixtures",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd.Context(), cmd.OutOrStdout(), o)
		},
	}
	cmd.Flags().StringVarP(&o.dir, "dir", "d", ".", "target directory for generated files")
	cmd.Flags().StringVarP(&o.profile, "profile", "p", initProfileLocal, "starter profile: local or team")
	cmd.Flags().StringVar(&o.upstreamID, "upstream-id", "", "upstream identifier (defaults to fs or app)")
	cmd.Flags().StringVar(&o.upstreamURL, "upstream-url", "", "streamable HTTP upstream URL")
	cmd.Flags().StringArrayVar(&o.upstreamCmd, "upstream-cmd", nil,
		"stdio upstream command token (repeatable, e.g. --upstream-cmd npx --upstream-cmd -y ...)")
	cmd.Flags().StringVar(&o.listen, "listen", "127.0.0.1:8080", "gateway listen address")
	cmd.Flags().StringVar(&o.adminListen, "admin-listen", "127.0.0.1:9090", "admin listen address")
	cmd.Flags().StringVar(&o.publicURL, "public-url", "", "canonical MCP URL")
	cmd.Flags().BoolVar(&o.force, "force", false, "overwrite existing tollkeeper.yaml and policies_test.yaml")
	return cmd
}

func runInit(ctx context.Context, out io.Writer, o initOpts) error {
	if err := o.normalize(); err != nil {
		return err
	}
	cfgPath := filepath.Join(o.dir, "tollkeeper.yaml")
	fixPath := filepath.Join(o.dir, "policies_test.yaml")
	if !o.force {
		if err := ensureAbsent(cfgPath, fixPath); err != nil {
			return err
		}
	}
	keysDir := filepath.Join(o.dir, "keys")
	privPath, pubPath, keyKept, err := ensureInitKeys(keysDir)
	if err != nil {
		return err
	}
	doc, fixtures := buildInitFiles(o, privPath)
	cfgBytes, err := marshalYAML(doc)
	if err != nil {
		return err
	}
	fixBytes, err := marshalYAML(fixtures)
	if err != nil {
		return err
	}
	if err := writeInitFile(cfgPath, cfgBytes); err != nil {
		return err
	}
	if err := writeInitFile(fixPath, fixBytes); err != nil {
		return err
	}
	if err := validateInitOutput(ctx, cfgPath, fixPath); err != nil {
		return err
	}
	return printInitSummary(out, o, cfgPath, fixPath, privPath, pubPath, keyKept)
}

func (o *initOpts) normalize() error {
	if o.profile != initProfileLocal && o.profile != initProfileTeam {
		return fmt.Errorf(
			"%w: --profile must be %q or %q, got %q",
			ErrInit,
			initProfileLocal,
			initProfileTeam,
			o.profile,
		)
	}
	if o.upstreamURL != "" && len(o.upstreamCmd) > 0 {
		return fmt.Errorf("%w: --upstream-url and --upstream-cmd cannot be set together", ErrInit)
	}
	if o.dir == "" {
		o.dir = "."
	}
	if o.upstreamID == "" {
		o.upstreamID = defaultUpstreamID(*o)
	}
	if o.publicURL == "" {
		o.publicURL = defaultPublicURL(o.profile, o.listen)
	}
	return nil
}

func defaultUpstreamID(o initOpts) string {
	if o.upstreamURL != "" || len(o.upstreamCmd) > 0 {
		return "upstream"
	}
	if o.profile == initProfileTeam {
		return "app"
	}
	return "fs"
}

func defaultPublicURL(profile, listen string) string {
	if profile == initProfileTeam {
		return "https://mcp.example.com/mcp"
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		port = "8080"
	}
	return "http://localhost:" + port + "/mcp"
}

func ensureAbsent(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%w: %s already exists (pass --force to overwrite)", ErrInit, p)
		}
	}
	return nil
}

func ensureInitKeys(dir string) (privPath, pubPath string, kept bool, err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", false, fmt.Errorf("create key dir: %w", err)
	}
	privPath = filepath.Join(dir, "audit-ed25519.pem")
	pubPath = filepath.Join(dir, "audit-ed25519.pub")
	if _, err := os.Stat(privPath); err == nil {
		return privPath, pubPath, true, nil
	}
	priv, pub, err := audit.GenerateKeyPair()
	if err != nil {
		return "", "", false, err
	}
	if err := writeNew(privPath, priv, 0o600); err != nil {
		return "", "", false, err
	}
	if err := writeNew(pubPath, pub, 0o644); err != nil {
		return "", "", false, err
	}
	return privPath, pubPath, false, nil
}

func buildInitFiles(o initOpts, privPath string) (initDoc, initFixtureDoc) {
	up := buildInitUpstream(o)
	auditPath := configPathForYAML(o.dir, "audit.jsonl")
	pinsPath := configPathForYAML(o.dir, "pins.json")
	keyPath := filepath.ToSlash(privPath)
	if o.dir == "." {
		keyPath = "./" + filepath.ToSlash(privPath)
	}
	if o.profile == initProfileTeam {
		return buildTeamInit(o, up, auditPath, pinsPath, keyPath)
	}
	return buildLocalInit(o, up, auditPath, pinsPath, keyPath)
}

func configPathForYAML(dir, name string) string {
	if dir == "." {
		return "./" + name
	}
	return filepath.ToSlash(filepath.Join(dir, name))
}

func buildInitUpstream(o initOpts) initUpstream {
	if o.upstreamURL != "" {
		return initUpstream{
			ID:             o.upstreamID,
			Transport:      config.TransportStreamable,
			URL:            o.upstreamURL,
			Timeout:        "30s",
			MaxConcurrency: 16,
		}
	}
	if len(o.upstreamCmd) > 0 {
		return initUpstream{
			ID:             o.upstreamID,
			Transport:      config.TransportStdio,
			Command:        o.upstreamCmd,
			EnvPassthrough: []string{"PATH", "HOME"},
			Timeout:        "15s",
		}
	}
	if o.profile == initProfileTeam {
		return initUpstream{
			ID:             o.upstreamID,
			Transport:      config.TransportStreamable,
			URL:            "https://upstream.example.com/mcp",
			Timeout:        "30s",
			MaxConcurrency: 16,
		}
	}
	return initUpstream{
		ID:             o.upstreamID,
		Transport:      config.TransportStdio,
		Command:        []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "."},
		EnvPassthrough: []string{"PATH", "HOME"},
		Timeout:        "15s",
	}
}

func buildLocalInit(o initOpts, up initUpstream, auditPath, pinsPath, keyPath string) (initDoc, initFixtureDoc) {
	customUpstream := o.upstreamURL != "" || len(o.upstreamCmd) > 0
	rules, fixtures := localRulesAndFixtures(customUpstream)
	doc := initDoc{
		Server: initServer{
			Listen:         o.listen,
			AdminListen:    o.adminListen,
			PublicURL:      o.publicURL,
			NamespaceTools: false,
		},
		Auth:      initAuth{Mode: config.AuthModeNone},
		Upstreams: []initUpstream{up},
		Policy:    initPolicy{Default: initEffectDeny, Rules: rules},
		RateLimits: initRateLimits{
			Rules: []initRateRule{{
				Name:  "local-agent",
				Per:   "global",
				Rate:  "300/m",
				Burst: 50,
			}},
		},
		Audit: initAudit{
			Path:       auditPath,
			ChainID:    "local-gateway",
			RecordArgs: config.RecordArgsFull,
			Checkpoint: initCheckpoint{SigningKeyFile: keyPath},
		},
		Pinning: initPinning{
			Mode: config.PinModeWarn,
			File: pinsPath,
		},
	}
	return doc, fixtures
}

func localRulesAndFixtures(customUpstream bool) ([]initPolicyRule, initFixtureDoc) {
	if customUpstream {
		rules := []initPolicyRule{{
			Name:   initRuleReadOnly,
			Tools:  []string{"*"},
			When:   "tool.annotations.readOnlyHint == true",
			Effect: initEffectAllow,
		}}
		fixtures := initFixtureDoc{Cases: []initFixtureCase{
			{
				Name:        "read-only tool is allowed",
				Tool:        "search",
				Annotations: map[string]bool{"readOnlyHint": true},
				Expect:      initEffectAllow,
				Rule:        initRuleReadOnly,
			},
			{
				Name:        "write tool is denied by default",
				Tool:        "delete_item",
				Annotations: map[string]bool{"destructiveHint": true},
				Expect:      initEffectDeny,
				Rule:        initRuleDefault,
			},
		}}
		return rules, fixtures
	}
	rules := []initPolicyRule{
		{
			Name: "reads-anywhere-in-workspace",
			Tools: []string{
				"read_text_file",
				"read_multiple_files",
				"list_directory",
				"directory_tree",
				"search_files",
				"get_file_info",
			},
			Effect: initEffectAllow,
		},
		{
			Name:   "writes-only-under-drafts",
			Tools:  []string{initToolWriteFile, "edit_file", "create_directory"},
			When:   `has(args.path) && args.path.startsWith("./drafts/") && !args.path.contains("..")`,
			Effect: initEffectAllow,
		},
	}
	fixtures := initFixtureDoc{Cases: []initFixtureCase{
		{
			Name:   "reading workspace files is allowed",
			Tool:   "read_text_file",
			Args:   map[string]any{initArgPath: "./README.md"},
			Expect: initEffectAllow,
			Rule:   "reads-anywhere-in-workspace",
		},
		{
			Name:   "writing inside drafts is allowed",
			Tool:   initToolWriteFile,
			Args:   map[string]any{initArgPath: "./drafts/note.md"},
			Expect: initEffectAllow,
			Rule:   "writes-only-under-drafts",
		},
		{
			Name:   "writing outside drafts is denied",
			Tool:   initToolWriteFile,
			Args:   map[string]any{initArgPath: "./etc/passwd"},
			Expect: initEffectDeny,
			Rule:   initRuleDefault,
		},
		{
			Name:   "path traversal out of drafts is denied",
			Tool:   initToolWriteFile,
			Args:   map[string]any{initArgPath: "./drafts/../secret.txt"},
			Expect: initEffectDeny,
			Rule:   initRuleDefault,
		},
	}}
	return rules, fixtures
}

func buildTeamInit(o initOpts, up initUpstream, auditPath, pinsPath, keyPath string) (initDoc, initFixtureDoc) {
	glob := o.upstreamID + "__*"
	readTool := o.upstreamID + "__search"
	writeTool := o.upstreamID + "__delete"
	doc := initDoc{
		Server: initServer{
			Listen:         o.listen,
			AdminListen:    o.adminListen,
			PublicURL:      o.publicURL,
			NamespaceTools: true,
		},
		Auth: initAuth{
			Mode:                 config.AuthModeJWT,
			Resource:             o.publicURL,
			AuthorizationServers: []string{"https://login.example.com"},
			ScopesSupported:      []string{initScopeTools, initScopeWrite},
			RequiredScopes:       []string{initScopeTools},
			JWT: &initJWT{
				Issuer:     "https://login.example.com",
				JWKSURL:    "https://login.example.com/.well-known/jwks.json",
				Audiences:  []string{o.publicURL},
				Algorithms: []string{"RS256", "ES256", "EdDSA"},
			},
		},
		Upstreams: []initUpstream{up},
		Policy: initPolicy{
			Default: initEffectDeny,
			Rules: []initPolicyRule{
				{
					Name:     initRuleReadOnly,
					Subjects: &initSubjects{ScopesAny: []string{initScopeTools}},
					Tools:    []string{glob},
					When:     "tool.annotations.readOnlyHint == true",
					Effect:   initEffectAllow,
				},
				{
					Name:     initRuleWriteStepUp,
					Subjects: &initSubjects{ScopesAny: []string{initScopeTools}},
					Tools:    []string{glob},
					When:     `"` + initScopeWrite + `" in principal.scopes`,
					Effect:   initEffectAllow,
					OnDeny:   &initOnDeny{StepUpScopes: []string{initScopeWrite}},
				},
			},
		},
		RateLimits: initRateLimits{
			Rules: []initRateRule{{
				Name:  "per-agent-per-tool",
				Tools: []string{glob},
				Per:   "subject_tool",
				Rate:  "60/m",
				Burst: 10,
			}},
		},
		Audit: initAudit{
			Path:       auditPath,
			ChainID:    "team-gateway",
			RecordArgs: config.RecordArgsHash,
			Checkpoint: initCheckpoint{SigningKeyFile: keyPath},
		},
		Pinning: initPinning{
			Mode: config.PinModeEnforce,
			File: pinsPath,
		},
	}
	fixtures := initFixtureDoc{Cases: []initFixtureCase{
		{
			Name:        "reader can call read-only tools",
			Principal:   &initFixturePrincipal{Sub: "alice", Scopes: []string{initScopeTools}},
			Tool:        readTool,
			Annotations: map[string]bool{"readOnlyHint": true},
			Expect:      initEffectAllow,
			Rule:        initRuleReadOnly,
		},
		{
			Name:      "reader gets step-up on write tool",
			Principal: &initFixturePrincipal{Sub: "alice", Scopes: []string{initScopeTools}},
			Tool:      writeTool,
			Expect:    "step_up",
			Rule:      initRuleWriteStepUp,
		},
		{
			Name:      "writer with mcp:write can call write tool",
			Principal: &initFixturePrincipal{Sub: "bob", Scopes: []string{initScopeTools, initScopeWrite}},
			Tool:      writeTool,
			Expect:    initEffectAllow,
			Rule:      initRuleWriteStepUp,
		},
		{
			Name:      "caller without scopes is denied",
			Principal: &initFixturePrincipal{Sub: "mallory", Scopes: []string{}},
			Tool:      readTool,
			Expect:    initEffectDeny,
			Rule:      initRuleDefault,
		},
	}}
	return doc, fixtures
}

func marshalYAML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close yaml encoder: %w", err)
	}
	return buf.Bytes(), nil
}

func writeInitFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create dir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func validateInitOutput(ctx context.Context, cfgPath, fixPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	eng, err := policy.New(cfg.Policy)
	if err != nil {
		return err
	}
	if _, err := ratelimit.New(cfg.RateLimits, ratelimit.NewStore(nil)); err != nil {
		return err
	}
	f, err := os.Open(fixPath)
	if err != nil {
		return fmt.Errorf("open generated fixtures: %w", err)
	}
	defer f.Close()
	ff, err := policy.ParseFixtures(f)
	if err != nil {
		return err
	}
	results, err := eng.RunFixtures(ctx, ff, cfg.Naming())
	if err != nil {
		return err
	}
	for _, r := range results {
		if !r.Pass {
			return fmt.Errorf("%w: generated fixture %q failed: %s", ErrInit, r.Name, r.Detail)
		}
	}
	return nil
}

func printInitSummary(
	out io.Writer,
	o initOpts,
	cfgPath, fixPath, privPath, pubPath string,
	keyKept bool,
) error {
	keyLine := fmt.Sprintf("wrote %s and %s\n", privPath, pubPath)
	if keyKept {
		keyLine = fmt.Sprintf("kept existing %s\n", privPath)
	}
	chainID := "local-gateway"
	if o.profile == initProfileTeam {
		chainID = "team-gateway"
	}
	auditPath := configPathForYAML(o.dir, "audit.jsonl")
	return printf(
		out,
		"wrote %s\nwrote %s\n%s\nNext steps:\n"+
			"  1. Test policies:    tollkeeper policy test -c %s -f %s\n"+
			"  2. Start gateway:    tollkeeper serve -c %s\n"+
			"  3. Point MCP client: %s\n"+
			"  4. Verify audit log: tollkeeper audit verify -f %s --pubkey %s --chain-id %s\n",
		cfgPath,
		fixPath,
		keyLine,
		cfgPath,
		fixPath,
		cfgPath,
		o.publicURL,
		auditPath,
		pubPath,
		chainID,
	)
}
