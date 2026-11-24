package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/bundle"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func writeEd25519Keypair(t *testing.T, dir, prefix string) (privPath, pubPath string, priv ed25519.PrivateKey) {
	t.Helper()
	privPEM, pubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, err = audit.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	privPath = filepath.Join(dir, prefix+".key")
	pubPath = filepath.Join(dir, prefix+".pub")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return privPath, pubPath, priv
}

func baseCoverageConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		Server: config.Server{
			Listen:             "127.0.0.1:0",
			AdminListen:        "127.0.0.1:0",
			PublicURL:          "http://127.0.0.1:8080/mcp",
			NamespaceTools:     true,
			NamespaceSeparator: "__",
			MaxBodyBytes:       1 << 20,
			RequestStateTTL:    5 * time.Minute,
			TaskTTL:            time.Hour,
			StampProvenance:    true,
			TasksEnabled:       true,
			Pprof:              true,
		},
		Auth: config.Auth{Mode: config.AuthModeNone},
		Upstreams: []config.Upstream{
			{
				ID:             "svc",
				Transport:      config.TransportStreamable,
				URL:            "http://127.0.0.1:19999/mcp",
				Timeout:        time.Second,
				MaxConcurrency: 4,
				Breaker:        config.Breaker{Failures: 3, OpenFor: time.Second},
				RestartBackoff: time.Second,
				RestartMax:     5 * time.Second,
			},
		},
		Policy: config.Policy{
			Default: config.EffectDeny,
			Rules: []config.Rule{
				{
					Name:   "allow-read",
					Tools:  []string{"svc__read"},
					Effect: config.EffectAllow,
				},
				{
					Name:   "shadow-write",
					Tools:  []string{"svc__write"},
					Mode:   config.RuleModeShadow,
					Effect: config.EffectAllow,
				},
				{
					Name:   "require-approval",
					Tools:  []string{"svc__write"},
					When:   "approval.verified == true",
					Effect: config.EffectAllow,
					OnDeny: config.OnDeny{
						StepUpScopes:    []string{"write:all"},
						ACRValues:       []string{"urn:mfa"},
						MaxAge:          5 * time.Minute,
						RequireDPoP:     true,
						RequireApproval: true,
						ApprovalTTL:     10 * time.Minute,
						ApprovalReason:  "production write",
					},
				},
			},
			Tenants: map[string]config.TenantPolicy{
				"acme": {
					Default: config.EffectDeny,
					Rules: []config.Rule{
						{Name: "acme-prompt", Prompts: []string{"svc__sum"}, Effect: config.EffectAllow},
					},
				},
			},
		},
		Pinning: config.Pinning{Mode: config.PinModeOff},
		RateLimits: config.RateLimits{
			Store: config.RateStoreMemory,
		},
		Digest: "abc123",
	}
}

func TestBuildApprovalsIdempotencyBundleWatchdogAndReload(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	dir := t.TempDir()

	_, approvalPub, _ := writeEd25519Keypair(t, dir, "approval")
	_, bundlePub, bundlePriv := writeEd25519Keypair(t, dir, "bundle")
	auditPrivPath, _, _ := writeEd25519Keypair(t, dir, "audit")

	stateKeyPath := filepath.Join(dir, "state.key")
	if err := os.WriteFile(stateKeyPath, []byte(strings.Repeat("k", 40)), 0o600); err != nil {
		t.Fatalf("write state key: %v", err)
	}

	cfgPath := filepath.Join(dir, "tollkeeper.yaml")
	cfgBytes := []byte("policy:\n  default: deny\n")
	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	sum := sha256.Sum256(cfgBytes)
	cfgDigest := hex.EncodeToString(sum[:])

	pinsPath := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(pinsPath, []byte(`{"version":1,"tools":{}}`), 0o600); err != nil {
		t.Fatalf("write pins: %v", err)
	}

	manifest, err := bundle.Sign(bundlePriv, bundle.SignOptions{
		BundleID:   "rel-1",
		ConfigPath: cfgPath,
		PinsPath:   pinsPath,
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("bundle.Sign: %v", err)
	}
	manifestPath := filepath.Join(dir, "bundle.json")
	if err := bundle.WriteManifest(manifestPath, manifest); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")

	cfg := baseCoverageConfig(t)
	cfg.Digest = cfgDigest
	cfg.Server.RequestStateKey = stateKeyPath
	cfg.Pinning = config.Pinning{Mode: config.PinModeWarn, File: pinsPath}
	cfg.RateLimits = config.RateLimits{
		Store: config.RateStoreRedis,
		Redis: config.RedisLimits{
			Addrs:     []string{mr.Addr()},
			KeyPrefix: "tk:",
			Timeout:   time.Second,
		},
	}
	cfg.Idempotency = config.Idempotency{
		Enabled:    true,
		Mode:       config.IdempotencyModeHeader,
		Header:     "Idempotency-Key",
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	}
	cfg.Approvals = config.Approvals{
		Enabled:     true,
		Header:      "X-Tollkeeper-Approval",
		PubKeyFiles: []string{approvalPub},
		Issuer:      "https://approvals.example.com",
		MaxTTL:      15 * time.Minute,
		ClockSkew:   30 * time.Second,
		SingleUse:   true,
		MaxEntries:  100,
	}
	cfg.Bundle = config.Bundle{
		Enabled:      true,
		ManifestFile: manifestPath,
		PubKeyFiles:  []string{bundlePub},
		RequirePins:  true,
	}
	cfg.Audit = config.Audit{
		Enabled: true,
		ChainID: "chain-test",
		Path:    auditPath,
		Checkpoint: config.Checkpoint{
			Every:          10,
			Interval:       time.Minute,
			SigningKeyFile: auditPrivPath,
		},
		Verify: config.AuditVerify{
			Enabled:  true,
			Interval: time.Minute,
		},
	}

	application, err := Build(t.Context(), cfg, slog.New(slog.DiscardHandler), "1.7.0")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() {
		application.close(t.Context())
	}()

	if application.Gateway() == nil || application.Catalog() == nil {
		t.Fatal("expected non-nil Gateway and Catalog")
	}
	if application.Addr("missing") != "" {
		t.Fatalf("expected empty Addr for unknown listener")
	}
	application.WatchConfig(cfgPath)
	if application.configPath != cfgPath {
		t.Fatalf("WatchConfig did not set configPath")
	}

	st := application.watchdog.Check(t.Context())
	if !st.Healthy {
		t.Fatalf("expected healthy watchdog check, got error=%q", st.Error)
	}

	h := application.adminHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/overview", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/overview = %d: %s", rec.Code, rec.Body.String())
	}
	var ov overviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if !ov.Bundle.Verified || ov.Bundle.BundleID != "rel-1" || !ov.Audit.Watchdog.Checked ||
		!ov.Audit.Watchdog.Healthy {
		t.Fatalf("unexpected overview bundle/watchdog: bundle=%+v wd=%+v", ov.Bundle, ov.Audit.Watchdog)
	}

	recPins := httptest.NewRecorder()
	h.ServeHTTP(recPins, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/pins", http.NoBody))
	if recPins.Code != http.StatusOK {
		t.Fatalf("GET /api/pins = %d", recPins.Code)
	}

	recPprof := httptest.NewRecorder()
	h.ServeHTTP(recPprof, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/debug/pprof/", http.NoBody))
	if recPprof.Code != http.StatusOK {
		t.Fatalf("GET /debug/pprof/ = %d", recPprof.Code)
	}

	recLive := httptest.NewRecorder()
	h.ServeHTTP(recLive, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/livez", http.NoBody))
	if recLive.Code != http.StatusOK {
		t.Fatalf("GET /livez = %d", recLive.Code)
	}

	recReady := httptest.NewRecorder()
	h.ServeHTTP(recReady, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", http.NoBody))
	if recReady.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 /readyz before ready, got %d", recReady.Code)
	}

	if err := application.Reload(t.Context(), cfg); err != nil {
		t.Fatalf("Reload with valid bundle: %v", err)
	}
	badCfg := cfg
	badCfg.Digest = "tampered-digest"
	if err := application.Reload(t.Context(), badCfg); err == nil {
		t.Fatal("expected Reload with mismatched bundle digest to fail")
	}
}

func TestBuildMemoryStoresAndErrorBranches(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, approvalPub, _ := writeEd25519Keypair(t, dir, "approval-mem")

	cfg := baseCoverageConfig(t)
	cfg.Idempotency = config.Idempotency{
		Enabled:    true,
		Mode:       config.IdempotencyModeHeader,
		Header:     "Idempotency-Key",
		TTL:        time.Minute,
		MaxEntries: 64,
	}
	cfg.Approvals = config.Approvals{
		Enabled:     true,
		Header:      "X-Tollkeeper-Approval",
		PubKeyFiles: []string{approvalPub},
		MaxTTL:      10 * time.Minute,
		SingleUse:   true,
		MaxEntries:  64,
	}
	cfg.Auth = config.Auth{
		Mode: config.AuthModeIntrospection,
		DPoP: config.DPoP{
			Mode:       config.DPoPModeOptional,
			Algorithms: []string{"ES256"},
			MaxAge:     time.Minute,
		},
		Introspection: config.Introspection{
			URL:           "https://idp.example.com/introspect",
			ClientID:      "tk",
			ClientSecret:  "secret",
			Audiences:     []string{"https://mcp.example.com"},
			CacheTTL:      time.Minute,
			Timeout:       time.Second,
			AllowInsecure: true,
		},
	}

	application, err := Build(t.Context(), cfg, slog.New(slog.DiscardHandler), "1.7.0")
	if err != nil {
		t.Fatalf("Build memory + introspection: %v", err)
	}
	defer func() {
		application.close(t.Context())
	}()

	if application.anchorStale() {
		t.Fatal("expected anchorStale() == false without anchorer")
	}

	recPins := httptest.NewRecorder()
	application.adminHandler().ServeHTTP(
		recPins,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/pins", http.NoBody),
	)
	if recPins.Code != http.StatusOK {
		t.Fatalf("GET /api/pins with pins off = %d", recPins.Code)
	}

	if k, err := readStateKey(""); err != nil || k != nil {
		t.Fatalf("readStateKey empty: k=%v err=%v", k, err)
	}
	if _, err := readStateKey(filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("expected error for missing state key")
	}
	shortPath := filepath.Join(dir, "short.key")
	if err := os.WriteFile(shortPath, []byte("short"), 0o600); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	if _, err := readStateKey(shortPath); err == nil {
		t.Fatal("expected error for short state key")
	}

	if _, _, err := buildAuditSigner(t.Context(), config.Checkpoint{}); !errors.Is(err, audit.ErrNoSigner) {
		t.Fatalf("expected ErrNoSigner, got %v", err)
	}
	if _, _, err := buildAuditSigner(
		t.Context(),
		config.Checkpoint{SigningKeyFile: filepath.Join(dir, "missing.key")},
	); err == nil {
		t.Fatal("expected error for missing signing key file")
	}
	if _, _, err := buildAuditSigner(
		t.Context(),
		config.Checkpoint{KMS: &config.AuditKMS{Provider: "unknown"}},
	); !errors.Is(
		err,
		config.ErrInvalid,
	) {
		t.Fatalf("expected config.ErrInvalid for unknown KMS provider, got %v", err)
	}

	badAuth := baseCoverageConfig(t)
	badAuth.Auth.Mode = "bogus"
	if _, err := application.verifier(t.Context(), badAuth); !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("expected config.ErrInvalid for bogus auth mode, got %v", err)
	}

	jwtCfg := baseCoverageConfig(t)
	jwtCfg.Auth = config.Auth{
		Mode: config.AuthModeJWT,
		JWT: config.JWT{
			Issuer:       "https://idp.example.com",
			JWKSURL:      "https://idp.example.com/jwks.json",
			Audiences:    []string{"https://mcp.example.com"},
			Algorithms:   []string{"EdDSA"},
			ClockSkew:    30 * time.Second,
			JWKSMinRetry: time.Second,
		},
	}
	if v, err := application.verifier(t.Context(), jwtCfg); err != nil || v == nil {
		t.Fatalf("verifier JWT: v=%v err=%v", v, err)
	}

	badBundle := baseCoverageConfig(t)
	badBundle.Bundle = config.Bundle{Enabled: true, PubKeyFiles: []string{filepath.Join(dir, "nope.pub")}}
	if _, err := Build(t.Context(), badBundle, slog.New(slog.DiscardHandler), "1.7.0"); err == nil {
		t.Fatal("expected Build error with missing bundle pubkey")
	}

	badApprovals := baseCoverageConfig(t)
	badApprovals.Approvals = config.Approvals{Enabled: true, PubKeyFiles: []string{filepath.Join(dir, "nope.pub")}}
	if _, err := Build(t.Context(), badApprovals, slog.New(slog.DiscardHandler), "1.7.0"); err == nil {
		t.Fatal("expected Build error with missing approval pubkey")
	}
}

func TestAdminPolicyEditorSimulatorAndAuditHelpers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pinsPath := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(pinsPath, []byte(`{"version":1,"tools":{}}`), 0o600); err != nil {
		t.Fatalf("write pins: %v", err)
	}

	cfg := baseCoverageConfig(t)
	cfg.Pinning = config.Pinning{Mode: config.PinModeEnforce, File: pinsPath, ReportToken: "secret-tok"}
	application, err := Build(t.Context(), cfg, slog.New(slog.DiscardHandler), "1.7.0")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() {
		application.close(t.Context())
	}()

	if _, err := application.catalog.Replace("svc", []catalog.Tool{
		{Name: "svc__read", Upstream: "svc", Original: "read", Pin: "sha256:aaa"},
		{Name: "svc__write", Upstream: "svc", Original: "write", Pin: "sha256:bbb"},
	}); err != nil {
		t.Fatalf("catalog.Replace: %v", err)
	}

	h := application.adminHandler()
	authHeader := "Bearer secret-tok"

	recUnauth := httptest.NewRecorder()
	h.ServeHTTP(recUnauth, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/policy", http.NoBody))
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", recUnauth.Code)
	}

	reqPol := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/policy", http.NoBody)
	reqPol.Header.Set("Authorization", authHeader)
	recPol := httptest.NewRecorder()
	h.ServeHTTP(recPol, reqPol)
	if recPol.Code != http.StatusOK {
		t.Fatalf("GET /api/policy = %d: %s", recPol.Code, recPol.Body.String())
	}

	validateCases := []struct {
		name      string
		body      string
		wantCode  int
		wantValid bool
	}{
		{
			name:      "bare yaml with tenants and durations",
			body:      `{"yaml":"default: deny\nrules:\n  - name: r1\n    tools: [\"svc__*\"]\n    when: approval.verified == true\n    effect: allow\n    on_deny:\n      max_age: 2m\n      approval_ttl: 5m\ntenants:\n  acme:\n    default: deny\n    rules:\n      - name: t1\n        tools: [\"svc__read\"]\n        effect: allow\n"}`,
			wantCode:  http.StatusOK,
			wantValid: true,
		},
		{
			name:      "wrapped policy yaml",
			body:      `{"yaml":"policy:\n  default: deny\n  rules:\n    - name: r1\n      tools: [\"svc__read\"]\n      effect: allow\n"}`,
			wantCode:  http.StatusOK,
			wantValid: true,
		},
		{
			name:      "json policy dto",
			body:      `{"policy":{"default":"deny","rules":[{"name":"r1","tools":["svc__read"],"effect":"allow"}]}}`,
			wantCode:  http.StatusOK,
			wantValid: true,
		},
		{
			name:      "invalid max_age duration",
			body:      `{"yaml":"default: deny\nrules:\n  - name: r1\n    tools: [\"svc__read\"]\n    effect: deny\n    on_deny:\n      max_age: bogus\n"}`,
			wantCode:  http.StatusOK,
			wantValid: false,
		},
		{
			name:      "invalid approval_ttl duration",
			body:      `{"yaml":"default: deny\nrules:\n  - name: r1\n    tools: [\"svc__read\"]\n    effect: deny\n    on_deny:\n      approval_ttl: bogus\n"}`,
			wantCode:  http.StatusOK,
			wantValid: false,
		},
		{
			name:      "empty request",
			body:      `{}`,
			wantCode:  http.StatusOK,
			wantValid: false,
		},
		{
			name:      "invalid json body",
			body:      `{bad`,
			wantCode:  http.StatusBadRequest,
			wantValid: false,
		},
	}

	for _, tc := range validateCases {
		req := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"/api/policy/validate",
			strings.NewReader(tc.body),
		)
		req.Header.Set("Authorization", authHeader)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Fatalf("%s: status = %d, want %d: %s", tc.name, rec.Code, tc.wantCode, rec.Body.String())
		}
		var out policyValidateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if out.Valid != tc.wantValid {
			t.Fatalf("%s: valid = %v, want %v (errors=%v)", tc.name, out.Valid, tc.wantValid, out.Errors)
		}
	}

	simReqs := []struct {
		name     string
		req      simulateRequest
		wantCode int
	}{
		{
			name: "write tool with shadow step-up annotations metadata approval",
			req: simulateRequest{
				Kind: "tool",
				Name: "svc__write",
				Principal: simulatePrincipalReq{
					Sub:            "alice",
					Actor:          "agent-1",
					AuthAgeSeconds: new(int64(30)),
				},
				Annotations: &simulateAnnotationsReq{
					ReadOnly:    new(false),
					Destructive: new(true),
					Idempotent:  new(false),
					OpenWorld:   new(true),
				},
				Metadata: &simulateMetadataReq{
					Trust:          "untrusted",
					Classification: "restricted",
					Egress:         new(true),
					Impact:         "destructive",
				},
				Approval: &simulateApprovalReq{
					Verified: false,
				},
				Args: json.RawMessage(`{"x":1}`),
			},
			wantCode: http.StatusOK,
		},
		{
			name: "unknown tool with pinning enforce",
			req: simulateRequest{
				Kind:      "tool",
				Name:      "svc__unknown",
				Principal: simulatePrincipalReq{Sub: "alice"},
			},
			wantCode: http.StatusOK,
		},
		{
			name: "prompt kind",
			req: simulateRequest{
				Kind:      "prompt",
				Name:      "svc__sum",
				Principal: simulatePrincipalReq{Sub: "alice", Tenant: "acme"},
			},
			wantCode: http.StatusOK,
		},
		{
			name: "resource kind",
			req: simulateRequest{
				Kind:      "resource",
				Name:      "file:///a.txt",
				Principal: simulatePrincipalReq{Sub: "alice"},
			},
			wantCode: http.StatusOK,
		},
		{
			name: "template kind with draft policy yaml",
			req: simulateRequest{
				Kind:       "template",
				Name:       "file:///docs/{id}",
				Principal:  simulatePrincipalReq{Sub: "alice"},
				PolicyYAML: "default: deny\nrules:\n  - name: allow-tpl\n    resources: [\"file:///docs/*\"]\n    effect: allow\n",
			},
			wantCode: http.StatusOK,
		},
		{
			name: "invalid draft policy yaml",
			req: simulateRequest{
				Kind:       "tool",
				Name:       "svc__read",
				PolicyYAML: "default: invalid_effect",
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "missing name",
			req:      simulateRequest{Kind: "tool"},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tc := range simReqs {
		b, err := json.Marshal(tc.req)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/simulate", bytes.NewReader(b))
		req.Header.Set("Authorization", authHeader)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Fatalf("%s: status = %d, want %d: %s", tc.name, rec.Code, tc.wantCode, rec.Body.String())
		}
	}

	k1, s1 := classifyAuditBody(&audit.Body{Event: &audit.Event{Phase: "call", Tool: "svc__read", Decision: "allow"}})
	k2, s2 := classifyAuditBody(
		&audit.Body{Event: &audit.Event{Phase: "call", Method: "tools/list", Decision: "allow"}},
	)
	k3, s3 := classifyAuditBody(&audit.Body{Checkpoint: &audit.Checkpoint{CoversSeq: 5, KeyID: "k1"}})
	k4, s4 := classifyAuditBody(&audit.Body{Anchor: &audit.Anchor{CoversSeq: 5}})
	k5, s5 := classifyAuditBody(&audit.Body{KeyRotation: &audit.KeyRotation{PrevKeyID: "k1", NewKeyID: "k2"}})
	k6, _ := classifyAuditBody(&audit.Body{})
	if k1 != audit.KindEvent || !strings.Contains(s1, "svc__read") ||
		k2 != audit.KindEvent || !strings.Contains(s2, "tools/list") ||
		k3 != audit.KindCheckpoint || !strings.Contains(s3, "k1") ||
		k4 != audit.KindAnchor || !strings.Contains(s4, "5") ||
		k5 != audit.KindKeyRotation || !strings.Contains(s5, "k2") ||
		k6 != "unknown" {
		t.Fatalf("unexpected classifyAuditBody outputs: %q %q %q %q %q %q", k1, k2, k3, k4, k5, k6)
	}

	evView := &auditEventView{
		Kind:  audit.KindEvent,
		Event: &audit.Event{Decision: "allow", Phase: "call", Tenant: "acme", Subject: "alice", Tool: "svc__read"},
		Raw:   json.RawMessage(`{"tool":"svc__read"}`),
	}
	if !matchesAuditFilter(
		evView,
		auditEventFilter{
			kind:     "event",
			decision: "allow",
			phase:    "call",
			tenant:   "ac",
			sub:      "ali",
			tool:     "read",
			query:    "svc__read",
		},
	) {
		t.Fatal("expected matching audit filter")
	}
	if matchesAuditFilter(evView, auditEventFilter{decision: "deny"}) ||
		matchesAuditFilter(evView, auditEventFilter{phase: "result"}) ||
		matchesAuditFilter(evView, auditEventFilter{tenant: "other"}) ||
		matchesAuditFilter(evView, auditEventFilter{sub: "bob"}) ||
		matchesAuditFilter(evView, auditEventFilter{tool: "write"}) ||
		matchesAuditFilter(evView, auditEventFilter{query: "nomatch"}) ||
		matchesAuditFilter(&auditEventView{Kind: audit.KindCheckpoint}, auditEventFilter{decision: "allow"}) {
		t.Fatal("expected non-matching audit filters to return false")
	}

	events, scanned, err := readRecentAuditEvents(filepath.Join(dir, "nonexistent.jsonl"), auditEventFilter{limit: 10})
	if err != nil || len(events) != 0 || scanned != 0 {
		t.Fatalf("readRecentAuditEvents missing file: len=%d scanned=%d err=%v", len(events), scanned, err)
	}

	reqAudit := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit/events?limit=10", http.NoBody)
	reqAudit.Header.Set("Authorization", authHeader)
	recAudit := httptest.NewRecorder()
	h.ServeHTTP(recAudit, reqAudit)
	if recAudit.Code != http.StatusOK {
		t.Fatalf("GET /api/audit/events = %d", recAudit.Code)
	}
}
