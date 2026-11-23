package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func adminReq(
	t *testing.T,
	method, url, bearer string,
	body []byte,
) (status int, headers http.Header, respBody []byte) {
	t.Helper()
	var rdr io.Reader = http.NoBody
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, data
}

func TestAdminDashboardOverviewPolicySimulatePinsAndAudit(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})
	cfg := testConfig(t, up.URL)
	cfg.Pinning.Mode = config.PinModeWarn
	cfg.Policy = config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:     "allow-echo-reader",
				Subjects: config.Subjects{ScopesAny: []string{"mcp:tools"}},
				Tools:    []string{"fake__echo"},
				Effect:   config.EffectAllow,
			},
			{
				Name:   "secret-needs-step-up",
				Tools:  []string{"fake__secret"},
				Effect: config.EffectAllow,
				OnDeny: config.OnDeny{
					StepUpScopes: []string{"files:write"},
					ACRValues:    []string{"phr"},
					MaxAge:       5 * time.Minute,
				},
			},
		},
	}
	a := runApp(t, cfg)
	base := "http://" + a.Addr("admin")

	status, hdr, body := adminReq(t, http.MethodGet, base+"/ui/", "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /ui/ = %d, want 200", status)
	}
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("missing strict CSP on /ui/: %q", hdr.Get("Content-Security-Policy"))
	}
	if !strings.Contains(string(body), "tollkeeper") {
		t.Fatalf("unexpected /ui/ body")
	}

	status, _, body = adminReq(t, http.MethodGet, base+"/api/overview", "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/overview = %d: %s", status, body)
	}
	var ov map[string]any
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatal(err)
	}
	if ov["ready"] != true {
		t.Fatalf("overview ready = %v, want true", ov["ready"])
	}

	status, _, body = adminReq(t, http.MethodGet, base+"/api/policy", "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/policy = %d: %s", status, body)
	}
	var polResp struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(body, &polResp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(polResp.YAML, "allow-echo-reader") {
		t.Fatalf("policy yaml missing rule: %s", polResp.YAML)
	}

	valPayload, err := json.Marshal(map[string]any{"yaml": polResp.YAML})
	if err != nil {
		t.Fatal(err)
	}
	status, _, body = adminReq(t, http.MethodPost, base+"/api/policy/validate", "", valPayload)
	if status != http.StatusOK {
		t.Fatalf("POST /api/policy/validate = %d: %s", status, body)
	}
	var valRes struct {
		Valid bool     `json:"valid"`
		Rules int      `json:"rules"`
		Errs  []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &valRes); err != nil {
		t.Fatal(err)
	}
	if !valRes.Valid || valRes.Rules != 2 {
		t.Fatalf("expected valid=true rules=2, got %+v", valRes)
	}

	badPayload, err := json.Marshal(map[string]any{
		"yaml": "policy:\n  default: deny\n  rules:\n    - name: bad\n      tools: ['*']\n      when: 'not_a_var == 1'\n      effect: allow\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _, body = adminReq(t, http.MethodPost, base+"/api/policy/validate", "", badPayload)
	if status != http.StatusOK {
		t.Fatalf("POST /api/policy/validate bad = %d", status)
	}
	valRes = struct {
		Valid bool     `json:"valid"`
		Rules int      `json:"rules"`
		Errs  []string `json:"errors"`
	}{}
	if err := json.Unmarshal(body, &valRes); err != nil {
		t.Fatal(err)
	}
	if valRes.Valid || len(valRes.Errs) == 0 {
		t.Fatalf("expected invalid CEL result, got %+v", valRes)
	}

	status, _, body = adminReq(t, http.MethodGet, base+"/api/pins", "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/pins = %d: %s", status, body)
	}
	if !strings.Contains(string(body), "fake__echo") {
		t.Fatalf("expected synced tool in /api/pins: %s", body)
	}

	simAllow, err := json.Marshal(map[string]any{
		"kind": "tool",
		"name": "fake__echo",
		"principal": map[string]any{
			"sub":    "alice",
			"scopes": []string{"mcp:tools"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _, body = adminReq(t, http.MethodPost, base+"/api/simulate", "", simAllow)
	if status != http.StatusOK {
		t.Fatalf("POST /api/simulate allow = %d: %s", status, body)
	}
	var simRes struct {
		Decision       string            `json:"decision"`
		Rule           string            `json:"rule"`
		Visible        bool              `json:"visible"`
		CatalogMatched bool              `json:"catalog_matched"`
		Steps          []simulateStepDTO `json:"steps"`
		StepUp         map[string]any    `json:"step_up"`
	}
	if err := json.Unmarshal(body, &simRes); err != nil {
		t.Fatal(err)
	}
	if simRes.Decision != "allow" || simRes.Rule != "allow-echo-reader" || !simRes.Visible || !simRes.CatalogMatched ||
		len(simRes.Steps) == 0 {
		t.Fatalf("unexpected allow simulation: %+v", simRes)
	}

	simStepUp, err := json.Marshal(map[string]any{
		"kind": "tool",
		"name": "fake__secret",
		"principal": map[string]any{
			"sub":              "alice",
			"scopes":           []string{"mcp:tools"},
			"acr":              "pwd",
			"auth_age_seconds": 3600,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _, body = adminReq(t, http.MethodPost, base+"/api/simulate", "", simStepUp)
	if status != http.StatusOK {
		t.Fatalf("POST /api/simulate step_up = %d: %s", status, body)
	}
	simRes = struct {
		Decision       string            `json:"decision"`
		Rule           string            `json:"rule"`
		Visible        bool              `json:"visible"`
		CatalogMatched bool              `json:"catalog_matched"`
		Steps          []simulateStepDTO `json:"steps"`
		StepUp         map[string]any    `json:"step_up"`
	}{}
	if err := json.Unmarshal(body, &simRes); err != nil {
		t.Fatal(err)
	}
	if simRes.Decision != "step_up" || simRes.StepUp == nil {
		t.Fatalf("expected step_up decision with challenge, got %+v", simRes)
	}

	simDraft, err := json.Marshal(map[string]any{
		"kind": "tool",
		"name": "fake__echo",
		"principal": map[string]any{
			"sub":    "alice",
			"scopes": []string{"mcp:tools"},
		},
		"policy_yaml": "policy:\n  default: deny\n  rules:\n    - name: deny-all-draft\n      tools: ['*']\n      effect: deny\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _, body = adminReq(t, http.MethodPost, base+"/api/simulate", "", simDraft)
	if status != http.StatusOK {
		t.Fatalf("POST /api/simulate draft = %d: %s", status, body)
	}
	simRes = struct {
		Decision       string            `json:"decision"`
		Rule           string            `json:"rule"`
		Visible        bool              `json:"visible"`
		CatalogMatched bool              `json:"catalog_matched"`
		Steps          []simulateStepDTO `json:"steps"`
		StepUp         map[string]any    `json:"step_up"`
	}{}
	if err := json.Unmarshal(body, &simRes); err != nil {
		t.Fatal(err)
	}
	if simRes.Decision != "deny" || simRes.Rule != "deny-all-draft" {
		t.Fatalf("expected draft policy override to deny, got %+v", simRes)
	}

	if err := a.auditLog.Append(t.Context(), audit.Event{
		Phase:     audit.PhaseDecision,
		RequestID: "req-sim-1",
		Subject:   "alice",
		Tenant:    "acme",
		Method:    "tools/call",
		Tool:      "fake__secret",
		Decision:  audit.DecisionDeny,
		Rule:      "deny-secret",
	}); err != nil {
		t.Fatal(err)
	}

	status, _, body = adminReq(t, http.MethodGet, base+"/api/audit/events?decision=deny&tenant=acme&sub=alice", "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/audit/events = %d: %s", status, body)
	}
	var auditRes struct {
		Enabled bool             `json:"enabled"`
		Events  []auditEventView `json:"events"`
	}
	if err := json.Unmarshal(body, &auditRes); err != nil {
		t.Fatal(err)
	}
	if !auditRes.Enabled || len(auditRes.Events) == 0 || auditRes.Events[0].Event == nil ||
		auditRes.Events[0].Event.Tool != "fake__secret" {
		t.Fatalf("expected filtered audit event for fake__secret, got %+v", auditRes)
	}
}

func TestAdminAPIAuthEnforcement(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})

	t.Run("bearer token required when report_token set", func(t *testing.T) {
		cfg := testConfig(t, up.URL)
		cfg.Pinning.ReportToken = "top-secret-token"
		a := runApp(t, cfg)
		base := "http://" + a.Addr("admin")

		st, _, _ := adminReq(t, http.MethodGet, base+"/api/overview", "", nil)
		if st != http.StatusUnauthorized {
			t.Fatalf("missing token = %d, want 401", st)
		}
		st, _, _ = adminReq(t, http.MethodGet, base+"/api/overview", "wrong", nil)
		if st != http.StatusUnauthorized {
			t.Fatalf("wrong token = %d, want 401", st)
		}
		st, _, _ = adminReq(t, http.MethodGet, base+"/api/overview", "top-secret-token", nil)
		if st != http.StatusOK {
			t.Fatalf("valid token = %d, want 200", st)
		}
	})

	t.Run("non-loopback without token hides ui and api", func(t *testing.T) {
		cfg := testConfig(t, up.URL)
		cfg.Server.AdminListen = "0.0.0.0:9090"
		cfg.Pinning.ReportToken = ""
		a, err := Build(t.Context(), cfg, slog.New(slog.DiscardHandler), "test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if cerr := a.close(t.Context()); cerr != nil {
				t.Errorf("close: %v", cerr)
			}
		})
		h := a.adminHandler()
		for _, path := range []string{"/ui/", "/api/overview", "/api/policy", "/api/audit/events"} {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s on non-loopback without token = %d, want 404", path, rec.Code)
			}
		}
	})
}
