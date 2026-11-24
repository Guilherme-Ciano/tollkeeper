package app

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestAdminV16OverviewAndSimulateApprovalMetadata(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.AdminListen = "127.0.0.1:0"
	cfg.Server.PublicURL = "http://127.0.0.1:8080/mcp"
	cfg.Server.StampProvenance = true
	cfg.Server.TasksEnabled = true
	cfg.Auth.Mode = config.AuthModeNone
	cfg.Audit.Enabled = false
	cfg.Idempotency.Enabled = true
	cfg.Idempotency.Mode = config.IdempotencyModeRequired
	cfg.Upstreams = []config.Upstream{
		{
			ID:             "files",
			Transport:      config.TransportStreamable,
			URL:            "http://127.0.0.1:19999/mcp",
			Timeout:        cfg.Server.ShutdownTimeout,
			MaxConcurrency: 4,
			Breaker:        config.Breaker{Failures: 5, OpenFor: cfg.Server.ShutdownTimeout},
		},
	}
	cfg.Policy = config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:   "four-eyes-delete",
				Tools:  []string{"files__delete"},
				When:   `tool.impact == "destructive" && approval.verified && approval.approver != principal.sub`,
				Effect: config.EffectAllow,
				OnDeny: config.OnDeny{
					RequireApproval: true,
					ApprovalReason:  "Needs human approval",
				},
			},
		},
	}
	a, err := Build(t.Context(), cfg, slog.New(slog.DiscardHandler), "v1.6.0-test")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	h := a.adminHandler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/overview", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status %d: %s", rec.Code, rec.Body.String())
	}
	var ov overviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if !ov.StampProvenance || !ov.TasksEnabled || !ov.Idempotency.Enabled ||
		ov.Idempotency.Mode != config.IdempotencyModeRequired {
		t.Fatalf("unexpected v1.6 overview fields: %+v", ov)
	}

	simNoApproval := `{"kind":"tool","name":"files__delete","principal":{"sub":"alice"},"metadata":{"impact":"destructive"}}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/api/simulate",
		bytes.NewBufferString(simNoApproval),
	)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("simulate 1 status %d: %s", rec.Code, rec.Body.String())
	}
	var sr1 simulateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sr1); err != nil {
		t.Fatal(err)
	}
	if sr1.Decision != "step_up" || sr1.StepUp == nil || !sr1.StepUp.RequireApproval {
		t.Fatalf("expected require_approval challenge, got %+v", sr1)
	}

	simApproved := `{"kind":"tool","name":"files__delete","principal":{"sub":"alice"},"metadata":{"impact":"destructive"},"approval":{"verified":true,"id":"apr_1","approver":"bob@corp.com"}}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/api/simulate",
		bytes.NewBufferString(simApproved),
	)
	h.ServeHTTP(rec, req)
	var sr2 simulateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sr2); err != nil {
		t.Fatal(err)
	}
	if sr2.Decision != "allow" || sr2.Rule != "four-eyes-delete" {
		t.Fatalf("expected four-eyes allow, got %+v", sr2)
	}
}
