package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/approval"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type approvalRecordingAuditor struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *approvalRecordingAuditor) Append(_ context.Context, e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *approvalRecordingAuditor) snapshot() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]audit.Event, len(a.events))
	copy(out, a.events)
	return out
}

type approvalTestCaller struct {
	calls atomic.Int64
}

func (c *approvalTestCaller) CallTool(_ context.Context, _ upstream.Call) (*mcp.CallToolResult, error) {
	c.calls.Add(1)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deleted"}}}, nil
}

type staticSubjectVerifier struct {
	sub    string
	tenant string
}

func (v staticSubjectVerifier) Verify(_ context.Context, _ string) (identity.Principal, error) {
	return identity.Principal{Subject: v.sub, Tenant: v.tenant, Scopes: []string{"mcp:tools"}}, nil
}

func sendApprovalCall(t *testing.T, url, body, approvalToken string) (status int, respBody string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer dummy")
	if approvalToken != "" {
		req.Header.Set(approval.DefaultHeader, approvalToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func TestStatelessApprovalTokensEndToEnd(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := approval.NewKeySet(pub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return now }

	cfg := config.Defaults()
	cfg.Server.PublicURL = "https://gw.example.com/mcp"
	cfg.Auth.Mode = config.AuthModeJWT
	cfg.Auth.Resource = "https://gw.example.com/mcp"
	cfg.Approvals.Enabled = true
	cfg.Approvals.Header = approval.DefaultHeader
	cfg.Approvals.SingleUse = true
	cfg.Approvals.MaxTTL = 10 * time.Minute
	cfg.Audit.Enabled = true

	rules := []config.Rule{
		{
			Name:   "delete-requires-four-eyes-approval",
			Tools:  []string{"files__delete_file"},
			When:   `approval.verified && approval.approver != principal.sub`,
			Effect: config.EffectAllow,
			OnDeny: config.OnDeny{
				RequireApproval: true,
				ApprovalTTL:     5 * time.Minute,
				ApprovalReason:  "Deleting files requires independent human approval",
			},
		},
	}
	pol, err := policy.New(config.Policy{Default: config.EffectDeny, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(clock))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(16)
	caller := &approvalTestCaller{}
	auditor := &approvalRecordingAuditor{}
	m := telemetry.NewMetrics()
	g := New(Deps{
		Config:     cfg,
		Verifier:   staticSubjectVerifier{sub: "alice", tenant: "acme"},
		Policy:     pol,
		Limiter:    lim,
		Audit:      auditor,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"files": caller},
		Metrics:    m,
		Tracer:     noop.NewTracerProvider().Tracer("t"),
		Propagator: propagation.TraceContext{},
		Log:        slog.New(slog.DiscardHandler),
		Now:        clock,
		Approvals: approval.NewVerifier(approval.VerifierOptions{
			Keys:     ks,
			Audience: "https://gw.example.com/mcp",
			MaxTTL:   10 * time.Minute,
			Now:      clock,
		}),
	})
	desc, err := json.Marshal(&mcp.Tool{Name: "files__delete_file", InputSchema: map[string]any{"type": "object"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := cat.Replace("files", []catalog.Tool{
		{Name: "files__delete_file", Upstream: "files", Original: "delete_file", Pin: "p1", Descriptor: desc},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(d)
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)

	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files__delete_file","arguments":{"path":"/important"}}}`

	st, body := sendApprovalCall(t, srv.URL+"/mcp", callBody, "")
	if st != http.StatusForbidden || !strings.Contains(body, `"code":-32010`) ||
		!strings.Contains(body, `"approval_required":true`) {
		t.Fatalf("expected 403/-32010 approval challenge, got %d %s", st, body)
	}
	expectedHash := approval.CanonicalArgsHash(json.RawMessage(`{"path":"/important"}`))
	if !strings.Contains(body, expectedHash) {
		t.Fatalf("approval challenge missing canonical args_hash %s: %s", expectedHash, body)
	}

	selfTok, err := approval.Sign(priv, approval.Claims{
		Audience:  "https://gw.example.com/mcp",
		Subject:   "alice",
		Tenant:    "acme",
		Approver:  "alice",
		Tool:      "files__delete_file",
		ArgsHash:  expectedHash,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	st, body = sendApprovalCall(t, srv.URL+"/mcp", callBody, selfTok)
	if st != http.StatusOK || !strings.Contains(body, `"code":-32001`) {
		t.Fatalf("self-approval should violate four-eyes CEL and be denied, got %d %s", st, body)
	}

	goodTok, err := approval.Sign(priv, approval.Claims{
		JTI:       "apr_ticket_99",
		Audience:  "https://gw.example.com/mcp",
		Subject:   "alice",
		Tenant:    "acme",
		Approver:  "bob@corp.com",
		Tool:      "files__delete_file",
		ArgsHash:  expectedHash,
		Reason:    "INC-99",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	tamperedBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files__delete_file","arguments":{"path":"/etc/passwd"}}}`
	st, body = sendApprovalCall(t, srv.URL+"/mcp", tamperedBody, goodTok)
	if st != http.StatusForbidden || !strings.Contains(body, `"code":-32010`) {
		t.Fatalf("tampered arguments must fail approval verification, got %d %s", st, body)
	}

	st, body = sendApprovalCall(t, srv.URL+"/mcp", callBody, goodTok)
	if st != http.StatusOK || strings.Contains(body, `"error"`) {
		t.Fatalf("valid independent approval should allow call, got %d %s", st, body)
	}

	st, body = sendApprovalCall(t, srv.URL+"/mcp", callBody, goodTok)
	if st != http.StatusConflict || !strings.Contains(body, `"code":-32011`) {
		t.Fatalf("replaying single-use approval should return 409/-32011, got %d %s", st, body)
	}

	if caller.calls.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", caller.calls.Load())
	}

	foundAudit := false
	for _, ev := range auditor.snapshot() {
		if ev.Phase == audit.PhaseIntent && ev.ApprovedBy == "bob@corp.com" && ev.ApprovalID == "apr_ticket_99" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("expected audit intent event with approved_by=bob@corp.com and approval_id=apr_ticket_99")
	}

	batchTok, err := approval.Sign(priv, approval.Claims{
		JTI:      "apr_batch_1",
		Audience: "https://gw.example.com/mcp",
		Subject:  "alice",
		Tenant:   "acme",
		Approver: "bob@corp.com",
		Batch: []approval.BatchItem{
			{Tool: "files__delete_file", ArgsHash: approval.CanonicalArgsHash(json.RawMessage(`{"path":"/tmp/1"}`))},
			{Tool: "files__delete_file", ArgsHash: approval.CanonicalArgsHash(json.RawMessage(`{"path":"/tmp/2"}`))},
		},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b1 := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files__delete_file","arguments":{"path":"/tmp/1"}}}`
	b2 := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"files__delete_file","arguments":{"path":"/tmp/2"}}}`
	if st, _ = sendApprovalCall(t, srv.URL+"/mcp", b1, batchTok); st != http.StatusOK {
		t.Fatalf("batch item 1 failed: %d", st)
	}
	if st, _ = sendApprovalCall(t, srv.URL+"/mcp", b2, batchTok); st != http.StatusOK {
		t.Fatalf("batch item 2 failed: %d", st)
	}
	if st, _ = sendApprovalCall(t, srv.URL+"/mcp", b1, batchTok); st != http.StatusConflict {
		t.Fatalf("replaying batch item 1 should return 409, got %d", st)
	}
	if caller.calls.Load() != 3 {
		t.Fatalf("expected 3 total upstream calls, got %d", caller.calls.Load())
	}
}
