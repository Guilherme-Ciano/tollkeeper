package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Guilherme-Ciano/tollkeeper/internal/approval"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type failingIdemStore struct{}

func (failingIdemStore) Claim(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("backend down")
}

type failingReplayStore struct{}

func (failingReplayStore) Consume(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("replay backend down")
}

func TestIdempotencyStoreEvictionJanitorAndErrorPaths(t *testing.T) {
	t.Parallel()
	clock := time.Unix(1_700_000_000, 0)
	store := NewMemoryIdempotencyStore(100, func() time.Time { return clock })
	for i := range 105 {
		clock = clock.Add(time.Millisecond)
		ok, err := store.Claim(t.Context(), "k-"+strconv.Itoa(i), time.Hour)
		if err != nil || !ok {
			t.Fatalf("claim %d: ok=%v err=%v", i, ok, err)
		}
	}
	if len(store.entries) > 100 {
		t.Fatalf("expected bounded entries <= 100, got %d", len(store.entries))
	}
	clock = clock.Add(2 * time.Hour)
	if swept := store.Sweep(); swept == 0 {
		t.Fatal("expected Sweep to remove expired entries")
	}

	jctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		store.RunJanitor(jctx, 5*time.Millisecond)
		close(done)
	}()
	time.Sleep(15 * time.Millisecond)
	cancel()
	<-done

	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond, MaxRetries: 0})
	t.Cleanup(func() {
		if err := dead.Close(); err != nil {
			t.Errorf("close dead redis: %v", err)
		}
	})
	rstore := NewRedisIdempotencyStore(dead, "", 0)
	if _, err := rstore.Claim(t.Context(), "k", time.Minute); err == nil {
		t.Fatal("expected error from dead redis")
	}

	tools := []catalog.Tool{
		{
			Name:       "files__delete",
			Upstream:   "files",
			Original:   "delete",
			Pin:        "p1",
			Descriptor: makeToolDescriptor(t, "files__delete"),
		},
	}
	allowAll := []config.Rule{{Name: "allow", Tools: []string{"*"}, Effect: config.EffectAllow}}

	cfg := config.Defaults()
	cfg.Idempotency.Enabled = true
	cfg.Idempotency.Mode = config.IdempotencyModeHeader
	cfg.Idempotency.TTL = time.Minute
	_, _, srv := buildV16Gateway(t, cfg, allowAll, tools, nil, failingIdemStore{})

	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files__delete","arguments":{}}}`
	st, body := sendWithHeaders(
		t,
		srv.URL+"/mcp",
		callBody,
		map[string]string{"Idempotency-Key": strings.Repeat("x", maxIdempotencyKeyLen+5)},
	)
	if st != http.StatusBadRequest || !strings.Contains(body, `"code":-32602`) {
		t.Fatalf("oversized key should return 400/-32602, got %d %s", st, body)
	}
	st, body = sendWithHeaders(t, srv.URL+"/mcp", callBody, map[string]string{"Idempotency-Key": "ok-key"})
	if st != http.StatusServiceUnavailable || !strings.Contains(body, "idempotency store unavailable") {
		t.Fatalf("store error should fail closed with 503, got %d %s", st, body)
	}
}

func TestApprovalErrorLabelsAndReplayStoreFailure(t *testing.T) {
	t.Parallel()
	if approvalErrorLabel(approval.ErrExpired) != "expired" ||
		approvalErrorLabel(approval.ErrTTLTooLong) != "expired" ||
		approvalErrorLabel(approval.ErrSubjectMismatch) != "mismatch" ||
		approvalErrorLabel(approval.ErrInvalidSignature) != "invalid" {
		t.Fatal("unexpected approvalErrorLabel mapping")
	}

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
	cfg.Approvals.MaxTTL = 2 * time.Minute
	cfg.Approvals.SingleUse = true
	cfg.Audit.Enabled = false

	pol, err := policy.New(config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:   "req-approval",
				Tools:  []string{"files__delete"},
				Effect: config.EffectAllow,
				OnDeny: config.OnDeny{RequireApproval: true},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(clock))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(8)
	g := New(Deps{
		Config:     cfg,
		Verifier:   staticSubjectVerifier{sub: "alice", tenant: "acme"},
		Policy:     pol,
		Limiter:    lim,
		Catalog:    cat,
		Upstreams:  map[string]Caller{"files": &approvalTestCaller{}},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     noop.NewTracerProvider().Tracer("t"),
		Propagator: propagation.TraceContext{},
		Log:        slog.New(slog.DiscardHandler),
		Now:        clock,
		Approvals: approval.NewVerifier(
			approval.VerifierOptions{
				Keys:     ks,
				Audience: "https://gw.example.com/mcp",
				MaxTTL:   2 * time.Minute,
				Now:      clock,
			},
		),
		ApprovalReplay: failingReplayStore{},
	})
	d, err := cat.Replace("files", []catalog.Tool{
		{
			Name:       "files__delete",
			Upstream:   "files",
			Original:   "delete",
			Pin:        "p1",
			Descriptor: makeToolDescriptor(t, "files__delete"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(d)
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)

	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files__delete","arguments":{}}}`
	st, body := sendApprovalCall(t, srv.URL+"/mcp", callBody, "")
	if st != http.StatusForbidden || !strings.Contains(body, `"ttl_s":120`) ||
		!strings.Contains(body, `"tenant":"acme"`) {
		t.Fatalf("expected capped ttl_s=120 and tenant=acme in challenge, got %d %s", st, body)
	}

	tok, err := approval.Sign(priv, approval.Claims{
		Audience:  "https://gw.example.com/mcp",
		Subject:   "alice",
		Tenant:    "acme",
		Approver:  "bob@corp.com",
		Tool:      "files__delete",
		ArgsHash:  approval.CanonicalArgsHash(nil),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	st, body = sendApprovalCall(t, srv.URL+"/mcp", callBody, tok)
	if st != http.StatusServiceUnavailable || !strings.Contains(body, "approval replay store unavailable") {
		t.Fatalf("expected 503 on failing replay store, got %d %s", st, body)
	}
}

type errorTaskUpstream struct {
	err    error
	result json.RawMessage
}

func (e errorTaskUpstream) CallTool(context.Context, upstream.Call) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{}, nil
}

func (e errorTaskUpstream) CallTaskTool(context.Context, upstream.Call) (json.RawMessage, error) {
	return e.result, e.err
}

func (e errorTaskUpstream) TaskRPC(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	return e.result, e.err
}

func TestTasksEdgeCasesSyncStateAndErrors(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return now }

	disabledCfg := config.Defaults()
	disabledCfg.Server.PublicURL = "http://127.0.0.1/mcp"
	disabledCfg.Server.TasksEnabled = false
	disabledCfg.Auth.Mode = config.AuthModeNone
	disabledCfg.Audit.Enabled = false
	pol, err := policy.New(config.Policy{
		Default: config.EffectAllow,
		Rules:   []config.Rule{{Name: "allow", Tools: []string{"*"}, Effect: config.EffectAllow}},
	})
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ratelimit.New(config.RateLimits{}, ratelimit.NewStore(clock))
	if err != nil {
		t.Fatal(err)
	}
	gDisabled := New(Deps{
		Config: disabledCfg, Policy: pol, Limiter: lim, Catalog: catalog.New(4),
		Upstreams: map[string]Caller{}, Metrics: telemetry.NewMetrics(),
		Tracer: noop.NewTracerProvider().Tracer("t"), Propagator: propagation.TraceContext{},
		Log: slog.New(slog.DiscardHandler), Now: clock,
	})
	srvDis := httptest.NewServer(gDisabled.Handler())
	t.Cleanup(srvDis.Close)

	st, body := postTaskRPC(
		t,
		srvDis.URL+"/mcp",
		"alice",
		`{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"taskId":"tkt1.x"}}`,
	)
	if st != http.StatusNotFound || !strings.Contains(body, `"code":-32601`) {
		t.Fatalf("disabled tasks should return 404/-32601, got %d %s", st, body)
	}

	cfg := config.Defaults()
	cfg.Server.PublicURL = "http://127.0.0.1/mcp"
	cfg.Server.TasksEnabled = true
	cfg.Server.StampProvenance = true
	cfg.Auth.Mode = config.AuthModeNone
	cfg.Audit.Enabled = true
	auditor := &approvalRecordingAuditor{}
	cat := catalog.New(8)
	g := New(Deps{
		Config:  cfg,
		Policy:  pol,
		Limiter: lim,
		Audit:   auditor,
		Catalog: cat,
		Upstreams: map[string]Caller{
			"syncup": errorTaskUpstream{
				result: json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"requestState":"inner-rs"}`),
			},
			"errup":  errorTaskUpstream{err: &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "bad task"}},
			"downup": errorTaskUpstream{err: upstream.ErrUnavailable},
		},
		Metrics:    telemetry.NewMetrics(),
		Tracer:     noop.NewTracerProvider().Tracer("t"),
		Propagator: propagation.TraceContext{},
		Log:        slog.New(slog.DiscardHandler),
		Now:        clock,
		StateKey:   []byte("0123456789abcdef0123456789abcdef"),
	})
	for _, uid := range []string{"syncup", "errup", "downup"} {
		d, rerr := cat.Replace(uid, []catalog.Tool{
			{
				Name:       uid + "__op",
				Upstream:   uid,
				Original:   "op",
				Pin:        "p1",
				Descriptor: makeToolDescriptor(t, uid+"__op"),
			},
		})
		if rerr != nil {
			t.Fatal(rerr)
		}
		g.Apply(d)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)

	st, body = postTaskRPC(t, srv.URL+"/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{}}`)
	if st != http.StatusBadRequest || !strings.Contains(body, "missing taskId") {
		t.Fatalf("missing taskId should fail with 400, got %d %s", st, body)
	}

	taskMeta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`
	st, body = postTaskRPC(
		t,
		srv.URL+"/mcp",
		"",
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"syncup__op","arguments":{},`+taskMeta+`}}`,
	)
	if st != http.StatusOK || !strings.Contains(body, `"tollkeeper.provenance"`) || !strings.Contains(body, `"tk1.`) {
		t.Fatalf("sync task-capable call should seal requestState and stamp provenance, got %d %s", st, body)
	}

	st, body = postTaskRPC(
		t,
		srv.URL+"/mcp",
		"",
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"syncup__op","arguments":{},"requestState":"bad-token",`+taskMeta+`}}`,
	)
	if st != http.StatusBadRequest || !strings.Contains(body, `"code":-32602`) {
		t.Fatalf("bad requestState in task call should return 400/-32602, got %d %s", st, body)
	}

	st, body = postTaskRPC(
		t,
		srv.URL+"/mcp",
		"",
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"errup__op","arguments":{},`+taskMeta+`}}`,
	)
	if st != http.StatusBadRequest || !strings.Contains(body, `"code":-32602`) {
		t.Fatalf("jsonrpc invalid params should map to 400/-32602, got %d %s", st, body)
	}

	st, body = postTaskRPC(
		t,
		srv.URL+"/mcp",
		"",
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"downup__op","arguments":{},`+taskMeta+`}}`,
	)
	if st != http.StatusBadGateway || !strings.Contains(body, `"code":-32004`) {
		t.Fatalf("upstream unavailable should map to 502/-32004, got %d %s", st, body)
	}
	if len(auditor.snapshot()) == 0 {
		t.Fatal("expected audit events recorded for task calls")
	}
}
