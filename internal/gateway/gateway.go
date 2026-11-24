package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/Guilherme-Ciano/tollkeeper/internal/approval"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/pin"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

var (
	ErrNoAdmission = errors.New("call reached the server without admission")
	ErrUnknownTool = errors.New("unknown tool")
)

type Auditor interface {
	Append(ctx context.Context, e audit.Event) error
}

type Caller interface {
	CallTool(ctx context.Context, c upstream.Call) (*mcp.CallToolResult, error)
}

type Deps struct {
	Config         config.Config
	Verifier       TokenVerifier
	DPoP           *authn.DPoPVerifier
	Policy         *policy.Engine
	Limiter        *ratelimit.Limiter
	Audit          Auditor
	Catalog        *catalog.Catalog
	Directory      *catalog.Directory
	Upstreams      map[string]Caller
	Metrics        *telemetry.Metrics
	Tracer         trace.Tracer
	Propagator     propagation.TextMapPropagator
	Log            *slog.Logger
	Version        string
	Now            func() time.Time
	Pins           PinGuard
	Idempotency    IdempotencyStore
	Approvals      *approval.Verifier
	ApprovalReplay approval.ReplayStore
	StateKey       []byte
}

type PinGuard interface {
	Mode() pin.Mode
	Status(t catalog.Tool) pin.Status
	Blocks(t catalog.Tool) bool
}

type Gateway struct {
	server         *mcp.Server
	verifier       TokenVerifier
	dpop           *authn.DPoPVerifier
	dpopMode       string
	authDisabled   bool
	requiredScopes []string
	challenge      challenge
	policy         atomic.Pointer[policy.Engine]
	limiter        atomic.Pointer[ratelimit.Limiter]
	audit          Auditor
	catalog        *catalog.Catalog
	directory      *catalog.Directory
	upstreams      map[string]Caller
	metrics        *telemetry.Metrics
	tracer         trace.Tracer
	propagator     propagation.TextMapPropagator
	log            *slog.Logger
	now            func() time.Time
	maxBody        int64
	recordArgs     string
	cfg            config.Config
	prm            *oauthex.ProtectedResourceMetadata
	prmPath        string

	pins           PinGuard
	idempotency    IdempotencyStore
	approvals      *approval.Verifier
	approvalReplay approval.ReplayStore
	fastDisabled   bool
	impl           *mcp.Implementation
	states         *stateSealer
	tasks          *taskSealer
	infoPrefix     []byte
	hidden         atomic.Pointer[map[string]struct{}]

	notifyMu    sync.Mutex
	sentinel    string
	regMu       sync.Mutex
	quarantined map[string]string
	unapproved  map[string]pin.Status
}

func ResourceMetadataPath(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil {
		return "/.well-known/oauth-protected-resource"
	}
	return "/.well-known/oauth-protected-resource" + strings.TrimSuffix(u.Path, "/")
}

func ResourceMetadataURL(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + ResourceMetadataPath(publicURL)
}

func New(d Deps) *Gateway {
	if d.Now == nil {
		d.Now = time.Now
	}
	g := &Gateway{
		verifier:       d.Verifier,
		dpop:           d.DPoP,
		dpopMode:       d.Config.Auth.DPoP.Mode,
		authDisabled:   d.Config.Auth.Mode == config.AuthModeNone,
		requiredScopes: d.Config.Auth.RequiredScopes,
		audit:          d.Audit,
		catalog:        d.Catalog,
		directory:      d.Directory,
		upstreams:      d.Upstreams,
		metrics:        d.Metrics,
		tracer:         d.Tracer,
		propagator:     d.Propagator,
		log:            d.Log,
		now:            d.Now,
		maxBody:        d.Config.Server.MaxBodyBytes,
		recordArgs:     d.Config.Audit.RecordArgs,
		cfg:            d.Config,
		quarantined:    map[string]string{},
		unapproved:     map[string]pin.Status{},
		pins:           d.Pins,
		idempotency:    d.Idempotency,
		approvals:      d.Approvals,
		approvalReplay: d.ApprovalReplay,
		fastDisabled:   d.Config.Server.DisableFastPath,
	}
	if d.Config.Idempotency.Enabled && g.idempotency == nil {
		g.idempotency = NewMemoryIdempotencyStore(d.Config.Idempotency.MaxEntries, g.now)
	}
	if g.approvals != nil && d.Config.Approvals.SingleUse && g.approvalReplay == nil {
		g.approvalReplay = approval.NewMemoryReplayStore(d.Config.Approvals.MaxEntries, g.now)
	}
	if !d.Config.Audit.Enabled {
		g.recordArgs = config.RecordArgsNone
	}
	g.policy.Store(d.Policy)
	g.limiter.Store(d.Limiter)
	stateKey := d.StateKey
	if stateKey != nil && len(stateKey) < MinStateKeyLen {
		d.Log.Error("request state key too short, using an ephemeral key")
		stateKey = nil
	}
	states := newStateSealer(stateKey, d.Config.Server.RequestStateTTL)
	g.states = states
	g.tasks = newTaskSealer(stateKey, d.Config.Server.TaskTTL)
	g.sentinel = "tollkeeper-list-changed-" + strings.ToLower(rand.Text()[:10])
	if g.verifier == nil {
		g.verifier = anonymousVerifier{}
	}
	g.prmPath = ResourceMetadataPath(d.Config.Server.PublicURL)
	g.challenge = challenge{scopes: d.Config.Auth.RequiredScopes}
	if !g.authDisabled {
		g.challenge.resourceMetadata = ResourceMetadataURL(d.Config.Server.PublicURL)
		g.prm = &oauthex.ProtectedResourceMetadata{
			Resource:               d.Config.Auth.Resource,
			AuthorizationServers:   d.Config.Auth.AuthorizationServers,
			ScopesSupported:        d.Config.Auth.ScopesSupported,
			BearerMethodsSupported: []string{"header"},
			ResourceName:           "tollkeeper MCP gateway",
		}
		if g.dpop != nil && g.dpopMode != config.DPoPModeOff {
			g.prm.DPOPSigningAlgValuesSupported = g.dpop.Algorithms()
			g.prm.DPOPBoundAccessTokensRequired = g.dpopMode == config.DPoPModeRequired
		}
	}
	g.impl = &mcp.Implementation{Name: "tollkeeper", Version: d.Version}
	g.infoPrefix = serverInfoPrefix(g.impl)
	g.server = mcp.NewServer(g.impl, &mcp.ServerOptions{
		Capabilities: g.capabilities(),
		PageSize:     10000,
		SetCacheable: func(_ context.Context, _ mcp.Request, c *mcp.Cacheable) {
			c.CacheScope = "private"
			c.TTLMs = 0
		},
	})
	g.server.AddReceivingMiddleware(g.middleware)
	return g
}

func (g *Gateway) Server() *mcp.Server {
	return g.server
}

func (g *Gateway) Policy() *policy.Engine {
	return g.policy.Load()
}

func (g *Gateway) Handler() http.Handler {
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return g.server },
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			JSONResponse:                 true,
			PropagateRequestCancellation: true,
			MaxRequestBodyBytes:          g.maxBody,
			DisableLocalhostProtection:   g.cfg.Server.AllowLocalhostHost,
			Logger:                       g.log,
		},
	)
	mcpPath := "/mcp"
	if u, err := url.Parse(g.cfg.Server.PublicURL); err == nil && u.Path != "" && u.Path != "/" {
		mcpPath = u.Path
	}
	mux := http.NewServeMux()
	chain := g.recover(g.bearer(g.admission(mcpHandler)))
	mux.Handle(mcpPath, otelhttp.NewHandler(chain, "mcp", otelhttp.WithServerName("tollkeeper")))
	if g.prm != nil {
		prm := auth.ProtectedResourceMetadataHandler(g.prm)
		mux.Handle("GET "+g.prmPath, prm)
		mux.Handle("OPTIONS "+g.prmPath, prm)
		if g.prmPath != "/.well-known/oauth-protected-resource" {
			mux.Handle("GET /.well-known/oauth-protected-resource", prm)
		}
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok\n")); err != nil {
			g.log.DebugContext(r.Context(), "healthz write failed", slog.String("error", err.Error()))
		}
	})
	return mux
}

func (g *Gateway) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer g.handlePanic(r.Context(), w)
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) handlePanic(ctx context.Context, w http.ResponseWriter) {
	v := recover()
	if v == nil {
		return
	}
	if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
		panic(v)
	}
	g.log.ErrorContext(ctx, "panic in handler", slog.String("panic", fmt.Sprint(v)))
	writeRPCError(w, http.StatusInternalServerError, nil, CodeInternal, "internal error", nil)
}

func (g *Gateway) Apply(d catalog.Delta) {
	g.regMu.Lock()
	defer g.regMu.Unlock()
	g.applyLocked(d)
}

func (g *Gateway) applyLocked(d catalog.Delta) {
	live := g.catalog.Snapshot()
	for _, n := range d.Removed {
		if _, back := live.Lookup(n); back {
			continue
		}
		g.server.RemoveTools(n)
		delete(g.quarantined, n)
		delete(g.unapproved, n)
	}
	for i := range d.Upserted {
		current, ok := live.Lookup(d.Upserted[i].Name)
		if !ok {
			continue
		}
		t := &current
		if g.pinHides(t) {
			g.server.RemoveTools(t.Name)
			delete(g.quarantined, t.Name)
			continue
		}
		if err := g.addTool(t); err != nil {
			g.quarantined[t.Name] = err.Error()
			g.server.RemoveTools(t.Name)
			g.metrics.CatalogRejected.WithLabelValues(t.Upstream).Inc()
			g.log.Warn("tool quarantined", slog.String("tool", t.Name), slog.String("error", err.Error()))
			continue
		}
		delete(g.quarantined, t.Name)
	}
	g.publishHidden()
	g.publishCatalogGauges()
}

func (g *Gateway) publishHidden() {
	hidden := make(map[string]struct{}, len(g.quarantined)+len(g.unapproved))
	for n := range g.quarantined {
		hidden[n] = struct{}{}
	}
	if g.pins != nil && g.pins.Mode() == pin.ModeEnforce {
		for n := range g.unapproved {
			hidden[n] = struct{}{}
		}
	}
	g.hidden.Store(&hidden)
}

func (g *Gateway) registered(name string) bool {
	h := g.hidden.Load()
	if h == nil {
		return true
	}
	_, hiddenTool := (*h)[name]
	return !hiddenTool
}

func (g *Gateway) pinHides(t *catalog.Tool) bool {
	if g.pins == nil || g.pins.Mode() == pin.ModeOff {
		return false
	}
	status := g.pins.Status(*t)
	if status == pin.StatusApproved {
		delete(g.unapproved, t.Name)
		return false
	}
	blocked := g.pins.Mode() == pin.ModeEnforce
	if prev, seen := g.unapproved[t.Name]; !seen || prev != status {
		g.log.Warn("tool definition not approved",
			slog.String("tool", t.Name),
			slog.String("status", string(status)),
			slog.String("pin", t.Pin),
			slog.String("mode", string(g.pins.Mode())))
	}
	g.unapproved[t.Name] = status
	return blocked
}

func (g *Gateway) publishCatalogGauges() {
	hidden := len(g.quarantined)
	counts := map[pin.Status]int{pin.StatusNew: 0, pin.StatusChanged: 0}
	for _, s := range g.unapproved {
		counts[s]++
	}
	if g.pins != nil && g.pins.Mode() == pin.ModeEnforce {
		hidden += len(g.unapproved)
	}
	for s, n := range counts {
		g.metrics.PinUnapproved.WithLabelValues(string(s)).Set(float64(n))
	}
	g.metrics.CatalogTools.Set(float64(g.catalog.Snapshot().Len() - hidden))
}

func (g *Gateway) Reevaluate() {
	if g.pins == nil {
		return
	}
	g.regMu.Lock()
	defer g.regMu.Unlock()
	var d catalog.Delta
	tools := g.catalog.Snapshot().Tools()
	for i := range tools {
		t := tools[i]
		prev, wasUnapproved := g.unapproved[t.Name]
		now := g.pins.Status(t)
		if (now == pin.StatusApproved) == wasUnapproved || (wasUnapproved && prev != now) {
			d.Upserted = append(d.Upserted, t)
		}
	}
	if len(d.Upserted) > 0 {
		g.applyLocked(d)
	}
}

func (g *Gateway) unapprovedTools() map[string]pin.Status {
	g.regMu.Lock()
	defer g.regMu.Unlock()
	return maps.Clone(g.unapproved)
}

func (g *Gateway) pinBlocked(t catalog.Tool) bool {
	return g.pins != nil && g.pins.Blocks(t)
}

func (g *Gateway) Quarantined() map[string]string {
	g.regMu.Lock()
	defer g.regMu.Unlock()
	return maps.Clone(g.quarantined)
}

var errBadSchema = errors.New("tool input schema must be a JSON object schema with type object")

func (g *Gateway) addTool(t *catalog.Tool) (err error) {
	var mt mcp.Tool
	if err := json.Unmarshal(t.Descriptor, &mt); err != nil {
		return fmt.Errorf("decode tool %s: %w", t.Name, err)
	}
	mt.Name = t.Name
	schema, ok := mt.InputSchema.(map[string]any)
	if mt.InputSchema == nil {
		schema, ok = map[string]any{"type": schemaObject}, true
	}
	if !ok || schema["type"] != schemaObject {
		return errBadSchema
	}
	mt.InputSchema = schema
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("register tool %s: %v", t.Name, v)
		}
	}()
	g.server.AddTool(&mt, g.forward(t.Name))
	return nil
}

type metaCarrier map[string]any

func (m metaCarrier) Get(k string) string {
	s, ok := m[k].(string)
	if !ok {
		return ""
	}
	return s
}

func (m metaCarrier) Set(k, v string) {
	m[k] = v
}

func (m metaCarrier) Keys() []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

func (g *Gateway) forward(name string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		a, _ := AdmissionFrom(ctx)
		tool, ok := g.catalog.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownTool, name)
		}
		if a != nil && (a.Tool.Pin != tool.Pin || a.Tool.Upstream != tool.Upstream || g.pinBlocked(tool)) {
			return toolError("tool definition changed since the call was authorised; retry"), nil
		}
		up, ok := g.upstreams[tool.Upstream]
		if !ok {
			return nil, fmt.Errorf("%w: upstream %s", ErrUnknownTool, tool.Upstream)
		}
		var principal identity.Principal
		if a != nil {
			principal = a.Principal
		}
		inner, err := g.openState(req.Params.RequestState, tool, principal)
		if err != nil {
			g.log.WarnContext(ctx, "requestState rejected", slog.String("tool", name))
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}
		}
		res, err := g.callUpstream(ctx, a, up, tool, upstream.Call{
			Tool:           tool.Original,
			Arguments:      req.Params.Arguments,
			InputResponses: req.Params.InputResponses,
			RequestState:   inner,
			Progress:       progressFrom(ctx),
		})
		if err != nil {
			if pe := protocolError(err); pe != nil {
				return nil, pe
			}
			return toolError(upstreamMessage(err)), nil
		}
		return g.sealResult(res, tool, principal)
	}
}

func (g *Gateway) callUpstream(
	ctx context.Context,
	a *Admission,
	up Caller,
	tool catalog.Tool,
	call upstream.Call,
) (*mcp.CallToolResult, error) {
	call.Meta = map[string]any{}
	ctx, span := g.tracer.Start(
		ctx,
		"upstream.call "+tool.Upstream,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("mcp.upstream", tool.Upstream),
			attribute.String("gen_ai.tool.name", tool.Original),
		),
	)
	defer span.End()
	g.propagator.Inject(ctx, metaCarrier(call.Meta))
	if a != nil {
		if raw, present := a.Envelope.meta[metaClientCapabilities]; present && !isNull(raw) {
			call.Meta[metaClientCapabilities] = raw
		}
	}
	start := g.now()
	res, err := up.CallTool(ctx, call)
	elapsed := g.now().Sub(start)
	if a != nil {
		a.AddUpstream(elapsed)
	}
	g.metrics.UpstreamLatency.WithLabelValues(tool.Upstream).Observe(elapsed.Seconds())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "upstream call failed")
		g.log.WarnContext(ctx, "upstream call failed",
			slog.String("tool", tool.Name), slog.String("error", err.Error()))
		return nil, err
	}
	return res, nil
}

func (g *Gateway) sealResult(
	res *mcp.CallToolResult,
	tool catalog.Tool,
	p identity.Principal,
) (*mcp.CallToolResult, error) {
	if res != nil && g.cfg.Server.StampProvenance {
		stampProvenance(res, tool)
	}
	if res == nil || res.RequestState == "" {
		return res, nil
	}
	sealed, err := g.states.seal(statePayload{
		Upstream: tool.Upstream, Tool: tool.Original, Subject: p.Subject, ClientID: p.ClientID, Inner: res.RequestState,
	}, g.now())
	if err != nil {
		return nil, err
	}
	res.RequestState = sealed
	return res, nil
}

func stampProvenance(res *mcp.CallToolResult, tool catalog.Tool) {
	m := tool.ResolvedMetadata()
	meta := make(mcp.Meta, len(res.Meta)+1)
	maps.Copy(meta, res.Meta)
	meta["tollkeeper.provenance"] = map[string]any{
		"upstream":       tool.Upstream,
		keyTool:          tool.Name,
		"trust":          m.Trust,
		"classification": m.Classification,
		"egress":         m.Egress,
		"impact":         m.Impact,
		"pin_hash":       tool.Pin,
	}
	res.Meta = meta
}

func (g *Gateway) openState(token string, tool catalog.Tool, p identity.Principal) (string, error) {
	if token == "" {
		return "", nil
	}
	st, err := g.states.open(token, g.now())
	if err != nil {
		return "", err
	}
	if st.Upstream != tool.Upstream || st.Tool != tool.Original ||
		st.Subject != p.Subject || st.ClientID != p.ClientID {
		return "", ErrRequestState
	}
	return st.Inner, nil
}

func protocolError(err error) *jsonrpc.Error {
	je, ok := errors.AsType[*jsonrpc.Error](err)
	if !ok || (je.Code != jsonrpc.CodeInvalidParams && je.Code != upstream.CodeMissingCapabilities) {
		return nil
	}
	return &jsonrpc.Error{Code: je.Code, Message: je.Message, Data: je.Data}
}

func upstreamMessage(err error) string {
	switch {
	case errors.Is(err, upstream.ErrBreakerOpen):
		return "upstream temporarily unavailable (circuit open)"
	case errors.Is(err, upstream.ErrSaturated):
		return "upstream busy, retry later"
	case errors.Is(err, upstream.ErrTimeout):
		return "upstream timed out"
	case errors.Is(err, upstream.ErrUnavailable):
		return "upstream unavailable"
	case errors.Is(err, upstream.ErrDelegationDenied):
		return "delegation not permitted for upstream"
	default:
		return "upstream call failed"
	}
}

func (g *Gateway) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "tools/list":
			return g.listTools(ctx, next, method, req)
		case MethodToolsCall:
			return g.callTool(ctx, next, method, req)
		case MethodPromptsList, MethodResourcesList, MethodTemplatesList:
			return g.listDirectory(ctx, method)
		case MethodPromptsGet, MethodResourcesRead:
			return g.readEntry(ctx, method, req)
		case "completion/complete":
			return g.complete(ctx, req)
		default:
			return next(ctx, method, req)
		}
	}
}

func (g *Gateway) listTools(
	ctx context.Context,
	next mcp.MethodHandler,
	method string,
	req mcp.Request,
) (mcp.Result, error) {
	res, err := next(ctx, method, req)
	if err != nil {
		return res, err
	}
	lr, ok := res.(*mcp.ListToolsResult)
	if !ok {
		return res, nil
	}
	p, ok := identity.FromContext(ctx)
	if !ok {
		lr.Tools = []*mcp.Tool{}
		return lr, nil
	}
	visible := lr.Tools[:0:0]
	for _, t := range lr.Tools {
		ct, ok := g.catalog.Lookup(t.Name)
		if ok && g.policy.Load().Visible(p, ct) {
			visible = append(visible, t)
		}
	}
	lr.Tools = visible
	g.metrics.Requests.WithLabelValues(method, "", "", "ok").Inc()
	return lr, nil
}

func (g *Gateway) callTool(
	ctx context.Context,
	next mcp.MethodHandler,
	method string,
	req mcp.Request,
) (mcp.Result, error) {
	a, ok := AdmissionFrom(ctx)
	name := ""
	if p, isCall := req.GetParams().(*mcp.CallToolParamsRaw); isCall {
		name = p.Name
	}
	if !ok || a.Tool.Name == "" || a.Tool.Name != name || a.Decision.Effect != policy.Allow {
		g.log.ErrorContext(ctx, "tools/call without matching admission", slog.String("tool", name))
		g.metrics.Requests.WithLabelValues(method, "", "", "backstop_denied").Inc()
		return nil, ErrNoAdmission
	}
	ctx, span := g.tracer.Start(g.dispatchContext(ctx, a), callSpanName(a), callSpanAttributes(a))
	defer span.End()
	res, err := next(ctx, method, req)
	out := callOutcome{err: err}
	if cr, ok := res.(*mcp.CallToolResult); ok && err == nil && cr != nil {
		out.hasResult, out.isError, out.inputRequired = true, cr.IsError, cr.NeedsInput()
		if b, merr := json.Marshal(cr); merr == nil {
			out.encoded = b
		}
	}
	g.finishCall(ctx, span, a, out)
	return res, err
}

type callOutcome struct {
	hasResult     bool
	encoded       []byte
	isError       bool
	inputRequired bool
	err           error
}

func (g *Gateway) dispatchContext(ctx context.Context, a *Admission) context.Context {
	a.MarkDispatched()
	if sc := trace.SpanContextFromContext(ctx); !sc.IsValid() && a.Envelope.TraceParent != "" {
		ctx = g.propagator.Extract(ctx, metaCarrier{"traceparent": a.Envelope.TraceParent})
	}
	return ctx
}

func callSpanName(a *Admission) string {
	return "mcp.server tools/call " + a.Tool.Name
}

func callSpanAttributes(a *Admission) trace.SpanStartEventOption {
	return trace.WithAttributes(
		attribute.String("mcp.method.name", MethodToolsCall), attribute.String("gen_ai.tool.name", a.Tool.Name),
		attribute.String("mcp.request.id", a.RequestID))
}

func (g *Gateway) finishCall(ctx context.Context, span trace.Span, a *Admission, out callOutcome) {
	outcome := "ok"
	e := g.event(a, audit.PhaseOutcome, audit.DecisionAllow, a.Decision.Rule, "")
	e.LatencyMicros = g.now().Sub(a.Start).Microseconds()
	e.UpstreamMicros = a.Upstream().Microseconds()
	switch {
	case out.err != nil:
		outcome = "error"
		e.Error = out.err.Error()
		span.SetStatus(codes.Error, "call failed")
	case out.hasResult:
		e.IsError = out.isError
		e.ResultType = resultTypeComplete
		if out.inputRequired {
			e.ResultType = "input_required"
		}
		if out.encoded != nil {
			e.ResultHash = audit.HashBytes(out.encoded)
		}
		if out.isError {
			outcome = "tool_error"
		}
	}
	if g.audit != nil {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), intentDeadline)
		if aerr := g.audit.Append(actx, e); aerr != nil {
			g.log.ErrorContext(ctx, "audit outcome append failed", slog.String("error", aerr.Error()))
		}
		cancel()
	}
	g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, outcome).Inc()
}
