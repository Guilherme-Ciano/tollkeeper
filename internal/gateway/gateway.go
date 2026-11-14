package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
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
	Config     config.Config
	Verifier   TokenVerifier
	Policy     *policy.Engine
	Limiter    *ratelimit.Limiter
	Audit      Auditor
	Catalog    *catalog.Catalog
	Upstreams  map[string]Caller
	Metrics    *telemetry.Metrics
	Tracer     trace.Tracer
	Propagator propagation.TextMapPropagator
	Log        *slog.Logger
	Version    string
	Now        func() time.Time
	Pins       PinGuard
}

type PinGuard interface {
	Mode() pin.Mode
	Status(t catalog.Tool) pin.Status
	Blocks(t catalog.Tool) bool
}

type Gateway struct {
	server         *mcp.Server
	verifier       TokenVerifier
	authDisabled   bool
	requiredScopes []string
	challenge      challenge
	policy         *policy.Engine
	limiter        *ratelimit.Limiter
	audit          Auditor
	catalog        *catalog.Catalog
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

	pins PinGuard

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
		authDisabled:   d.Config.Auth.Mode == config.AuthModeNone,
		requiredScopes: d.Config.Auth.RequiredScopes,
		policy:         d.Policy,
		limiter:        d.Limiter,
		audit:          d.Audit,
		catalog:        d.Catalog,
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
	}
	if !d.Config.Audit.Enabled {
		g.recordArgs = config.RecordArgsNone
	}
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
	}
	g.server = mcp.NewServer(&mcp.Implementation{Name: "tollkeeper", Version: d.Version}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
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
	if len(d.Removed) > 0 {
		g.server.RemoveTools(d.Removed...)
		for _, n := range d.Removed {
			delete(g.quarantined, n)
			delete(g.unapproved, n)
		}
	}
	for i := range d.Upserted {
		t := &d.Upserted[i]
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
	g.publishCatalogGauges()
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
	if prev, seen := g.unapproved[t.Name]; !seen || prev != status {
		g.log.Warn("tool definition not approved",
			slog.String("tool", t.Name),
			slog.String("status", string(status)),
			slog.String("pin", t.Pin),
			slog.String("mode", string(g.pins.Mode())))
	}
	g.unapproved[t.Name] = status
	return g.pins.Blocks(*t)
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
	g.Apply(catalog.Delta{Upserted: g.catalog.Snapshot().Tools()})
}

func (g *Gateway) Unapproved() map[string]pin.Status {
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
		schema, ok = map[string]any{"type": "object"}, true
	}
	if !ok || schema["type"] != "object" {
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
		tool, ok := g.catalog.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownTool, name)
		}
		if a, ok := AdmissionFrom(ctx); ok && a.Tool.Pin != tool.Pin {
			return toolError("tool definition changed since the call was authorised; retry"), nil
		}
		up, ok := g.upstreams[tool.Upstream]
		if !ok {
			return nil, fmt.Errorf("%w: upstream %s", ErrUnknownTool, tool.Upstream)
		}
		meta := map[string]any{}
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
		g.propagator.Inject(ctx, metaCarrier(meta))
		start := g.now()
		res, err := up.CallTool(ctx, upstream.Call{
			Tool:           tool.Original,
			Arguments:      req.Params.Arguments,
			Meta:           meta,
			InputResponses: req.Params.InputResponses,
			RequestState:   req.Params.RequestState,
		})
		elapsed := g.now().Sub(start)
		if a, ok := AdmissionFrom(ctx); ok {
			a.AddUpstream(elapsed)
		}
		g.metrics.UpstreamLatency.WithLabelValues(tool.Upstream).Observe(elapsed.Seconds())
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "upstream call failed")
			g.log.WarnContext(ctx, "upstream call failed", slog.String("tool", name), slog.String("error", err.Error()))
			return toolError(upstreamMessage(err)), nil
		}
		return res, nil
	}
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
		if ok && g.policy.Visible(p, ct) {
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
	a.MarkDispatched()
	if sc := trace.SpanContextFromContext(ctx); !sc.IsValid() && a.Envelope.TraceParent != "" {
		ctx = g.propagator.Extract(ctx, metaCarrier{"traceparent": a.Envelope.TraceParent})
	}
	ctx, span := g.tracer.Start(ctx, "mcp.server tools/call "+name, trace.WithAttributes(
		attribute.String("mcp.method.name", method), attribute.String("gen_ai.tool.name", name),
		attribute.String("mcp.request.id", a.RequestID)))
	defer span.End()
	res, err := next(ctx, method, req)
	outcome := "ok"
	e := g.event(a, audit.PhaseOutcome, audit.DecisionAllow, a.Decision.Rule, "")
	e.LatencyMicros = g.now().Sub(a.Start).Microseconds()
	e.UpstreamMicros = a.Upstream().Microseconds()
	switch {
	case err != nil:
		outcome = "error"
		e.Error = err.Error()
		span.SetStatus(codes.Error, "call failed")
	default:
		if cr, ok := res.(*mcp.CallToolResult); ok {
			e.IsError = cr.IsError
			e.ResultType = "complete"
			if cr.NeedsInput() {
				e.ResultType = "input_required"
			}
			if b, merr := json.Marshal(cr); merr == nil {
				e.ResultHash = audit.HashBytes(b)
			}
			if cr.IsError {
				outcome = "tool_error"
			}
		}
	}
	if g.audit != nil {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), intentDeadline)
		if aerr := g.audit.Append(actx, e); aerr != nil {
			g.log.ErrorContext(ctx, "audit outcome append failed", slog.String("error", aerr.Error()))
		}
		cancel()
	}
	g.metrics.Requests.WithLabelValues(method, name, a.Tool.Upstream, outcome).Inc()
	return res, err
}
