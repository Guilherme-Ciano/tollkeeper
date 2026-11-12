package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
)

const (
	intentDeadline  = 100 * time.Millisecond
	MethodToolsCall = "tools/call"
	dataRule        = "rule"

	maxClientField   = 256
	maxProtocolField = 32
)

type Admission struct {
	RequestID     string
	Start         time.Time
	Principal     identity.Principal
	Envelope      Envelope
	Tool          catalog.Tool
	Decision      policy.Decision
	ArgsHash      string
	TraceID       string
	upstreamNanos atomic.Int64
	dispatched    atomic.Bool
}

func (a *Admission) MarkDispatched() {
	a.dispatched.Store(true)
}

func (a *Admission) AddUpstream(d time.Duration) {
	a.upstreamNanos.Add(int64(d))
}

func (a *Admission) Upstream() time.Duration {
	return time.Duration(a.upstreamNanos.Load())
}

type admissionKey struct{}

func withAdmission(ctx context.Context, a *Admission) context.Context {
	return context.WithValue(ctx, admissionKey{}, a)
}

func AdmissionFrom(ctx context.Context) (*Admission, bool) {
	a, ok := ctx.Value(admissionKey{}).(*Admission)
	return a, ok && a != nil
}

func allowedMethod(m string) bool {
	switch m {
	case "initialize", "ping", "server/discover", "tools/list", MethodToolsCall,
		"resources/list", "resources/templates/list", "prompts/list",
		"notifications/initialized", "notifications/cancelled", "notifications/progress",
		"notifications/roots/list_changed":
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func nameMethod(m string) bool {
	return m == MethodToolsCall || m == "resources/read" || m == "prompts/get"
}

func notIDChar(c rune) bool {
	return c != '-' && c != '_' && c != '.' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z')
}

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 64 {
		if strings.IndexFunc(id, notIDChar) < 0 {
			return id
		}
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err == nil {
		return body, true
	}
	if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
		writeRPCError(w, http.StatusRequestEntityTooLarge, nil, CodeInvalidRequest, "request body too large", nil)
		return nil, false
	}
	writeRPCError(w, http.StatusBadRequest, nil, CodeParseError, "unreadable body", nil)
	return nil, false
}

func checkHeaders(w http.ResponseWriter, r *http.Request, env *Envelope) bool {
	if hm := r.Header.Get("Mcp-Method"); hm != "" && hm != env.Method {
		writeRPCError(
			w,
			http.StatusBadRequest,
			env.ID,
			CodeHeaderMismatch,
			"Mcp-Method header does not match body",
			nil,
		)
		return false
	}
	if nameMethod(env.Method) {
		if hn := r.Header.Get("Mcp-Name"); hn != "" && hn != env.Name {
			writeRPCError(
				w,
				http.StatusBadRequest,
				env.ID,
				CodeHeaderMismatch,
				"Mcp-Name header does not match body",
				nil,
			)
			return false
		}
	}
	return true
}

func readEnvelope(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, Envelope, bool) {
	body, ok := readBody(w, r, limit)
	if !ok {
		return nil, Envelope{}, false
	}
	env, err := ParseEnvelope(body)
	if err != nil {
		code := CodeInvalidRequest
		if errors.Is(err, ErrEnvelope) {
			code = CodeParseError
		}
		writeRPCError(w, http.StatusBadRequest, nil, code, err.Error(), nil)
		return nil, env, false
	}
	if !checkHeaders(w, r, &env) {
		return nil, env, false
	}
	if allowedMethod(env.Method) {
		return body, env, true
	}
	if env.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return nil, env, false
	}
	writeRPCError(w, http.StatusOK, env.ID, CodeMethodNotFound, "method not supported by gateway: "+env.Method, nil)
	return nil, env, false
}

func (g *Gateway) admission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		start := g.now()
		rid := requestID(r)
		w.Header().Set("X-Request-Id", rid)
		body, env, ok := readEnvelope(w, r, g.maxBody)
		if !ok {
			return
		}
		p, _ := identity.FromContext(r.Context())
		a := &Admission{RequestID: rid, Start: start, Principal: p, Envelope: env}
		if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() {
			a.TraceID = sc.TraceID().String()
		}
		if env.Method == MethodToolsCall && !g.admitCall(w, r, a) {
			return
		}
		r2 := r.WithContext(withAdmission(r.Context(), a))
		r2.Body = io.NopCloser(bytes.NewReader(body))
		r2.ContentLength = int64(len(body))
		next.ServeHTTP(w, r2)
		total := g.now().Sub(start)
		g.metrics.Duration.WithLabelValues(env.Method).Observe(total.Seconds())
		if env.Method != MethodToolsCall {
			return
		}
		g.metrics.Overhead.Observe(max(total-a.Upstream(), 0).Seconds())
		if !a.dispatched.Load() {
			g.recordNotDispatched(r.Context(), a)
		}
	})
}

func (g *Gateway) admitCall(w http.ResponseWriter, r *http.Request, a *Admission) bool {
	ctx := r.Context()
	env := a.Envelope
	if g.recordArgs != config.RecordArgsNone && len(env.Arguments) > 0 {
		a.ArgsHash = audit.HashBytes(env.Arguments)
	}
	tool, known := g.catalog.Lookup(env.Name)
	subject := ratelimit.Subject{Sub: a.Principal.Subject, ClientID: a.Principal.ClientID}
	if known {
		a.Tool = tool
		subject.Tool, subject.Upstream = tool.Name, tool.Upstream
	}
	if !g.takeRate(ctx, w, a, subject) {
		return false
	}
	if !known {
		g.metrics.Requests.WithLabelValues(env.Method, "unknown", "", "unknown_tool").Inc()
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "unknown tool")
		writeRPCError(w, http.StatusOK, env.ID, CodePolicyDenied, "denied by policy", nil)
		return false
	}
	d := g.policy.Decide(ctx, policy.Input{
		Principal:  a.Principal,
		Method:     env.Method,
		Tool:       tool,
		Args:       env.Arguments,
		ClientName: env.ClientName,
		Now:        g.now(),
	})
	a.Decision = d
	g.metrics.PolicyDecisions.WithLabelValues(d.Effect.String(), d.Rule).Inc()
	if !g.applyDecision(ctx, w, a, d) {
		return false
	}
	return g.recordIntent(ctx, w, a)
}

func (g *Gateway) takeRate(ctx context.Context, w http.ResponseWriter, a *Admission, s ratelimit.Subject) bool {
	res := g.limiter.Allow(ctx, s)
	if res.Allowed {
		if res.Limit.Count > 0 {
			setRateHeaders(w, res)
		}
		return true
	}
	g.metrics.RateLimited.WithLabelValues(res.Rule).Inc()
	g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "rate_limited").Inc()
	g.recordDecision(ctx, a, audit.DecisionRateLimited, res.Rule, "rate limit exceeded")
	setRateHeaders(w, res)
	w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(res.RetryAfter.Seconds())), 10))
	writeRPCError(w, http.StatusTooManyRequests, a.Envelope.ID, CodeRateLimited, "rate limit exceeded", map[string]any{
		"retry_after_ms": res.RetryAfter.Milliseconds(),
		dataRule:         res.Rule,
		"limit":          res.Limit.Count,
		"window_s":       int64(res.Limit.Per.Seconds()),
	})
	return false
}

func (g *Gateway) applyDecision(ctx context.Context, w http.ResponseWriter, a *Admission, d policy.Decision) bool {
	env := a.Envelope
	switch d.Effect {
	case policy.Allow:
		return true
	case policy.StepUp:
		g.metrics.Requests.WithLabelValues(env.Method, a.Tool.Name, a.Tool.Upstream, "step_up").Inc()
		g.recordDecision(ctx, a, audit.DecisionStepUp, d.Rule, d.Reason)
		w.Header().
			Set("WWW-Authenticate", g.challenge.header("insufficient_scope", "additional scope required", d.StepUpScopes))
		writeRPCError(w, http.StatusForbidden, env.ID, CodePolicyDenied, "insufficient scope", map[string]any{
			"required_scopes": d.StepUpScopes,
		})
		return false
	case policy.Deny:
	}
	g.metrics.Requests.WithLabelValues(env.Method, a.Tool.Name, a.Tool.Upstream, "denied").Inc()
	g.recordDecision(ctx, a, audit.DecisionDeny, d.Rule, d.Reason)
	writeRPCError(w, http.StatusOK, env.ID, CodePolicyDenied, "denied by policy", nil)
	return false
}

func (g *Gateway) recordIntent(ctx context.Context, w http.ResponseWriter, a *Admission) bool {
	if g.audit == nil {
		return true
	}
	ictx, cancel := context.WithTimeout(ctx, intentDeadline)
	err := g.audit.Append(ictx, g.event(a, audit.PhaseIntent, audit.DecisionAllow, a.Decision.Rule, ""))
	cancel()
	if err == nil {
		return true
	}
	g.log.ErrorContext(ctx, "audit intent rejected, denying call", slog.String("error", err.Error()))
	g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "audit_unavailable").Inc()
	w.Header().Set("Retry-After", "1")
	writeRPCError(w, http.StatusServiceUnavailable, a.Envelope.ID, CodeAuditUnavailabe, "audit log unavailable", nil)
	return false
}

func (g *Gateway) recordNotDispatched(ctx context.Context, a *Admission) {
	if g.audit == nil {
		return
	}
	e := g.event(a, audit.PhaseOutcome, audit.DecisionAllow, a.Decision.Rule, "")
	e.Error = "not dispatched: rejected by the MCP transport before reaching the tool"
	e.LatencyMicros = g.now().Sub(a.Start).Microseconds()
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), intentDeadline)
	defer cancel()
	if err := g.audit.Append(actx, e); err != nil {
		g.log.WarnContext(ctx, "audit append failed", slog.String("error", err.Error()))
	}
}

func setRateHeaders(w http.ResponseWriter, res ratelimit.Result) {
	w.Header().Set("RateLimit-Policy", strconv.Quote(res.Rule)+";q="+strconv.Itoa(res.Limit.Count)+";w="+
		strconv.FormatInt(int64(res.Limit.Per.Seconds()), 10))
	w.Header().Set("RateLimit", strconv.Quote(res.Rule)+";r="+strconv.Itoa(res.Remaining)+";t="+
		strconv.FormatInt(int64(math.Ceil(res.ResetAfter.Seconds())), 10))
}

func (g *Gateway) event(a *Admission, phase, decision, rule, reason string) audit.Event {
	e := audit.Event{
		Phase:           phase,
		RequestID:       a.RequestID,
		TraceID:         a.TraceID,
		Subject:         a.Principal.Subject,
		ClientID:        a.Principal.ClientID,
		ClientName:      truncate(a.Envelope.ClientName, maxClientField),
		ClientVersion:   truncate(a.Envelope.ClientVersion, maxClientField),
		ProtocolVersion: truncate(a.Envelope.ProtocolVersion, maxProtocolField),
		Method:          a.Envelope.Method,
		Tool:            truncate(a.Envelope.Name, catalog.MaxNameLen),
		Upstream:        a.Tool.Upstream,
		Decision:        decision,
		Rule:            rule,
		Reason:          reason,
		ArgsHash:        a.ArgsHash,
		PinHash:         a.Tool.Pin,
	}
	if g.recordArgs == config.RecordArgsFull {
		e.Args = a.Envelope.Arguments
	}
	return e
}

func (g *Gateway) recordDecision(ctx context.Context, a *Admission, decision, rule, reason string) {
	if g.audit == nil {
		return
	}
	e := g.event(a, audit.PhaseDecision, decision, rule, reason)
	e.LatencyMicros = g.now().Sub(a.Start).Microseconds()
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), intentDeadline)
	defer cancel()
	if err := g.audit.Append(actx, e); err != nil {
		g.log.WarnContext(ctx, "audit append failed", slog.String("error", err.Error()))
	}
}
