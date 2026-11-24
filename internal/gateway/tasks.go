package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

const (
	ExtensionTasks    = "io.modelcontextprotocol/tasks"
	MethodTasksGet    = "tasks/get"
	MethodTasksUpdate = "tasks/update"
	MethodTasksCancel = "tasks/cancel"

	taskPrefix         = "tkt1."
	DefaultTaskTTL     = time.Hour
	maxTaskToken       = 4 << 10
	fieldTaskID        = "taskId"
	resultTypeComplete = "complete"
)

var ErrTaskHandle = errors.New("invalid or expired taskId")

type TaskCaller interface {
	CallTaskTool(ctx context.Context, c upstream.Call) (json.RawMessage, error)
	TaskRPC(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error)
}

type taskHandle struct {
	Upstream string `json:"u"`
	Tool     string `json:"t"`
	Original string `json:"o"`
	Pin      string `json:"p,omitempty"`
	Subject  string `json:"s,omitempty"`
	Tenant   string `json:"n,omitempty"`
	ClientID string `json:"c,omitempty"`
	InnerID  string `json:"i"`
	Expires  int64  `json:"e"`
}

type taskSealer struct {
	key []byte
	ttl time.Duration
}

func newTaskSealer(key []byte, ttl time.Duration) *taskSealer {
	if ttl <= 0 {
		ttl = DefaultTaskTTL
	}
	if key == nil {
		key = []byte(rand.Text() + rand.Text())
	}
	return &taskSealer{key: key, ttl: ttl}
}

func (s *taskSealer) mac(body string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(body))
	return m.Sum(nil)
}

func (s *taskSealer) seal(h taskHandle, now time.Time) (string, error) {
	h.Expires = now.Add(s.ttl).Unix()
	b, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("encode task handle: %w", err)
	}
	body := taskPrefix + base64.RawURLEncoding.EncodeToString(b)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.mac(body)), nil
}

func (s *taskSealer) open(token string, now time.Time) (taskHandle, error) {
	var h taskHandle
	if len(token) > maxTaskToken {
		return h, ErrTaskHandle
	}
	i := strings.LastIndexByte(token, '.')
	if i < 0 || !strings.HasPrefix(token, taskPrefix) {
		return h, ErrTaskHandle
	}
	body := token[:i]
	sig, err := base64.RawURLEncoding.DecodeString(token[i+1:])
	if err != nil || !hmac.Equal(sig, s.mac(body)) {
		return h, ErrTaskHandle
	}
	raw, err := base64.RawURLEncoding.DecodeString(body[len(taskPrefix):])
	if err != nil || json.Unmarshal(raw, &h) != nil || now.Unix() >= h.Expires || h.InnerID == "" {
		return taskHandle{}, ErrTaskHandle
	}
	return h, nil
}

func isTaskMethod(m string) bool {
	return m == MethodTasksGet || m == MethodTasksUpdate || m == MethodTasksCancel
}

func clientSupportsTasks(meta map[string]json.RawMessage) bool {
	raw, ok := meta[metaClientCapabilities]
	if !ok || isNull(raw) {
		return false
	}
	var caps struct {
		Extensions map[string]json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(raw, &caps); err != nil {
		return false
	}
	_, supported := caps.Extensions[ExtensionTasks]
	return supported
}

func (g *Gateway) taskCallCandidate(a *Admission) (TaskCaller, bool) {
	if !g.cfg.Server.TasksEnabled || a.Envelope.Method != MethodToolsCall {
		return nil, false
	}
	if !clientSupportsTasks(a.Envelope.meta) {
		return nil, false
	}
	tc, ok := g.upstreams[a.Tool.Upstream].(TaskCaller)
	return tc, ok
}

func (g *Gateway) serveTaskCall(w http.ResponseWriter, r *http.Request, a *Admission, tc TaskCaller) {
	ctx := g.dispatchContext(withAdmission(r.Context(), a), a)
	ctx, span := g.tracer.Start(ctx, callSpanName(a), callSpanAttributes(a))
	defer span.End()

	innerState, err := g.openTaskCallState(a)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, a.Envelope.ID, CodeInvalidParams, err.Error(), nil)
		g.finishCall(ctx, span, a, callOutcome{err: err})
		return
	}
	call := upstream.Call{
		Tool:         a.Tool.Original,
		Arguments:    a.Envelope.Arguments,
		RequestState: innerState,
		Meta:         map[string]any{},
	}
	g.propagator.Inject(ctx, metaCarrier(call.Meta))
	if raw, ok := a.Envelope.meta[metaClientCapabilities]; ok && !isNull(raw) {
		call.Meta[metaClientCapabilities] = raw
	}
	start := g.now()
	rawRes, err := tc.CallTaskTool(ctx, call)
	elapsed := g.now().Sub(start)
	a.AddUpstream(elapsed)
	g.metrics.UpstreamLatency.WithLabelValues(a.Tool.Upstream).Observe(elapsed.Seconds())
	if err != nil {
		g.writeTaskCallError(ctx, w, span, a, err)
		return
	}
	sealedRes, resultType, isErr, serr := g.sealTaskCallResult(rawRes, a)
	if serr != nil {
		g.writeTaskCallError(ctx, w, span, a, serr)
		return
	}
	g.finishTaskOutcome(ctx, span, a, resultType, isErr, sealedRes, nil)
	g.writeJSONRPCResult(ctx, w, a.Envelope.ID, sealedRes)
}

func (g *Gateway) openTaskCallState(a *Admission) (string, error) {
	raw, present := a.Envelope.params["requestState"]
	if !present || isNull(raw) {
		return "", nil
	}
	var token string
	if err := json.Unmarshal(raw, &token); err != nil {
		return "", ErrRequestState
	}
	return g.openState(token, a.Tool, a.Principal)
}

func (g *Gateway) sealTaskCallResult(
	raw json.RawMessage,
	a *Admission,
) (out json.RawMessage, resultType string, isErr bool, err error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, "", false, fmt.Errorf("decode upstream task result: %w", err)
	}
	if rt, ok := obj["resultType"].(string); ok {
		resultType = rt
	}
	if ie, ok := obj["isError"].(bool); ok {
		isErr = ie
	}
	if resultType == "task" {
		innerID, ok := obj[fieldTaskID].(string)
		if !ok || innerID == "" {
			return nil, "", false, fmt.Errorf("%w: missing upstream taskId", ErrTaskHandle)
		}
		sealed, serr := g.tasks.seal(taskHandle{
			Upstream: a.Tool.Upstream,
			Tool:     a.Tool.Name,
			Original: a.Tool.Original,
			Pin:      a.Tool.Pin,
			Subject:  a.Principal.Subject,
			Tenant:   a.Principal.Tenant,
			ClientID: a.Principal.ClientID,
			InnerID:  innerID,
		}, g.now())
		if serr != nil {
			return nil, "", false, serr
		}
		obj[fieldTaskID] = sealed
	} else {
		if rs, ok := obj["requestState"].(string); ok && rs != "" {
			sealed, serr := g.states.seal(statePayload{
				Upstream: a.Tool.Upstream, Tool: a.Tool.Original,
				Subject: a.Principal.Subject, ClientID: a.Principal.ClientID, Inner: rs,
			}, g.now())
			if serr != nil {
				return nil, "", false, serr
			}
			obj["requestState"] = sealed
		}
		if g.cfg.Server.StampProvenance {
			stampRawProvenance(obj, a.Tool)
		}
	}
	if resultType == "" {
		resultType = resultTypeComplete
	}
	encoded, merr := json.Marshal(obj)
	if merr != nil {
		return nil, "", false, fmt.Errorf("encode task result: %w", merr)
	}
	return encoded, resultType, isErr, nil
}

func stampRawProvenance(obj map[string]any, tool catalog.Tool) {
	meta, ok := obj["_meta"].(map[string]any)
	if !ok {
		meta = nil
	}
	cloned := make(map[string]any, len(meta)+1)
	maps.Copy(cloned, meta)
	m := tool.ResolvedMetadata()
	cloned["tollkeeper.provenance"] = map[string]any{
		"upstream":       tool.Upstream,
		keyTool:          tool.Name,
		"trust":          m.Trust,
		"classification": m.Classification,
		"egress":         m.Egress,
		"impact":         m.Impact,
		"pin_hash":       tool.Pin,
	}
	obj["_meta"] = cloned
}

func (g *Gateway) serveTaskMethod(w http.ResponseWriter, r *http.Request, a *Admission) {
	ctx := r.Context()
	env := a.Envelope
	if !g.cfg.Server.TasksEnabled {
		writeRPCError(w, http.StatusNotFound, env.ID, CodeMethodNotFound, "tasks extension is disabled", nil)
		return
	}
	taskID, ok := extractTaskID(env.params)
	if !ok {
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "missing taskId")
		writeRPCError(w, http.StatusBadRequest, env.ID, CodeInvalidParams, "missing taskId", nil)
		return
	}
	h, err := g.openTaskHandle(taskID, a.Principal)
	if err != nil {
		g.metrics.Requests.WithLabelValues(env.Method, "", "", "invalid_task").Inc()
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "invalid or foreign taskId")
		writeRPCError(w, http.StatusBadRequest, env.ID, CodeInvalidParams, ErrTaskHandle.Error(), nil)
		return
	}
	a.Tool = catalog.Tool{Name: h.Tool, Upstream: h.Upstream, Original: h.Original, Pin: h.Pin}
	if live, found := g.catalog.Lookup(h.Tool); found {
		a.Tool = live
	}
	if !g.takeRate(ctx, w, a, ratelimit.Subject{
		Sub:      a.Principal.Subject,
		ClientID: a.Principal.ClientID,
		Tenant:   a.Principal.Tenant,
		Tool:     a.Tool.Name,
		Upstream: a.Tool.Upstream,
	}) {
		return
	}
	tc, ok := g.upstreams[h.Upstream].(TaskCaller)
	if !ok {
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "upstream does not support tasks")
		writeRPCError(w, http.StatusBadGateway, env.ID, CodeUpstreamFailed, "upstream does not support tasks", nil)
		return
	}
	if !g.recordIntent(ctx, w, a) {
		return
	}
	rewritten, rerr := rewriteTaskParams(env.params, h.InnerID)
	if rerr != nil {
		writeRPCError(w, http.StatusBadRequest, env.ID, CodeInvalidParams, "invalid task params", nil)
		return
	}
	ctx, span := g.tracer.Start(
		g.dispatchContext(ctx, a),
		"mcp.server "+env.Method+" "+h.Tool,
		trace.WithAttributes(
			attribute.String("mcp.method.name", env.Method),
			attribute.String("mcp.upstream", h.Upstream),
			attribute.String("gen_ai.tool.name", h.Tool),
		),
	)
	defer span.End()

	start := g.now()
	rawRes, uerr := tc.TaskRPC(ctx, env.Method, rewritten)
	elapsed := g.now().Sub(start)
	a.AddUpstream(elapsed)
	g.metrics.UpstreamLatency.WithLabelValues(h.Upstream).Observe(elapsed.Seconds())
	if uerr != nil {
		g.writeTaskCallError(ctx, w, span, a, uerr)
		return
	}
	sealedRes, serr := g.sealTaskMethodResult(rawRes, taskID, a.Tool)
	if serr != nil {
		g.writeTaskCallError(ctx, w, span, a, serr)
		return
	}
	g.finishTaskOutcome(ctx, span, a, "task", false, sealedRes, nil)
	g.writeJSONRPCResult(ctx, w, env.ID, sealedRes)
}

func extractTaskID(params map[string]json.RawMessage) (string, bool) {
	raw, ok := params[fieldTaskID]
	if !ok || isNull(raw) {
		return "", false
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil || strings.TrimSpace(id) == "" {
		return "", false
	}
	return id, true
}

func (g *Gateway) openTaskHandle(token string, p identity.Principal) (taskHandle, error) {
	h, err := g.tasks.open(token, g.now())
	if err != nil {
		return taskHandle{}, err
	}
	if h.Subject != p.Subject || h.Tenant != p.Tenant || h.ClientID != p.ClientID {
		return taskHandle{}, ErrTaskHandle
	}
	return h, nil
}

func rewriteTaskParams(params map[string]json.RawMessage, innerID string) (json.RawMessage, error) {
	out := make(map[string]json.RawMessage, len(params))
	maps.Copy(out, params)
	encodedID, err := json.Marshal(innerID)
	if err != nil {
		return nil, fmt.Errorf("encode inner taskId: %w", err)
	}
	out[fieldTaskID] = encodedID
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode task params: %w", err)
	}
	return b, nil
}

func (g *Gateway) sealTaskMethodResult(
	raw json.RawMessage,
	sealedID string,
	tool catalog.Tool,
) (json.RawMessage, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("decode task response: %w", err)
	}
	if _, hasID := obj[fieldTaskID]; hasID {
		obj[fieldTaskID] = sealedID
	}
	if g.cfg.Server.StampProvenance {
		if resObj, ok := obj["result"].(map[string]any); ok {
			stampRawProvenance(resObj, tool)
		}
	}
	encoded, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("encode task response: %w", err)
	}
	return encoded, nil
}

func (g *Gateway) writeTaskCallError(
	ctx context.Context,
	w http.ResponseWriter,
	span trace.Span,
	a *Admission,
	err error,
) {
	span.RecordError(err)
	span.SetStatus(codes.Error, "task call failed")
	g.finishTaskOutcome(ctx, span, a, "", false, nil, err)
	if je, ok := errors.AsType[*jsonrpc.Error](err); ok {
		status := http.StatusOK
		if je.Code == jsonrpc.CodeInvalidParams || je.Code == upstream.CodeMissingCapabilities {
			status = http.StatusBadRequest
		}
		writeRPCError(w, status, a.Envelope.ID, int(je.Code), je.Message, je.Data)
		return
	}
	writeRPCError(w, http.StatusBadGateway, a.Envelope.ID, CodeUpstreamFailed, upstreamMessage(err), nil)
}

func (g *Gateway) finishTaskOutcome(
	ctx context.Context,
	span trace.Span,
	a *Admission,
	resultType string,
	isErr bool,
	encoded []byte,
	err error,
) {
	outcome := "ok"
	e := g.event(a, audit.PhaseOutcome, audit.DecisionAllow, a.Decision.Rule, "")
	e.LatencyMicros = g.now().Sub(a.Start).Microseconds()
	e.UpstreamMicros = a.Upstream().Microseconds()
	switch {
	case err != nil:
		outcome = "error"
		e.Error = err.Error()
		span.SetStatus(codes.Error, "task failed")
	default:
		e.IsError = isErr
		e.ResultType = resultType
		if len(encoded) > 0 {
			e.ResultHash = audit.HashBytes(encoded)
		}
		if isErr {
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

func (g *Gateway) writeJSONRPCResult(ctx context.Context, w http.ResponseWriter, id, result json.RawMessage) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(fastResponse{JSONRPC: jsonrpcVersion, ID: id, Result: result})
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, id, CodeInternal, "internal error", nil)
		return
	}
	writeFast(ctx, w, http.StatusOK, body)
}
