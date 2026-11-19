package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

const (
	MethodPromptsGet    = "prompts/get"
	MethodResourcesRead = "resources/read"
	MethodPromptsList   = "prompts/list"
	MethodResourcesList = "resources/list"
	MethodTemplatesList = "resources/templates/list"
)

func privateCache() mcp.Cacheable {
	return mcp.Cacheable{CacheScope: "private"}
}

type Reader interface {
	GetPrompt(ctx context.Context, c upstream.PromptCall) (*mcp.GetPromptResult, error)
	ReadResource(ctx context.Context, c upstream.ResourceCall) (*mcp.ReadResourceResult, error)
	Complete(ctx context.Context, p *mcp.CompleteParams) (*mcp.CompleteResult, error)
}

var errUpstreamFailed = &jsonrpc.Error{Code: CodeUpstreamFailed, Message: "upstream call failed"}

func (g *Gateway) capabilities() *mcp.ServerCapabilities {
	caps := &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}
	if g.directory != nil {
		caps.Prompts = &mcp.PromptCapabilities{ListChanged: true}
		caps.Resources = &mcp.ResourceCapabilities{ListChanged: true}
		caps.Completions = &mcp.CompletionCapabilities{}
	}
	return caps
}

func targetKind(method string) catalog.Kind {
	switch method {
	case MethodPromptsGet:
		return catalog.KindPrompt
	case MethodResourcesRead:
		return catalog.KindResource
	}
	return ""
}

func (g *Gateway) lookupEntry(kind catalog.Kind, name string) (catalog.Entry, bool) {
	if g.directory == nil {
		return catalog.Entry{}, false
	}
	snap := g.directory.Snapshot()
	if kind == catalog.KindResource {
		return snap.Resource(name)
	}
	return snap.Lookup(kind, name)
}

func entryTarget(e catalog.Entry, name string) catalog.Tool {
	original := e.Original
	if e.Kind != catalog.KindPrompt {
		original = name
	}
	return catalog.Tool{Name: name, Upstream: e.Upstream, Original: original}
}

func notFoundError(kind catalog.Kind, name string) *jsonrpc.Error {
	if kind == catalog.KindPrompt {
		return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "unknown prompt"}
	}
	data, err := json.Marshal(map[string]string{"uri": name})
	if err != nil {
		data = nil
	}
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "resource not found", Data: data}
}

func (g *Gateway) listDirectory(ctx context.Context, method string) (mcp.Result, error) {
	p, ok := identity.FromContext(ctx)
	var snap *catalog.DirSnapshot
	if g.directory != nil {
		snap = g.directory.Snapshot()
	}
	visible := func(kind catalog.Kind) []catalog.Entry {
		var out []catalog.Entry
		if !ok {
			return out
		}
		for _, e := range snap.Entries(kind) {
			if g.policy.Load().VisibleAs(p, kind, e.Name) {
				out = append(out, e)
			}
		}
		return out
	}
	switch method {
	case MethodPromptsList:
		res := &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{}, Cacheable: privateCache()}
		res.Prompts = decodeAll[mcp.Prompt](visible(catalog.KindPrompt), res.Prompts)
		return res, nil
	case MethodTemplatesList:
		res := &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{}, Cacheable: privateCache()}
		res.ResourceTemplates = decodeAll[mcp.ResourceTemplate](visible(catalog.KindTemplate), res.ResourceTemplates)
		return res, nil
	default:
		res := &mcp.ListResourcesResult{Resources: []*mcp.Resource{}, Cacheable: privateCache()}
		res.Resources = decodeAll[mcp.Resource](visible(catalog.KindResource), res.Resources)
		return res, nil
	}
}

func decodeAll[T any](entries []catalog.Entry, out []*T) []*T {
	for _, e := range entries {
		v := new(T)
		if json.Unmarshal(e.Descriptor, v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func (g *Gateway) readEntry(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
	a, ok := AdmissionFrom(ctx)
	name := ""
	switch p := req.GetParams().(type) {
	case *mcp.GetPromptParams:
		name = p.Name
	case *mcp.ReadResourceParams:
		name = p.URI
	}
	if !ok || a.Kind != targetKind(method) || a.Tool.Name == "" || a.Tool.Name != name ||
		a.Decision.Effect != policy.Allow {
		g.log.ErrorContext(ctx, "read without matching admission",
			slog.String("method", method), slog.String("name", name))
		g.metrics.Requests.WithLabelValues(method, "", "", "backstop_denied").Inc()
		return nil, ErrNoAdmission
	}
	ctx = g.dispatchContext(ctx, a)
	ctx, span := g.tracer.Start(ctx, "mcp.server "+method+" "+a.Tool.Name, trace.WithAttributes(
		attribute.String("mcp.method.name", method), attribute.String("mcp.request.id", a.RequestID)))
	defer span.End()
	res, out := g.dispatchEntry(ctx, a, req)
	g.finishCall(ctx, span, a, out)
	return res, out.err
}

func (g *Gateway) dispatchEntry(ctx context.Context, a *Admission, req mcp.Request) (mcp.Result, callOutcome) {
	reader, ok := g.upstreams[a.Tool.Upstream].(Reader)
	if !ok {
		return nil, callOutcome{err: errUpstreamFailed}
	}
	start := g.now()
	defer func() { a.AddUpstream(g.now().Sub(start)) }()
	switch p := req.GetParams().(type) {
	case *mcp.GetPromptParams:
		inner, err := g.openState(p.RequestState, a.Tool, a.Principal)
		if err != nil {
			return nil, callOutcome{err: &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}}
		}
		res, err := reader.GetPrompt(ctx, upstream.PromptCall{
			Name: a.Tool.Original, Arguments: p.Arguments, Meta: g.forwardMeta(a),
			InputResponses: p.InputResponses, RequestState: inner,
		})
		if err != nil {
			return nil, callOutcome{err: g.readError(ctx, a, err)}
		}
		if res.RequestState, err = g.sealState(res.RequestState, a); err != nil {
			return nil, callOutcome{err: err}
		}
		if res, err = withResultType(res, res.InputRequests != nil); err != nil {
			return nil, callOutcome{err: errUpstreamFailed}
		}
		return res, encodedOutcome(res, res.NeedsInput())
	case *mcp.ReadResourceParams:
		inner, err := g.openState(p.RequestState, a.Tool, a.Principal)
		if err != nil {
			return nil, callOutcome{err: &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}}
		}
		res, err := reader.ReadResource(ctx, upstream.ResourceCall{
			URI: p.URI, Meta: g.forwardMeta(a), InputResponses: p.InputResponses, RequestState: inner,
		})
		if err != nil {
			return nil, callOutcome{err: g.readError(ctx, a, err)}
		}
		if res.RequestState, err = g.sealState(res.RequestState, a); err != nil {
			return nil, callOutcome{err: err}
		}
		res.Cacheable = privateCache()
		if res, err = withResultType(res, res.InputRequests != nil); err != nil {
			return nil, callOutcome{err: errUpstreamFailed}
		}
		return res, encodedOutcome(res, res.NeedsInput())
	}
	return nil, callOutcome{err: errUpstreamFailed}
}

func encodedOutcome(res any, inputRequired bool) callOutcome {
	out := callOutcome{hasResult: true, inputRequired: inputRequired}
	if b, err := json.Marshal(res); err == nil {
		out.encoded = b
	}
	return out
}

func (g *Gateway) forwardMeta(a *Admission) map[string]any {
	meta := map[string]any{}
	if raw, present := a.Envelope.meta[metaClientCapabilities]; present && !isNull(raw) {
		meta[metaClientCapabilities] = raw
	}
	return meta
}

func (g *Gateway) sealState(state string, a *Admission) (string, error) {
	if state == "" {
		return "", nil
	}
	return g.states.seal(statePayload{
		Upstream: a.Tool.Upstream, Tool: a.Tool.Original, Subject: a.Principal.Subject,
		ClientID: a.Principal.ClientID, Inner: state,
	}, g.now())
}

func (g *Gateway) readError(ctx context.Context, a *Admission, err error) error {
	if pe := protocolError(err); pe != nil {
		return pe
	}
	g.log.WarnContext(ctx, "upstream call failed", slog.String("target", a.Tool.Name),
		slog.String("error", err.Error()))
	return errUpstreamFailed
}

func (g *Gateway) complete(ctx context.Context, req mcp.Request) (mcp.Result, error) {
	p, ok := req.GetParams().(*mcp.CompleteParams)
	if !ok || p.Ref == nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "completion reference required"}
	}
	principal, signedIn := identity.FromContext(ctx)
	kind, name := catalog.KindPrompt, p.Ref.Name
	if p.Ref.Type == "ref/resource" {
		kind, name = catalog.KindResource, p.Ref.URI
	}
	e, found := g.lookupEntry(kind, name)
	if !found || !signedIn || !g.policy.Load().VisibleAs(principal, e.Kind, e.Name) {
		return nil, notFoundError(kind, name)
	}
	reader, ok := g.upstreams[e.Upstream].(Reader)
	if !ok {
		return nil, errUpstreamFailed
	}
	fwd := *p
	ref := *p.Ref
	if kind == catalog.KindPrompt {
		ref.Name = e.Original
	}
	fwd.Ref = &ref
	res, err := reader.Complete(ctx, &fwd)
	if err != nil {
		if pe := protocolError(err); pe != nil {
			return nil, pe
		}
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		g.log.WarnContext(ctx, "upstream completion failed", slog.String("error", err.Error()))
		return nil, errUpstreamFailed
	}
	return res, nil
}

func withResultType[T any, P interface{ *T }](res P, inputRequired bool) (P, error) {
	b, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	fields["resultType"] = json.RawMessage(`"complete"`)
	if inputRequired {
		fields["resultType"] = json.RawMessage(`"input_required"`)
	}
	if b, err = json.Marshal(fields); err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	out := P(new(T))
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	return out, nil
}
