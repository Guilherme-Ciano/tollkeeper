package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

const (
	protocolStateless = "2026-07-28"
	maxFastIDLen      = 128
	maxSafeInteger    = 1<<53 - 1

	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"

	msgContentAndInput = "server bug: result has both content and inputRequests"

	codeMissingCapabilities = upstream.CodeMissingCapabilities
	codeUnsupportedVersion  = -32022
)

type fastCall struct {
	id             []byte
	arguments      json.RawMessage
	inputResponses mcp.InputResponseMap
	requestState   string
}

type capabilitiesWire struct {
	mcp.ClientCapabilities
	Roots *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"roots,omitempty"`
}

type callResultWire struct {
	Meta              mcp.Meta        `json:"_meta,omitempty"`
	Content           []mcp.Content   `json:"content"`
	StructuredContent any             `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
	RequestState      string          `json:"requestState,omitempty"`
	ResultType        string          `json:"resultType,omitempty"`
	InputRequests     json.RawMessage `json:"inputRequests,omitempty"`
}

type fastError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type fastResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *fastError      `json:"error,omitempty"`
}

func (g *Gateway) fastPath(r *http.Request, a *Admission) (fastCall, bool) {
	env := &a.Envelope
	h := r.Header
	switch {
	case g.fastDisabled,
		h.Get("Mcp-Protocol-Version") != protocolStateless,
		env.ProtocolVersion != protocolStateless,
		h.Get("Mcp-Method") != MethodToolsCall,
		env.Name == "" || h.Get("Mcp-Name") != env.Name,
		len(h.Values("Last-Event-Id")) > 0,
		!jsonContentType(h.Get("Content-Type")),
		!acceptsBoth(h.Values("Accept")),
		hasParamHeaders(h),
		bytes.Contains(a.Tool.Descriptor, []byte("x-mcp-header")),
		!g.hostAllowed(r),
		!g.registered(a.Tool.Name),
		!validClientMeta(env.meta):
		return fastCall{}, false
	}
	if _, ok := g.upstreams[a.Tool.Upstream]; !ok {
		return fastCall{}, false
	}
	id, ok := canonicalID(env.ID)
	if !ok {
		return fastCall{}, false
	}
	fc := fastCall{id: id, arguments: env.Arguments}
	if raw, present := env.params["arguments"]; present && isNull(raw) {
		return fastCall{}, false
	}
	if raw, present := env.params["requestState"]; present {
		if json.Unmarshal(raw, &fc.requestState) != nil {
			return fastCall{}, false
		}
	}
	if raw, present := env.params["inputResponses"]; present && !isNull(raw) {
		if json.Unmarshal(raw, &fc.inputResponses) != nil {
			return fastCall{}, false
		}
	}
	return fc, true
}

func jsonContentType(v string) bool {
	mt, _, err := mime.ParseMediaType(v)
	return err == nil && mt == "application/json"
}

func acceptsBoth(values []string) bool {
	var jsonOK, streamOK bool
	for _, value := range values {
		for raw := range strings.SplitSeq(value, ",") {
			base, _, _ := strings.Cut(raw, ";")
			switch strings.ToLower(strings.TrimSpace(base)) {
			case "application/json":
				jsonOK = true
			case "text/event-stream":
				streamOK = true
			}
		}
	}
	return jsonOK && streamOK
}

func hasParamHeaders(h http.Header) bool {
	for k := range h {
		if len(k) >= len("Mcp-Param-") && strings.EqualFold(k[:len("Mcp-Param-")], "Mcp-Param-") {
			return true
		}
	}
	return false
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.Trim(addr, "[]")
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (g *Gateway) hostAllowed(r *http.Request) bool {
	if g.cfg.Server.AllowLocalhostHost {
		return true
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		return true
	}
	return !loopback(local.String()) || loopback(r.Host)
}

func validClientMeta(meta map[string]json.RawMessage) bool {
	if raw, present := meta[metaClientInfo]; present {
		var info mcp.Implementation
		if isNull(raw) || bytes.TrimSpace(raw)[0] != '{' || json.Unmarshal(raw, &info) != nil {
			return false
		}
	}
	raw, present := meta[metaClientCapabilities]
	if !present || isNull(raw) || bytes.TrimSpace(raw)[0] != '{' {
		return false
	}
	var caps capabilitiesWire
	return json.Unmarshal(raw, &caps) == nil
}

func idChar(c byte) bool {
	return c == '-' || c == '_' || c == '.' || c == ':' ||
		('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func canonicalID(id json.RawMessage) ([]byte, bool) {
	if len(id) == 0 || len(id) > maxFastIDLen {
		return nil, false
	}
	if id[0] == '"' {
		if len(id) < 2 || id[len(id)-1] != '"' {
			return nil, false
		}
		for _, c := range id[1 : len(id)-1] {
			if !idChar(c) {
				return nil, false
			}
		}
		return id, true
	}
	n, err := strconv.ParseInt(string(id), 10, 64)
	if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
		return nil, false
	}
	return strconv.AppendInt(nil, n, 10), true
}

func (g *Gateway) serveFast(w http.ResponseWriter, r *http.Request, a *Admission, fc fastCall) {
	ctx := g.dispatchContext(withAdmission(r.Context(), a), a)
	var stream *progressStream
	if token, ok := clientProgressToken(a.Envelope.meta); ok {
		stream = newProgressStream(g.log, w, token)
		ctx = withProgress(ctx, stream.send)
	}
	ctx, span := g.tracer.Start(ctx, callSpanName(a), callSpanAttributes(a))
	defer span.End()
	res, err := g.forward(a.Tool.Name)(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
		Name:           a.Tool.Name,
		Arguments:      fc.arguments,
		InputResponses: fc.inputResponses,
		RequestState:   fc.requestState,
	}})
	out := callOutcome{err: err}
	var body []byte
	switch {
	case err != nil:
	case res == nil:
		out.err = errNilResult
	case res.InputRequests != nil && (len(res.Content) > 0 || res.StructuredContent != nil):
		g.log.WarnContext(ctx, "handler returned both content and inputRequests")
		out.err = &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: msgContentAndInput}
	default:
		encoded, eerr := encodeCallResult(res)
		var annotated []byte
		if eerr == nil {
			annotated, eerr = g.withServerInfo(res, encoded)
		}
		if eerr == nil {
			body, eerr = json.Marshal(fastResponse{JSONRPC: jsonrpcVersion, ID: fc.id, Result: annotated})
		}
		if eerr != nil {
			out.err = &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "internal error"}
			break
		}
		out.hasResult, out.encoded, out.isError = true, encoded, res.IsError
		out.inputRequired = res.InputRequests != nil
	}
	status := http.StatusOK
	if out.err != nil {
		body, status = encodeFastError(fc.id, out.err)
	}
	g.finishCall(ctx, span, a, out)
	if stream != nil && stream.finish(body) {
		return
	}
	writeFast(ctx, w, status, body)
}

var errNilResult = errors.New("tool handler returned a nil result")

func encodeFastError(id []byte, err error) (body []byte, status int) {
	fe := &fastError{Message: err.Error()}
	status = http.StatusOK
	if je, ok := errors.AsType[*jsonrpc.Error](err); ok {
		fe.Code, fe.Data = je.Code, je.Data
		switch je.Code {
		case jsonrpc.CodeMethodNotFound:
			status = http.StatusNotFound
		case jsonrpc.CodeInvalidParams, codeMissingCapabilities, codeUnsupportedVersion:
			status = http.StatusBadRequest
		}
	}
	b, merr := json.Marshal(fastResponse{JSONRPC: jsonrpcVersion, ID: id, Error: fe})
	if merr != nil {
		fallback := `{"jsonrpc":"2.0","id":` + string(id) + `,"error":{"code":-32603,"message":"internal error"}}`
		return []byte(fallback), status
	}
	return b, status
}

func encodeCallResult(res *mcp.CallToolResult) ([]byte, error) {
	w := callResultWire{
		Meta:              res.Meta,
		Content:           res.Content,
		StructuredContent: res.StructuredContent,
		IsError:           res.IsError,
		RequestState:      res.RequestState,
		ResultType:        "complete",
	}
	if res.InputRequests != nil {
		w.ResultType = "input_required"
		ir, err := json.Marshal(res.InputRequests)
		if err != nil {
			return nil, fmt.Errorf("encode input requests: %w", err)
		}
		w.InputRequests = ir
	} else if w.Content == nil {
		w.Content = []mcp.Content{}
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("encode tool result: %w", err)
	}
	return b, nil
}

func serverInfoPrefix(impl *mcp.Implementation) []byte {
	b, err := json.Marshal(map[string]any{mcp.MetaKeyServerInfo: impl})
	if err != nil {
		return nil
	}
	return append(append([]byte(`{"_meta":`), b...), ',')
}

func (g *Gateway) withServerInfo(res *mcp.CallToolResult, encoded []byte) ([]byte, error) {
	if _, present := res.Meta[mcp.MetaKeyServerInfo]; present {
		return encoded, nil
	}
	if len(res.Meta) == 0 && g.infoPrefix != nil && len(encoded) > 1 {
		out := make([]byte, 0, len(g.infoPrefix)+len(encoded)-1)
		out = append(out, g.infoPrefix...)
		return append(out, encoded[1:]...), nil
	}
	shadow := *res
	shadow.Meta = maps.Clone(res.Meta)
	if shadow.Meta == nil {
		shadow.Meta = mcp.Meta{}
	}
	shadow.Meta[mcp.MetaKeyServerInfo] = g.impl
	return encodeCallResult(&shadow)
}

func writeFast(ctx context.Context, w http.ResponseWriter, status int, body []byte) {
	hd := w.Header()
	hd.Set("Cache-Control", "no-cache, no-transform")
	hd.Set("Content-Type", "application/json")
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		slog.DebugContext(ctx, "tools/call response not delivered", slog.String("error", err.Error()))
	}
}
