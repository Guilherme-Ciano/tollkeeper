package upstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

const (
	protocolStateless    = "2026-07-28"
	maxTaskResponseBytes = 4 << 20
)

var ErrTasksUnsupported = errors.New("tasks extension requires streamable_http upstream")

type taskHTTPState struct {
	mu     sync.Mutex
	client *http.Client
}

func (u *Upstream) taskHTTPClient(ctx context.Context) (*http.Client, error) {
	if u.cfg.Transport != config.TransportStreamable {
		return nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrTasksUnsupported)
	}
	u.taskHTTP.mu.Lock()
	defer u.taskHTTP.mu.Unlock()
	if u.taskHTTP.client != nil {
		return u.taskHTTP.client, nil
	}
	hc, err := HTTPClient(ctx, u.cfg)
	if err != nil {
		return nil, err
	}
	u.taskHTTP.client = hc
	return hc, nil
}

func (u *Upstream) CallTaskTool(ctx context.Context, c Call) (json.RawMessage, error) {
	params := map[string]any{
		"name": c.Tool,
	}
	if len(c.Arguments) > 0 {
		params["arguments"] = c.Arguments
	}
	if len(c.Meta) > 0 {
		params["_meta"] = c.Meta
	}
	if len(c.InputResponses) > 0 {
		params["inputResponses"] = c.InputResponses
	}
	if c.RequestState != "" {
		params["requestState"] = c.RequestState
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("encode task tool params: %w", err)
	}
	return u.sendTaskJSONRPC(ctx, "tools/call", c.Tool, raw)
}

func (u *Upstream) TaskRPC(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	return u.sendTaskJSONRPC(ctx, method, "", params)
}

type taskRPCEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type taskRPCResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *jsonrpc.Error  `json:"error,omitempty"`
}

func (u *Upstream) sendTaskJSONRPC(
	ctx context.Context,
	method, toolName string,
	params json.RawMessage,
) (json.RawMessage, error) {
	callStart := time.Now()
	hc, err := u.taskHTTPClient(ctx)
	if err != nil {
		u.diag.recordCall(time.Since(callStart), err, time.Now())
		return nil, err
	}
	ctx, cancel := context.WithTimeoutCause(ctx, u.cfg.Timeout, ErrTimeout)
	defer cancel()
	select {
	case u.sem <- struct{}{}:
	default:
		serr := fmt.Errorf("%s: %w", u.cfg.ID, ErrSaturated)
		u.diag.recordCall(time.Since(callStart), serr, time.Now())
		return nil, serr
	}
	defer func() { <-u.sem }()

	body, err := json.Marshal(taskRPCEnvelope{
		JSONRPC: "2.0",
		ID:      u.taskSeq.Add(1),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, fmt.Errorf("encode task rpc: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build task request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", protocolStateless)
	req.Header.Set("Mcp-Method", method)
	if toolName != "" {
		req.Header.Set("Mcp-Name", toolName)
	}
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(context.Cause(ctx), ErrTimeout) {
			err = fmt.Errorf("%s: %w", u.cfg.ID, ErrTimeout)
		} else {
			err = fmt.Errorf("task rpc %s/%s: %w", u.cfg.ID, method, err)
		}
		u.diag.recordCall(time.Since(callStart), err, time.Now())
		return nil, err
	}
	defer resp.Body.Close()

	res, rerr := decodeTaskHTTPResponse(resp)
	u.diag.recordCall(time.Since(callStart), rerr, time.Now())
	return res, rerr
}

func decodeTaskHTTPResponse(resp *http.Response) (json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTaskResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read task response: %w", err)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	}
	if mt, _, perr := mime.ParseMediaType(resp.Header.Get("Content-Type")); perr == nil && mt == "text/event-stream" {
		raw, err = extractSSEJSONRPC(raw)
		if err != nil {
			return nil, err
		}
	}
	var env taskRPCResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode task response: %w", err)
	}
	if env.Error != nil {
		return nil, env.Error
	}
	if len(env.Result) == 0 {
		return nil, fmt.Errorf("%w: empty task result", ErrUnavailable)
	}
	return env.Result, nil
}

func extractSSEJSONRPC(raw []byte) ([]byte, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64<<10), maxTaskResponseBytes)
	var last []byte
	for sc.Scan() {
		line := sc.Text()
		if data, ok := strings.CutPrefix(line, "data:"); ok {
			trimmed := strings.TrimSpace(data)
			if trimmed != "" {
				last = []byte(trimmed)
			}
		}
	}
	if len(last) == 0 {
		return nil, fmt.Errorf("%w: empty SSE task response", ErrUnavailable)
	}
	return last, nil
}
