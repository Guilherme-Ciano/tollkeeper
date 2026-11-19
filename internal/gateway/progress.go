package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type progressKey struct{}

type progressNotification struct {
	JSONRPC string                          `json:"jsonrpc"`
	Method  string                          `json:"method"`
	Params  *mcp.ProgressNotificationParams `json:"params"`
}

type progressStream struct {
	mu      sync.Mutex
	log     *slog.Logger
	w       http.ResponseWriter
	rc      *http.ResponseController
	token   json.RawMessage
	started bool
	closed  bool
}

func clientProgressToken(meta map[string]json.RawMessage) (json.RawMessage, bool) {
	raw, ok := meta["progressToken"]
	if !ok {
		return nil, false
	}
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return nil, false
	}
	if t[0] == '"' {
		var s string
		return t, json.Unmarshal(t, &s) == nil
	}
	_, ok = canonicalID(t)
	return t, ok
}

func newProgressStream(log *slog.Logger, w http.ResponseWriter, token json.RawMessage) *progressStream {
	return &progressStream{log: log, w: w, rc: http.NewResponseController(w), token: token}
}

func withProgress(ctx context.Context, fn func(*mcp.ProgressNotificationParams)) context.Context {
	return context.WithValue(ctx, progressKey{}, fn)
}

func progressFrom(ctx context.Context) func(*mcp.ProgressNotificationParams) {
	fn, ok := ctx.Value(progressKey{}).(func(*mcp.ProgressNotificationParams))
	if !ok {
		return nil
	}
	return fn
}

func (p *progressStream) send(n *mcp.ProgressNotificationParams) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || n == nil {
		return
	}
	params := *n
	params.ProgressToken = p.token
	b, err := json.Marshal(progressNotification{
		JSONRPC: jsonrpcVersion, Method: "notifications/progress", Params: &params,
	})
	if err != nil {
		return
	}
	p.startLocked()
	p.eventLocked(b)
}

func (p *progressStream) startLocked() {
	if p.started {
		return
	}
	p.started = true
	h := p.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Del("Content-Length")
	p.w.WriteHeader(http.StatusOK)
}

func (p *progressStream) eventLocked(data []byte) {
	buf := make([]byte, 0, len(data)+24)
	buf = append(buf, "event: message\ndata: "...)
	buf = append(buf, data...)
	buf = append(buf, "\n\n"...)
	if _, err := p.w.Write(buf); err != nil {
		p.log.Debug("progress event not delivered", slog.String("error", err.Error()))
		return
	}
	if err := p.rc.Flush(); err != nil {
		p.log.Debug("progress flush failed", slog.String("error", err.Error()))
	}
}

func (p *progressStream) finish(body []byte) (streamed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if !p.started {
		return false
	}
	p.eventLocked(body)
	return true
}
