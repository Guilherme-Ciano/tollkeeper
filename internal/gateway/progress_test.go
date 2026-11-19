package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

type progressCaller struct {
	scriptedCaller
}

func (c *progressCaller) CallTool(ctx context.Context, call upstream.Call) (*mcp.CallToolResult, error) {
	if call.Progress != nil {
		for _, v := range []float64{0, 50, 100} {
			call.Progress(&mcp.ProgressNotificationParams{ProgressToken: "tk-upstream", Progress: v, Total: 100})
		}
	}
	return c.scriptedCaller.CallTool(ctx, call)
}

func TestProgressIsRelayedAsServerSentEvents(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	s := newDiffSide(t, false, schema)
	caller := &progressCaller{}
	s.gw.upstreams["up"] = caller
	meta := strings.Replace(statelessMeta, `"_meta":{`, `"_meta":{"progressToken":"client-7",`, 1)
	got := s.do(t, statelessHeaders(), callBody(`1`, `"arguments":{"mode":"text"},`+meta))
	if got.status != 200 || got.contentType != "text/event-stream" {
		t.Fatalf("not streamed: %+v", got)
	}
	events := strings.Split(strings.TrimSpace(got.body), "\n\n")
	if len(events) != 4 {
		t.Fatalf("want 3 progress events and the result, got %d: %s", len(events), got.body)
	}
	for i, want := range []string{`"progress":0,`, `"progress":50,`, `"progress":100,`} {
		ev := events[i]
		if !strings.HasPrefix(ev, "event: message\ndata: ") || !strings.Contains(ev, `"progressToken":"client-7"`) ||
			!strings.Contains(ev, want) || strings.Contains(ev, "tk-upstream") {
			t.Fatalf("event %d: %s", i, ev)
		}
	}
	if !strings.Contains(events[3], `"id":1,"result":`) {
		t.Fatalf("last event is not the result: %s", events[3])
	}
}

func TestNoProgressTokenKeepsJSON(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	s := newDiffSide(t, false, schema)
	s.gw.upstreams["up"] = &progressCaller{}
	got := s.do(t, statelessHeaders(), callBody(`1`, `"arguments":{"mode":"text"},`+statelessMeta))
	if got.contentType != "application/json" || !strings.HasPrefix(got.body, `{"jsonrpc":"2.0","id":1,"result"`) {
		t.Fatalf("response changed without a progress token: %+v", got)
	}
}

func TestClientProgressToken(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		`"a"`: true, `7`: true, `-3`: true, `1.5`: false, `null`: false, `{}`: false, `"\x"`: false,
	}
	for raw, want := range cases {
		_, ok := clientProgressToken(map[string]json.RawMessage{"progressToken": json.RawMessage(raw)})
		if ok != want {
			t.Errorf("%s: got %t", raw, ok)
		}
	}
}
