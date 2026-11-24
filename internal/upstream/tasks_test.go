package upstream

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestStreamableHTTPTaskRPCAndErrors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			ID     uint64         `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch env.Method {
		case "tools/call":
			name, ok := env.Params["name"].(string)
			if !ok {
				http.Error(w, "missing name", http.StatusBadRequest)
				return
			}
			switch name {
			case "rpc_err":
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      env.ID,
					"error":   map[string]any{"code": -32602, "message": "bad args"},
				}); err != nil {
					t.Errorf("encode rpc err: %v", err)
				}
			case "http_500":
				http.Error(w, "boom", http.StatusInternalServerError)
			case "slow":
				time.Sleep(150 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			case "empty_res":
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(`{"jsonrpc":"2.0","id":1}`)); err != nil {
					t.Errorf("write empty res: %v", err)
				}
			default:
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      env.ID,
					"result":  map[string]any{"resultType": "task", "taskId": "t-99", "status": "working"},
				}); err != nil {
					t.Errorf("encode task: %v", err)
				}
			}
		case "tasks/get":
			w.Header().Set("Content-Type", "text/event-stream")
			if _, err := w.Write(
				[]byte(
					"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"taskId\":\"t-99\",\"status\":\"completed\"}}\n\n",
				),
			); err != nil {
				t.Errorf("write sse: %v", err)
			}
		case "tasks/empty_sse":
			w.Header().Set("Content-Type", "text/event-stream")
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				t.Errorf("write keepalive: %v", err)
			}
		}
	}))
	t.Cleanup(srv.Close)

	ucfg := config.Upstream{
		ID:             "jobs",
		Transport:      config.TransportStreamable,
		URL:            srv.URL,
		Timeout:        80 * time.Millisecond,
		MaxConcurrency: 1,
		Breaker:        config.Breaker{Failures: 5, OpenFor: time.Second},
	}
	u := New(ucfg, catalog.Naming{Separator: "__"}, nil, slog.New(slog.DiscardHandler), Hooks{}, "test")

	var ir mcp.InputResponseMap
	if err := json.Unmarshal([]byte(`{"q1":{"action":"accept","content":{"ok":true}}}`), &ir); err != nil {
		t.Fatal(err)
	}
	res, err := u.CallTaskTool(t.Context(), Call{
		Tool:           "run",
		Arguments:      json.RawMessage(`{"x":1}`),
		Meta:           map[string]any{"k": "v"},
		InputResponses: ir,
		RequestState:   "rs-1",
	})
	if err != nil || !strings.Contains(string(res), `"taskId":"t-99"`) {
		t.Fatalf("CallTaskTool = (%s, %v)", string(res), err)
	}

	sseRes, err := u.TaskRPC(t.Context(), "tasks/get", json.RawMessage(`{"taskId":"t-99"}`))
	if err != nil || !strings.Contains(string(sseRes), `"status":"completed"`) {
		t.Fatalf("TaskRPC SSE = (%s, %v)", string(sseRes), err)
	}

	_, err = u.CallTaskTool(t.Context(), Call{Tool: "rpc_err"})
	if je, ok := errors.AsType[*jsonrpc.Error](err); !ok || je.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("expected jsonrpc invalid params, got %v", err)
	}

	if _, err := u.CallTaskTool(t.Context(), Call{Tool: "http_500"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on HTTP 500, got %v", err)
	}

	if _, err := u.CallTaskTool(t.Context(), Call{Tool: "empty_res"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on empty result, got %v", err)
	}

	if _, err := u.TaskRPC(t.Context(), "tasks/empty_sse", json.RawMessage(`{}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on empty SSE, got %v", err)
	}

	if _, err := u.CallTaskTool(t.Context(), Call{Tool: "slow"}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout on slow call, got %v", err)
	}

	u.sem <- struct{}{}
	_, satErr := u.TaskRPC(t.Context(), "tasks/get", json.RawMessage(`{}`))
	<-u.sem
	if !errors.Is(satErr, ErrSaturated) {
		t.Fatalf("expected ErrSaturated, got %v", satErr)
	}

	stdioCfg := config.Upstream{
		ID:             "local",
		Transport:      config.TransportStdio,
		Command:        []string{"echo"},
		Timeout:        time.Second,
		MaxConcurrency: 1,
		Breaker:        config.Breaker{Failures: 5, OpenFor: time.Second},
	}
	stdioUp := New(stdioCfg, catalog.Naming{Separator: "__"}, nil, slog.New(slog.DiscardHandler), Hooks{}, "test")
	if _, err := stdioUp.TaskRPC(
		t.Context(),
		"tasks/get",
		json.RawMessage(`{}`),
	); !errors.Is(
		err,
		ErrTasksUnsupported,
	) {
		t.Fatalf("expected ErrTasksUnsupported for stdio upstream, got %v", err)
	}
}
