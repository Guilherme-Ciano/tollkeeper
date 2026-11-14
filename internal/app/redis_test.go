package app

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func postEcho(t *testing.T, url string) int {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake__echo","arguments":{"text":"x"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"raw","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "fake__echo")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

func TestRedisRateLimitIsSharedAcrossReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	up := fakeUpstream(t, &headerLog{})
	replica := func() string {
		cfg := testConfig(t, up.URL)
		cfg.RateLimits.Store = config.RateStoreRedis
		cfg.RateLimits.Redis.Addrs = []string{mr.Addr()}
		cfg.RateLimits.Redis.OnError = config.RedisOnErrorDeny
		cfg.RateLimits.Rules = []config.RateRule{
			{Name: "one-per-hour", Tools: []string{"fake__*"}, Per: config.PerSubjectTool, Rate: "1/h", Burst: 1},
		}
		return startApp(t, cfg)
	}
	a, b := replica(), replica()
	if code := postEcho(t, a); code != http.StatusOK {
		t.Fatalf("replica a: status %d", code)
	}
	if code := postEcho(t, b); code != http.StatusTooManyRequests {
		t.Fatalf("replica b ignored the shared limit: status %d", code)
	}
	if len(mr.Keys()) == 0 {
		t.Fatal("no rate limit state written to redis")
	}
}
