package app

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type logCollector struct {
	mu     sync.Mutex
	bodies []string
}

func (c *logCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Body struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	b, err := io.ReadAll(r.Body)
	if err != nil || json.Unmarshal(b, &p) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rl := range p.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				c.bodies = append(c.bodies, lr.Body.StringValue)
			}
		}
	}
}

func (c *logCollector) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}

func TestAuditRecordsAreExportedOverOTLP(t *testing.T) {
	col := &logCollector{}
	srv := httptest.NewServer(col)
	defer srv.Close()
	up := fakeUpstream(t, &headerLog{})
	cfg := testConfig(t, up.URL)
	cfg.Audit.OTLP.Endpoint = srv.URL + "/v1/logs"
	cfg.Audit.OTLP.Interval = 20 * time.Millisecond
	_, url := readyApp(t, cfg)
	if r := post(t, url, "", callEcho, modernHeaders("fake__echo")); r.status != 200 {
		t.Fatalf("call: %+v", r)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(col.snapshot()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	exported := map[string]bool{}
	for _, b := range col.snapshot() {
		exported[b] = true
	}
	f, err := os.Open(cfg.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	matched := 0
	for sc.Scan() {
		var line struct {
			Body json.RawMessage `json:"body"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil && exported[string(line.Body)] {
			matched++
		}
	}
	if matched < 3 {
		t.Fatalf("only %d of the chain's records were exported verbatim; collector got %d", matched, len(exported))
	}
	if !strings.Contains(strings.Join(col.snapshot(), "\n"), `"method":"config/load"`) {
		t.Fatal("config/load record not exported")
	}
}
