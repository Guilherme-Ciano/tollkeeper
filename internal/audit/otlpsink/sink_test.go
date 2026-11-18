package otlpsink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

type collector struct {
	mu       sync.Mutex
	payloads []payload
	headers  []http.Header
	status   int
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var p payload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || r.URL.Path != "/v1/logs" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.payloads = append(c.payloads, p)
	c.headers = append(c.headers, r.Header.Clone())
	status := c.status
	c.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
	}
}

func (c *collector) records() []logRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []logRecord
	for _, p := range c.payloads {
		for _, rl := range p.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				out = append(out, sl.LogRecords...)
			}
		}
	}
	return out
}

func eventRow(seq uint64, decision string) audit.Row {
	b := audit.Body{Seq: seq, TS: time.Unix(1_800_000_000, 0).UnixNano(), ChainID: "c1", Event: &audit.Event{
		Phase: "intent", Method: "tools/call", Tool: "notes__search", Subject: "alice", Decision: decision,
	}}
	raw, err := json.Marshal(b)
	if err != nil {
		panic(err)
	}
	return audit.Row{
		ChainID: "c1", Seq: seq, TS: time.Unix(0, b.TS), Kind: audit.KindEvent,
		Hash: "h" + string(rune('0'+seq)), Raw: raw,
	}
}

func attr(r logRecord, key string) string {
	for _, kv := range r.Attributes {
		if kv.Key != key {
			continue
		}
		switch {
		case kv.Value.StringValue != nil:
			return *kv.Value.StringValue
		case kv.Value.IntValue != nil:
			return *kv.Value.IntValue
		}
	}
	return ""
}

func TestExportsCommittedRowsAsOTLPLogs(t *testing.T) {
	t.Parallel()
	col := &collector{}
	srv := httptest.NewServer(col)
	defer srv.Close()
	var exported atomic.Int64
	s := New(Options{
		Endpoint: srv.URL + "/v1/logs", Headers: map[string]string{"Authorization": "Bearer k"},
		Service: "tollkeeper", Version: "test", Batch: 2, Interval: time.Hour,
		Hooks: Hooks{Exported: func(n int) { exported.Add(int64(n)) }},
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	rows := []audit.Row{eventRow(1, "allow"), eventRow(2, "deny"), eventRow(3, "allow")}
	s.Committed(rows)
	for i := range rows {
		rows[i].Raw[0] = 'X'
	}
	deadline := time.Now().Add(5 * time.Second)
	for exported.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	recs := col.records()
	if len(recs) != 3 || exported.Load() != 3 {
		t.Fatalf("exported %d, collector got %d", exported.Load(), len(recs))
	}
	if attr(recs[0], "audit.seq") != "1" || attr(recs[0], "gen_ai.tool.name") != "notes__search" ||
		attr(recs[0], "enduser.id") != "alice" || recs[0].SeverityText != "INFO" || recs[1].SeverityText != "WARN" {
		t.Fatalf("record: %+v", recs[0])
	}
	var body audit.Body
	if err := json.Unmarshal([]byte(*recs[2].Body.StringValue), &body); err != nil || body.Seq != 3 {
		t.Fatalf("body is not the committed record (caller's buffer was reused): %v %+v", err, body)
	}
	if col.headers[0].Get("Authorization") != "Bearer k" {
		t.Fatal("configured header not sent")
	}
}

func TestFullQueueAndFailingCollectorDropWithoutBlocking(t *testing.T) {
	t.Parallel()
	col := &collector{status: http.StatusServiceUnavailable}
	srv := httptest.NewServer(col)
	defer srv.Close()
	var dropped, failed atomic.Int64
	s := New(Options{
		Endpoint: srv.URL + "/v1/logs", Batch: 2, Queue: 2, Interval: time.Hour,
		Hooks: Hooks{
			Dropped: func(n int) { dropped.Add(int64(n)) },
			Failed:  func(error) { failed.Add(1) },
		},
	})
	start := time.Now()
	s.Committed([]audit.Row{eventRow(1, "allow"), eventRow(2, "allow"), eventRow(3, "allow")})
	if time.Since(start) > 100*time.Millisecond || dropped.Load() != 1 {
		t.Fatalf("overflow: dropped %d in %v", dropped.Load(), time.Since(start))
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for failed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if failed.Load() != 1 || dropped.Load() != 3 {
		t.Fatalf("failed %d, dropped %d", failed.Load(), dropped.Load())
	}
}
