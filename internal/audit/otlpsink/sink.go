package otlpsink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

const maxErrorBody = 4 << 10

type Hooks struct {
	Exported func(n int)
	Dropped  func(n int)
	Failed   func(err error)
}

type Options struct {
	Endpoint string
	Headers  map[string]string
	Service  string
	Version  string
	Batch    int
	Queue    int
	Interval time.Duration
	Client   *http.Client
	Hooks    Hooks
}

type Sink struct {
	o  Options
	ch chan audit.Row
}

func New(o Options) *Sink {
	if o.Batch <= 0 {
		o.Batch = 512
	}
	if o.Queue <= 0 {
		o.Queue = 10000
	}
	if o.Interval <= 0 {
		o.Interval = 2 * time.Second
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Sink{o: o, ch: make(chan audit.Row, o.Queue)}
}

func (s *Sink) Committed(rows []audit.Row) {
	dropped := 0
	for i := range rows {
		r := rows[i]
		r.Raw = bytes.Clone(r.Raw)
		select {
		case s.ch <- r:
		default:
			dropped++
		}
	}
	if dropped > 0 && s.o.Hooks.Dropped != nil {
		s.o.Hooks.Dropped(dropped)
	}
}

func (s *Sink) Run(ctx context.Context) {
	tick := time.NewTicker(s.o.Interval)
	defer tick.Stop()
	batch := make([]audit.Row, 0, s.o.Batch)
	flush := func(ctx context.Context) {
		if len(batch) == 0 {
			return
		}
		s.export(ctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			for len(batch) < s.o.Batch {
				select {
				case r := <-s.ch:
					batch = append(batch, r)
					continue
				default:
				}
				break
			}
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.o.Client.Timeout)
			flush(fctx)
			cancel()
			return
		case r := <-s.ch:
			batch = append(batch, r)
			if len(batch) >= s.o.Batch {
				flush(ctx)
			}
		case <-tick.C:
			flush(ctx)
		}
	}
}

func (s *Sink) export(ctx context.Context, rows []audit.Row) {
	body, err := json.Marshal(s.payload(rows))
	if err == nil {
		err = s.post(ctx, body)
	}
	if err != nil {
		if s.o.Hooks.Failed != nil {
			s.o.Hooks.Failed(err)
		}
		if s.o.Hooks.Dropped != nil {
			s.o.Hooks.Dropped(len(rows))
		}
		return
	}
	if s.o.Hooks.Exported != nil {
		s.o.Hooks.Exported(len(rows))
	}
}

func (s *Sink) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.o.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.o.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.o.Client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp export: %w", err)
	}
	defer resp.Body.Close()
	msg, rerr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if resp.StatusCode/100 != 2 {
		if rerr != nil {
			msg = nil
		}
		return fmt.Errorf("otlp export: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

type anyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"`
	BoolValue   *bool   `json:"boolValue,omitempty"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

type logRecord struct {
	TimeUnixNano         string     `json:"timeUnixNano"`
	ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
	SeverityNumber       int        `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 anyValue   `json:"body"`
	Attributes           []keyValue `json:"attributes"`
}

type payload struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

type resourceLogs struct {
	Resource  resource    `json:"resource"`
	ScopeLogs []scopeLogs `json:"scopeLogs"`
}

type resource struct {
	Attributes []keyValue `json:"attributes"`
}

type scopeLogs struct {
	Scope      scope       `json:"scope"`
	LogRecords []logRecord `json:"logRecords"`
}

type scope struct {
	Name string `json:"name"`
}

func str(k, v string) keyValue {
	return keyValue{Key: k, Value: anyValue{StringValue: &v}}
}

func num(k string, v uint64) keyValue {
	s := strconv.FormatUint(v, 10)
	return keyValue{Key: k, Value: anyValue{IntValue: &s}}
}

func (s *Sink) payload(rows []audit.Row) payload {
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	records := make([]logRecord, 0, len(rows))
	for i := range rows {
		records = append(records, record(&rows[i], now))
	}
	return payload{ResourceLogs: []resourceLogs{{
		Resource: resource{Attributes: []keyValue{
			str("service.name", s.o.Service), str("service.version", s.o.Version),
		}},
		ScopeLogs: []scopeLogs{{Scope: scope{Name: "tollkeeper.audit"}, LogRecords: records}},
	}}}
}

func record(r *audit.Row, observed string) logRecord {
	body := string(r.Raw)
	attrs := []keyValue{
		str("audit.chain_id", r.ChainID), num("audit.seq", r.Seq), str("audit.kind", r.Kind),
		str("audit.hash", r.Hash), str("audit.prev", r.Prev),
	}
	sev, sevText := 9, "INFO"
	var b audit.Body
	if r.Kind == audit.KindEvent && json.Unmarshal(r.Raw, &b) == nil && b.Event != nil {
		e := b.Event
		for _, kv := range [][2]string{
			{"audit.phase", e.Phase},
			{"audit.decision", e.Decision},
			{"audit.rule", e.Rule},
			{"mcp.method.name", e.Method},
			{"gen_ai.tool.name", e.Tool},
			{"mcp.upstream", e.Upstream},
			{"enduser.id", e.Subject},
			{"client.id", e.ClientID},
			{"trace_id", e.TraceID},
			{"mcp.request.id", e.RequestID},
			{"audit.error", e.Error},
		} {
			if kv[1] != "" {
				attrs = append(attrs, str(kv[0], kv[1]))
			}
		}
		if e.Decision != audit.DecisionAllow || e.Error != "" {
			sev, sevText = 13, "WARN"
		}
	}
	return logRecord{
		TimeUnixNano: strconv.FormatInt(r.TS.UnixNano(), 10), ObservedTimeUnixNano: observed,
		SeverityNumber: sev, SeverityText: sevText, Body: anyValue{StringValue: &body}, Attributes: attrs,
	}
}
