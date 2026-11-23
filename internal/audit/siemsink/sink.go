package siemsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/netguard"
)

const (
	FormatJSON      = "json"
	FormatSplunkHEC = "splunk_hec"
	FormatCEF       = "cef"

	defaultSourcetype = "tollkeeper:audit"
	maxErrorBody      = 4 << 10
)

type Hooks struct {
	Exported func(n int)
	Dropped  func(n int)
	Failed   func(err error)
}

type Options struct {
	Endpoint        string
	Format          string
	Headers         map[string]string
	Index           string
	Sourcetype      string
	Service         string
	Version         string
	Batch           int
	Queue           int
	Interval        time.Duration
	Timeout         time.Duration
	BlockPrivateIPs bool
	Client          *http.Client
	Hooks           Hooks
}

type Sink struct {
	o  Options
	ch chan audit.Row
}

func New(o Options) *Sink {
	if o.Format == "" {
		o.Format = FormatJSON
	}
	if o.Sourcetype == "" {
		o.Sourcetype = defaultSourcetype
	}
	if o.Service == "" {
		o.Service = "tollkeeper"
	}
	if o.Batch <= 0 {
		o.Batch = 256
	}
	if o.Queue <= 0 {
		o.Queue = 10000
	}
	if o.Interval <= 0 {
		o.Interval = 2 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Client == nil {
		dialer := netguard.Dialer(o.Timeout, 30*time.Second, o.BlockPrivateIPs)
		o.Client = &http.Client{
			Timeout: o.Timeout,
			Transport: &http.Transport{
				DialContext:         dialer.DialContext,
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: o.Timeout,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
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
	flush := func(fctx context.Context) {
		if len(batch) == 0 {
			return
		}
		s.export(fctx, batch)
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
	body, contentType, err := s.encodeBatch(rows)
	if err == nil {
		err = s.post(ctx, body, contentType)
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

func (s *Sink) post(ctx context.Context, body []byte, contentType string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.o.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("siem request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range s.o.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.o.Client.Do(req)
	if err != nil {
		return fmt.Errorf("siem export: %w", err)
	}
	defer resp.Body.Close()
	msg, rerr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if resp.StatusCode/100 != 2 {
		if rerr != nil {
			msg = nil
		}
		return fmt.Errorf("siem export: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

type siemEvent struct {
	Timestamp string          `json:"timestamp"`
	Service   string          `json:"service"`
	Version   string          `json:"version,omitempty"`
	ChainID   string          `json:"chain_id"`
	Seq       uint64          `json:"seq"`
	Kind      string          `json:"kind"`
	Hash      string          `json:"hash"`
	Prev      string          `json:"prev"`
	Severity  string          `json:"severity"`
	Record    json.RawMessage `json:"record"`
}

type splunkHECEvent struct {
	Time       float64   `json:"time"`
	Host       string    `json:"host"`
	Source     string    `json:"source"`
	Sourcetype string    `json:"sourcetype"`
	Index      string    `json:"index,omitempty"`
	Event      siemEvent `json:"event"`
}

func (s *Sink) encodeBatch(rows []audit.Row) (body []byte, contentType string, err error) {
	switch s.o.Format {
	case FormatSplunkHEC:
		var buf bytes.Buffer
		for i := range rows {
			r := &rows[i]
			ev := s.toSIEMEvent(r)
			line, err := json.Marshal(splunkHECEvent{
				Time:       float64(r.TS.UnixNano()) / 1e9,
				Host:       s.o.Service,
				Source:     "tollkeeper",
				Sourcetype: s.o.Sourcetype,
				Index:      s.o.Index,
				Event:      ev,
			})
			if err != nil {
				return nil, "", fmt.Errorf("encode splunk hec: %w", err)
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		return buf.Bytes(), "application/json", nil
	case FormatCEF:
		var buf bytes.Buffer
		for i := range rows {
			buf.WriteString(s.formatCEF(&rows[i]))
			buf.WriteByte('\n')
		}
		return buf.Bytes(), "text/plain; charset=utf-8", nil
	default:
		out := make([]siemEvent, 0, len(rows))
		for i := range rows {
			out = append(out, s.toSIEMEvent(&rows[i]))
		}
		b, err := json.Marshal(out)
		if err != nil {
			return nil, "", fmt.Errorf("encode siem json: %w", err)
		}
		return b, "application/json", nil
	}
}

func (s *Sink) toSIEMEvent(r *audit.Row) siemEvent {
	sev := "INFO"
	var b audit.Body
	if r.Kind == audit.KindEvent && json.Unmarshal(r.Raw, &b) == nil && b.Event != nil {
		if b.Event.Decision != audit.DecisionAllow || b.Event.Error != "" {
			sev = "WARN"
		}
	}
	return siemEvent{
		Timestamp: r.TS.UTC().Format(time.RFC3339Nano),
		Service:   s.o.Service,
		Version:   s.o.Version,
		ChainID:   r.ChainID,
		Seq:       r.Seq,
		Kind:      r.Kind,
		Hash:      r.Hash,
		Prev:      r.Prev,
		Severity:  sev,
		Record:    r.Raw,
	}
}

func (s *Sink) formatCEF(r *audit.Row) string {
	ver := s.o.Version
	if ver == "" {
		ver = "dev"
	}
	classID := r.Kind
	name := "audit." + r.Kind
	sev := "3"
	exts := []string{
		"cs1Label=chainId", "cs1=" + escapeCEFExt(r.ChainID),
		"cn1Label=seq", "cn1=" + strconv.FormatUint(r.Seq, 10),
		"cs2Label=hash", "cs2=" + escapeCEFExt(r.Hash),
		"rt=" + strconv.FormatInt(r.TS.UnixMilli(), 10),
	}
	var b audit.Body
	if r.Kind == audit.KindEvent && json.Unmarshal(r.Raw, &b) == nil && b.Event != nil {
		e := b.Event
		classID = e.Decision
		name = e.Method
		if e.Decision != audit.DecisionAllow || e.Error != "" {
			sev = "7"
		}
		for _, kv := range [][2]string{
			{"suser", e.Subject},
			{"act", e.Decision},
			{"cs3", e.Tool},
			{"cs4", e.Tenant},
			{"cs5", e.Actor},
			{"cs6", e.Rule},
			{"msg", e.Reason},
		} {
			if kv[1] != "" {
				exts = append(exts, kv[0]+"="+escapeCEFExt(kv[1]))
			}
		}
	}
	return "CEF:0|Tollkeeper|MCPGateway|" + escapeCEFHeader(ver) + "|" +
		escapeCEFHeader(classID) + "|" + escapeCEFHeader(name) + "|" + sev + "|" +
		strings.Join(exts, " ")
}

func escapeCEFHeader(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ")
	return r.Replace(s)
}

func escapeCEFExt(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", " ")
	return r.Replace(s)
}
