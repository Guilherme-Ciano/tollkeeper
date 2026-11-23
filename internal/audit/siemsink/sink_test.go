package siemsink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

func sampleAuditRow(t *testing.T, decision string) audit.Row {
	t.Helper()
	body := audit.Body{
		Seq:     1,
		TS:      time.Date(2026, 11, 23, 16, 0, 0, 0, time.UTC).UnixNano(),
		ChainID: "prod-1",
		Prev:    audit.ZeroHash,
		Event: &audit.Event{
			Phase:     audit.PhaseDecision,
			RequestID: "req-1",
			Subject:   "alice",
			Tenant:    "acme",
			Actor:     "agent-1",
			Method:    "tools/call",
			Tool:      "crm__delete",
			Decision:  decision,
			Rule:      "deny-delete",
			Reason:    "policy denied",
		},
	}
	raw, err := json.Marshal(&body)
	if err != nil {
		t.Fatal(err)
	}
	return audit.Row{
		ChainID: body.ChainID,
		Seq:     body.Seq,
		TS:      time.Unix(0, body.TS).UTC(),
		Kind:    audit.KindEvent,
		Hash:    "abcd1234",
		Prev:    body.Prev,
		Raw:     raw,
	}
}

func TestSIEMSinkFormatsJSONSplunkAndCEF(t *testing.T) {
	t.Parallel()
	row := sampleAuditRow(t, audit.DecisionDeny)

	cases := []struct {
		name      string
		format    string
		wantCT    string
		wantSub   string
		wantToken string
	}{
		{
			name:    "json",
			format:  FormatJSON,
			wantCT:  "application/json",
			wantSub: `"severity":"WARN"`,
		},
		{
			name:      "splunk_hec",
			format:    FormatSplunkHEC,
			wantCT:    "application/json",
			wantSub:   `"sourcetype":"tollkeeper:audit"`,
			wantToken: "Splunk hec-token",
		},
		{
			name:    "cef",
			format:  FormatCEF,
			wantCT:  "text/plain; charset=utf-8",
			wantSub: "CEF:0|Tollkeeper|MCPGateway|1.5.0|deny|tools/call|7|",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			var gotBody, gotCT, gotAuth string
			exportedCh := make(chan int, 1)
			failedCh := make(chan error, 1)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				mu.Lock()
				gotBody = string(b)
				gotCT = r.Header.Get("Content-Type")
				gotAuth = r.Header.Get("Authorization")
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			headers := map[string]string{}
			if tc.wantToken != "" {
				headers["Authorization"] = tc.wantToken
			}
			var exported atomic.Int64
			s := New(Options{
				Endpoint: srv.URL,
				Format:   tc.format,
				Headers:  headers,
				Index:    "security",
				Version:  "1.5.0",
				Batch:    1,
				Interval: 10 * time.Millisecond,
				Client:   srv.Client(),
				Hooks: Hooks{
					Exported: func(n int) {
						exported.Add(int64(n))
						select {
						case exportedCh <- n:
						default:
						}
					},
					Failed: func(err error) {
						select {
						case failedCh <- err:
						default:
						}
					},
				},
			})

			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.Run(ctx)
			}()

			s.Committed([]audit.Row{row})
			select {
			case err := <-failedCh:
				t.Fatalf("unexpected SIEM failure: %v", err)
			case <-exportedCh:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for SIEM delivery")
			}
			cancel()
			<-done

			mu.Lock()
			defer mu.Unlock()
			if gotCT != tc.wantCT {
				t.Fatalf("content-type = %q, want %q", gotCT, tc.wantCT)
			}
			if !strings.Contains(gotBody, tc.wantSub) {
				t.Fatalf("body %q missing %q", gotBody, tc.wantSub)
			}
			if tc.wantToken != "" && gotAuth != tc.wantToken {
				t.Fatalf("authorization = %q, want %q", gotAuth, tc.wantToken)
			}
			if exported.Load() != 1 {
				t.Fatalf("exported = %d, want 1", exported.Load())
			}
		})
	}
}

func TestSIEMSinkQueueDropAndServerErrors(t *testing.T) {
	t.Parallel()
	row := sampleAuditRow(t, audit.DecisionAllow)

	var dropped atomic.Int64
	failedCh := make(chan error, 4)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "downstream unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := New(Options{
		Endpoint: srv.URL,
		Format:   FormatJSON,
		Queue:    1,
		Batch:    1,
		Interval: 10 * time.Millisecond,
		Client:   srv.Client(),
		Hooks: Hooks{
			Dropped: func(n int) {
				dropped.Add(int64(n))
			},
			Failed: func(err error) {
				select {
				case failedCh <- err:
				default:
				}
			},
		},
	})

	s.Committed([]audit.Row{row, row})
	if dropped.Load() != 1 {
		t.Fatalf("queue overflow dropped = %d, want 1", dropped.Load())
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	select {
	case err := <-failedCh:
		if !strings.Contains(err.Error(), "status 503") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for error hook")
	}
	cancel()
	<-done

	if dropped.Load() < 2 {
		t.Fatalf("total dropped = %d, want >= 2", dropped.Load())
	}
}

func TestSIEMSinkDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redir.Close()

	failedCh := make(chan error, 1)
	s := New(Options{
		Endpoint: redir.URL,
		Format:   FormatJSON,
		Batch:    1,
		Interval: 10 * time.Millisecond,
		Timeout:  2 * time.Second,
		Hooks: Hooks{
			Failed: func(err error) {
				select {
				case failedCh <- err:
				default:
				}
			},
		},
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	s.Committed([]audit.Row{sampleAuditRow(t, audit.DecisionAllow)})
	select {
	case err := <-failedCh:
		if !strings.Contains(err.Error(), "status 302") {
			t.Fatalf("expected 302 failure, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirect rejection")
	}
	cancel()
	<-done

	if followed.Load() {
		t.Fatal("SIEM client followed redirect")
	}
}

func TestSIEMCEFEscaping(t *testing.T) {
	t.Parallel()
	if got := escapeCEFHeader("a|b\\c\nd"); got != `a\|b\\c d` {
		t.Fatalf("escapeCEFHeader = %q", got)
	}
	if got := escapeCEFExt("k=v\\x\ny"); got != `k\=v\\x\ny` {
		t.Fatalf("escapeCEFExt = %q", got)
	}
}
