package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestLoggerFormatsRedactionAndTraceContext(t *testing.T) {
	t.Parallel()
	if got := ParseLevel("debug"); got != slog.LevelDebug {
		t.Fatalf("ParseLevel(debug) = %v", got)
	}
	if got := ParseLevel("not-a-level"); got != slog.LevelInfo {
		t.Fatalf("ParseLevel(invalid) = %v, want info", got)
	}

	var jsonBuf bytes.Buffer
	jlog := NewLogger(&jsonBuf, "debug", "json").With(slog.String("svc", "gw")).WithGroup("req")
	tid, err := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := trace.SpanIDFromHex("0102030405060708")
	if err != nil {
		t.Fatal(err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(t.Context(), sc)
	jlog.InfoContext(
		ctx,
		"redaction check",
		slog.String("authorization", "Bearer super-secret"),
		slog.String("token", "tok123"),
		slog.String("password", "hunter2"),
		slog.String("safe", "visible"),
	)
	out := jsonBuf.String()
	for _, leaked := range []string{"super-secret", "tok123", "hunter2"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("secret %q leaked into log: %s", leaked, out)
		}
	}
	if !strings.Contains(out, "[redacted]") || !strings.Contains(out, "visible") ||
		!strings.Contains(out, tid.String()) || !strings.Contains(out, sid.String()) {
		t.Fatalf("missing expected log fields: %s", out)
	}

	var textBuf bytes.Buffer
	tlog := NewLogger(&textBuf, "warn", "text")
	tlog.Info("dropped-info")
	tlog.Warn("kept-warn", slog.String("client_secret", "shh"))
	tout := textBuf.String()
	if strings.Contains(tout, "dropped-info") || !strings.Contains(tout, "kept-warn") || strings.Contains(tout, "shh") {
		t.Fatalf("unexpected text log: %s", tout)
	}
}

func TestMetricsAndTracing(t *testing.T) {
	t.Parallel()
	m := NewMetrics()
	if m.Registry == nil || m.Requests == nil || m.IdempotencyRejections == nil || m.ApprovalVerifications == nil ||
		m.BundleVerified == nil {
		t.Fatal("metrics registry or collectors not initialized")
	}
	m.BundleVerified.Set(1)
	m.IdempotencyRejections.Inc()
	m.ApprovalVerifications.WithLabelValues("ok").Inc()
	mfs, err := m.Registry.Gather()
	if err != nil || len(mfs) == 0 {
		t.Fatalf("gather metrics failed: %v", err)
	}

	tr, err := NewTracing(t.Context(), "tollkeeper", "test", "", 1.0)
	if err != nil {
		t.Fatalf("noop tracing: %v", err)
	}
	if tr.Tracer() == nil {
		t.Fatal("expected non-nil noop tracer")
	}
	if err := tr.Shutdown(t.Context()); err != nil {
		t.Fatalf("noop shutdown: %v", err)
	}

	trOTLP, err := NewTracing(t.Context(), "tollkeeper", "test", "http://127.0.0.1:4318/v1/traces", 0.5)
	if err != nil {
		t.Fatalf("otlp tracing init: %v", err)
	}
	if trOTLP.Tracer() == nil {
		t.Fatal("expected non-nil otlp tracer")
	}
	if err := trOTLP.Shutdown(t.Context()); err != nil {
		t.Fatalf("otlp shutdown: %v", err)
	}
}
