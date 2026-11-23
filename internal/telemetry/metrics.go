package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const (
	labelUpstream = "upstream"
	labelRule     = "rule"
	labelResult   = "result"
)

type Metrics struct {
	Registry        *prometheus.Registry
	Requests        *prometheus.CounterVec
	Duration        *prometheus.HistogramVec
	Overhead        prometheus.Histogram
	CallDispatch    *prometheus.CounterVec
	UpstreamLatency *prometheus.HistogramVec
	PolicyDecisions *prometheus.CounterVec
	PolicyShadow    *prometheus.CounterVec
	ConfigReloads   *prometheus.CounterVec
	RateLimited     *prometheus.CounterVec
	AuthFailures    *prometheus.CounterVec
	AuditQueue      prometheus.Gauge
	AuditDropped    prometheus.Counter
	AuditErrors     prometheus.Counter
	AuditWritten    prometheus.Counter
	AuditExport     *prometheus.CounterVec
	UpstreamUp      *prometheus.GaugeVec
	BreakerState    *prometheus.GaugeVec
	CatalogTools    prometheus.Gauge
	CatalogRejected *prometheus.CounterVec
	PinUnapproved   *prometheus.GaugeVec
	RateBackendErrs prometheus.Counter

	AnchorAttempts     *prometheus.CounterVec
	AnchorDuration     prometheus.Histogram
	AnchorLastSuccess  prometheus.Gauge
	AnchorCoveredSeq   prometheus.Gauge
	AuditVerifyRuns    *prometheus.CounterVec
	AuditVerifyLastSeq prometheus.Gauge
	AuditVerifyHealthy prometheus.Gauge
}

func latencyBuckets() []float64 {
	return []float64{
		0.00005,
		0.0001,
		0.00025,
		0.0005,
		0.001,
		0.0025,
		0.005,
		0.01,
		0.025,
		0.05,
		0.1,
		0.25,
		0.5,
		1,
		2.5,
		5,
		10,
	}
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_requests_total", Help: "MCP requests by method, tool, upstream and outcome.",
		}, []string{"method", "tool", labelUpstream, "outcome"}),
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "mcpgw_request_duration_seconds", Help: "End-to-end MCP request duration.",
			Buckets: latencyBuckets(), NativeHistogramBucketFactor: 1.1,
		}, []string{"method"}),
		Overhead: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "mcpgw_gateway_overhead_seconds", Help: "tools/call duration minus upstream call duration.",
			Buckets: latencyBuckets(), NativeHistogramBucketFactor: 1.1,
		}),
		CallDispatch: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_tools_call_dispatch_total",
			Help: "Admitted tools/call requests by dispatch path (fast or sdk).",
		}, []string{"path"}),
		UpstreamLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "mcpgw_upstream_duration_seconds", Help: "Upstream tools/call duration.",
			Buckets: latencyBuckets(), NativeHistogramBucketFactor: 1.1,
		}, []string{labelUpstream}),
		ConfigReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_config_reloads_total",
			Help: "Config reloads by result: ok, invalid or audit_failed.",
		}, []string{labelResult}),
		PolicyShadow: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_policy_shadow_decisions_total",
			Help: "Calls a shadow rule would have decided, by rule, its effect and the effect actually applied.",
		}, []string{labelRule, "shadow_effect", "effect"}),
		PolicyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_policy_decisions_total", Help: "Policy decisions by effect and rule.",
		}, []string{"effect", labelRule}),
		RateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_ratelimit_rejections_total", Help: "Requests rejected by rate limit rule.",
		}, []string{labelRule}),
		AuthFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_auth_failures_total", Help: "Rejected bearer tokens by reason.",
		}, []string{"reason"}),
		AuditQueue: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpgw_audit_queue_depth", Help: "Audit events waiting for the sequencer.",
		}),
		AuditDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpgw_audit_dropped_total", Help: "Audit events dropped in fail_open mode.",
		}),
		AuditErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpgw_audit_sink_errors_total", Help: "Audit sink write failures.",
		}),
		AuditExport: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_audit_otlp_records_total",
			Help: "Audit records sent to the OTLP log sink, by result: exported or dropped.",
		}, []string{labelResult}),
		AuditWritten: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpgw_audit_records_written_total", Help: "Audit events written.",
		}),
		UpstreamUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mcpgw_upstream_up", Help: "1 when the upstream session is connected.",
		}, []string{labelUpstream}),
		BreakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mcpgw_breaker_state", Help: "Circuit breaker state: 0 closed, 1 half-open, 2 open.",
		}, []string{labelUpstream}),
		CatalogTools: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpgw_catalog_tools", Help: "Tools in the aggregated catalog.",
		}),
		CatalogRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_catalog_rejected_tools_total", Help: "Upstream tools rejected at registration.",
		}, []string{labelUpstream}),
		PinUnapproved: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mcpgw_pin_unapproved_tools",
			Help: "Catalog tools whose definition is new or differs from the approved pin.",
		}, []string{"status"}),
		RateBackendErrs: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpgw_ratelimit_backend_errors_total",
			Help: "Shared rate limit backend failures answered by the configured fallback.",
		}),
		AnchorAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_audit_anchor_attempts_total",
			Help: "Checkpoint anchoring attempts by outcome: ok, retry, rejected, invalid_receipt, dropped.",
		}, []string{"outcome"}),
		AnchorDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "mcpgw_audit_anchor_duration_seconds", Help: "Time to submit a checkpoint to the transparency log.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 40, 60},
		}),
		AnchorLastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpgw_audit_anchor_last_success_timestamp_seconds",
			Help: "Unix time of the last checkpoint anchored in the transparency log.",
		}),
		AnchorCoveredSeq: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpgw_audit_anchor_covered_seq", Help: "Audit sequence number covered by the latest anchor.",
		}),
		AuditVerifyRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_audit_verify_runs_total",
			Help: "Continuous audit chain verification runs by result: ok or failed.",
		}, []string{labelResult}),
		AuditVerifyLastSeq: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpgw_audit_verify_last_seq",
			Help: "Last sequence number verified by the continuous audit watchdog.",
		}),
		AuditVerifyHealthy: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpgw_audit_verify_healthy",
			Help: "1 when the latest continuous audit verification passed, 0 otherwise.",
		}),
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.Requests,
		m.Duration,
		m.Overhead,
		m.CallDispatch,
		m.UpstreamLatency,
		m.PolicyDecisions,
		m.PolicyShadow,
		m.ConfigReloads,
		m.RateLimited,
		m.AuthFailures,
		m.AuditQueue,
		m.AuditDropped,
		m.AuditErrors,
		m.AuditWritten,
		m.AuditExport,
		m.UpstreamUp,
		m.BreakerState,
		m.CatalogTools,
		m.CatalogRejected,
		m.PinUnapproved,
		m.RateBackendErrs,
		m.AnchorAttempts,
		m.AnchorDuration,
		m.AnchorLastSuccess,
		m.AnchorCoveredSeq,
		m.AuditVerifyRuns,
		m.AuditVerifyLastSeq,
		m.AuditVerifyHealthy,
	)
	return m
}
