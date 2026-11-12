package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const labelUpstream = "upstream"

type Metrics struct {
	Registry        *prometheus.Registry
	Requests        *prometheus.CounterVec
	Duration        *prometheus.HistogramVec
	Overhead        prometheus.Histogram
	UpstreamLatency *prometheus.HistogramVec
	PolicyDecisions *prometheus.CounterVec
	RateLimited     *prometheus.CounterVec
	AuthFailures    *prometheus.CounterVec
	AuditQueue      prometheus.Gauge
	AuditDropped    prometheus.Counter
	AuditErrors     prometheus.Counter
	AuditWritten    prometheus.Counter
	UpstreamUp      *prometheus.GaugeVec
	BreakerState    *prometheus.GaugeVec
	CatalogTools    prometheus.Gauge
	CatalogRejected *prometheus.CounterVec
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
		UpstreamLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "mcpgw_upstream_duration_seconds", Help: "Upstream tools/call duration.",
			Buckets: latencyBuckets(), NativeHistogramBucketFactor: 1.1,
		}, []string{labelUpstream}),
		PolicyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_policy_decisions_total", Help: "Policy decisions by effect and rule.",
		}, []string{"effect", "rule"}),
		RateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgw_ratelimit_rejections_total", Help: "Requests rejected by rate limit rule.",
		}, []string{"rule"}),
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
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.Requests, m.Duration, m.Overhead, m.UpstreamLatency, m.PolicyDecisions, m.RateLimited, m.AuthFailures,
		m.AuditQueue, m.AuditDropped, m.AuditErrors, m.AuditWritten, m.UpstreamUp, m.BreakerState,
		m.CatalogTools, m.CatalogRejected,
	)
	return m
}
