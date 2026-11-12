package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type Tracing struct {
	Provider   trace.TracerProvider
	Propagator propagation.TextMapPropagator
	shutdown   func(context.Context) error
}

func (t *Tracing) Tracer() trace.Tracer {
	return t.Provider.Tracer("github.com/Guilherme-Ciano/tollkeeper")
}

func (t *Tracing) Shutdown(ctx context.Context) error {
	if t.shutdown == nil {
		return nil
	}
	return t.shutdown(ctx)
}

func NewTracing(ctx context.Context, service, version, endpoint string, ratio float64) (*Tracing, error) {
	prop := propagation.TraceContext{}
	otel.SetTextMapPropagator(prop)
	if endpoint == "" {
		return &Tracing{Provider: noop.NewTracerProvider(), Propagator: prop}, nil
	}
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	res := resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(service), semconv.ServiceVersion(version))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)
	return &Tracing{Provider: tp, Propagator: prop, shutdown: tp.Shutdown}, nil
}
