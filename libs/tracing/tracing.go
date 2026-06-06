/*
Package tracing is the shared OpenTelemetry trace bootstrap for every
ClearCompass service binary (witness, auditor, network-api, aggregator, …).

One call — Setup — builds a TracerProvider from an endpoint string, sets it as
the process-global provider, installs the global W3C propagator, and returns a
shutdown closure. After Setup, the SDK trace surface (log.OTelHandler inbound,
log.WithOTel outbound) carries every request as one trace across component hops,
and the sampler keeps marked batch/lifecycle spans always-on while ratio-sampling
high-cardinality per-entry traces.

This mirrors the ledger's lifecycle.NewTracerProvider (which the ledger keeps for
its richer shutdown-chain integration) so every binary samples and exports
identically.

Endpoint semantics:

	""        → NoOp provider (zero overhead; the default for tests/laptop)
	"stdout"  → spans to stderr (pretty), for local inspection
	host:port → OTLP HTTP exporter (http:// ⇒ insecure; https:// or bare ⇒ TLS)
*/
package tracing

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config configures Setup.
type Config struct {
	// ServiceName is the OTel resource service.name. Required.
	ServiceName string
	// ServiceVersion is the OTel resource service.version. Defaults to "dev".
	ServiceVersion string
	// Environment is the OTel resource deployment.environment. Defaults to "dev".
	Environment string
	// Endpoint selects the exporter (see package doc). "" ⇒ NoOp.
	Endpoint string
	// SampleRatio samples high-cardinality per-entry traces; marked batch roots
	// are always recorded regardless. 0 ⇒ 1.0 (sample everything).
	SampleRatio float64
}

// Setup installs the global TracerProvider + W3C propagator and returns a
// shutdown closure (flushes spans; bind it to the binary's shutdown path).
// Always installs propagation — even on the NoOp path — so a service that does
// not export its own spans still forwards traceparent on outbound calls,
// keeping the cross-component trace_id intact. Always returns a usable shutdown.
func Setup(cfg Config) (func(context.Context) error, error) {
	// Propagation first: harmless on NoOp, and required for the trace to flow.
	sdklog.InstallPropagation()

	if cfg.ServiceName == "" {
		cfg.ServiceName = "service"
	}
	if cfg.ServiceVersion == "" {
		cfg.ServiceVersion = "dev"
	}
	if cfg.Environment == "" {
		cfg.Environment = "dev"
	}
	if cfg.SampleRatio == 0 {
		cfg.SampleRatio = 1.0
	}

	if cfg.Endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: resource: %w", err)
	}

	var exporter sdktrace.SpanExporter
	if cfg.Endpoint == "stdout" {
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("tracing: stdout exporter: %w", err)
		}
	} else {
		ep := cfg.Endpoint
		insecure := false
		if strings.HasPrefix(ep, "http://") {
			ep, insecure = strings.TrimPrefix(ep, "http://"), true
		} else if strings.HasPrefix(ep, "https://") {
			ep = strings.TrimPrefix(ep, "https://")
		}
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(ep),
			otlptracehttp.WithTimeout(10 * time.Second),
		}
		if insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptrace.New(context.Background(), otlptracehttp.NewClient(opts...))
		if err != nil {
			return nil, fmt.Errorf("tracing: otlp http exporter (%s): %w", cfg.Endpoint, err)
		}
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdklog.SampleRatioOrMarked(cfg.SampleRatio)),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
