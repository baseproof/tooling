package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
)

// The NoOp path (no endpoint) still installs the global W3C propagator — so a
// service that does not export its own spans still forwards traceparent — and
// returns a usable, non-nil shutdown.
func TestSetup_NoEndpoint_InstallsPropagationAndNoopShutdown(t *testing.T) {
	otel.SetTextMapPropagator(nil) // clear any prior global

	shutdown, err := Setup(Config{ServiceName: "test"})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown is nil")
	}

	p := otel.GetTextMapPropagator()
	if p == nil {
		t.Fatal("global propagator not installed")
	}
	fields := map[string]bool{}
	for _, f := range p.Fields() {
		fields[f] = true
	}
	if !fields["traceparent"] {
		t.Errorf("W3C traceparent not in propagator fields: %v", p.Fields())
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown returned error: %v", err)
	}
}

// The stdout exporter path builds a real provider + shutdown.
func TestSetup_Stdout_BuildsProvider(t *testing.T) {
	shutdown, err := Setup(Config{ServiceName: "test", Endpoint: "stdout"})
	if err != nil {
		t.Fatalf("Setup stdout: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	if shutdown == nil {
		t.Fatal("shutdown is nil")
	}
}
