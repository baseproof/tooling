package wal

import (
	"context"
	"crypto/sha256"
	"testing"

	sdklog "github.com/baseproof/baseproof/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// Submit must capture the admission span's W3C traceparent into the durable
// Meta (a V3 record), so the asynchronous downstream stages can resume the
// SAME trace across the WAL boundary. This is the capture half of the spine.
func TestSubmit_CapturesTraceparentIntoMeta(t *testing.T) {
	c, _ := openTestCommitter(t)

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	ctx, span := tp.Tracer("admission").Start(context.Background(), "admission")
	defer span.End()

	want := sdklog.TraceparentFromCtx(ctx)
	if want == "" {
		t.Fatal("admission span produced no traceparent")
	}

	wire := []byte("entry-wire-for-trace-capture")
	hash := sha256.Sum256(wire)
	if err := c.Submit(ctx, hash, wire, 1_000_000, nil); err != nil {
		t.Fatalf("submit: %v", err)
	}

	meta, err := c.MetaState(context.Background(), hash)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.TraceContext != want {
		t.Fatalf("captured traceparent = %q, want %q", meta.TraceContext, want)
	}
	// The captured traceparent resumes to the SAME trace the admission span ran in.
	got := trace.SpanContextFromContext(sdklog.CtxWithTraceparent(context.Background(), meta.TraceContext)).TraceID()
	if got != span.SpanContext().TraceID() {
		t.Fatalf("resumed trace id %s != admission trace id %s", got, span.SpanContext().TraceID())
	}
}

// A Submit made OUTSIDE any trace stores no trace context (V1/V2 record) — the
// byte-compat path is preserved for unsampled / tracing-off traffic.
func TestSubmit_NoTrace_NoTraceContext(t *testing.T) {
	c, _ := openTestCommitter(t)
	wire := []byte("entry-wire-no-trace")
	hash := sha256.Sum256(wire)
	if err := c.Submit(context.Background(), hash, wire, 1, nil); err != nil {
		t.Fatalf("submit: %v", err)
	}
	meta, err := c.MetaState(context.Background(), hash)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.TraceContext != "" {
		t.Fatalf("expected no trace context, got %q", meta.TraceContext)
	}
}
