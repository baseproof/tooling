package shipper

import (
	"context"
	"testing"

	sdklog "github.com/baseproof/baseproof/log"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/baseproof/tooling/services/ledger/wal"
)

func lastNamed(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for i := len(spans) - 1; i >= 0; i-- {
		if spans[i].Name() == name {
			return spans[i]
		}
	}
	return nil
}

// THE spine: shipOne RESUMES the admission trace carried on the entry's Meta, so
// admission → shipper.ship → bytestore.put is ONE trace per entry across the
// asynchronous WAL boundary. This is the resume half (capture is proven in the
// wal package).
func TestShipOne_ContinuesAdmissionTrace(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	// An admission span; capture its traceparent as the WAL would, then end it
	// (the async ship runs long after admission returned 202).
	ctxA, admit := tp.Tracer("admission").Start(context.Background(), "admission")
	admitTID := admit.SpanContext().TraceID()
	traceparent := sdklog.TraceparentFromCtx(ctxA)
	admit.End()

	w := newFakeWAL()
	w.seed(0, hashFor(0), wireFor(0))
	w.metas[hashFor(0)].TraceContext = traceparent // what Submit would have stored

	s := NewShipper(w, newFakeBytestore(), fastConfig())
	s.shipOne(context.Background(), wal.SequencedEntry{Seq: 0, Hash: hashFor(0)})

	spans := rec.Ended()
	ship := lastNamed(spans, "shipper.ship")
	put := lastNamed(spans, "bytestore.put")
	if ship == nil || put == nil {
		t.Fatalf("missing spans: ship=%v put=%v (have %d)", ship != nil, put != nil, len(spans))
	}
	if ship.SpanContext().TraceID() != admitTID {
		t.Fatalf("NOT stitched: ship trace %s != admission trace %s", ship.SpanContext().TraceID(), admitTID)
	}
	if put.Parent().SpanID() != ship.SpanContext().SpanID() {
		t.Fatalf("bytestore.put parent %s != ship span %s", put.Parent().SpanID(), ship.SpanContext().SpanID())
	}
	// The ship span is a child of the (remote) admission span.
	if ship.Parent().TraceID() != admitTID || !ship.Parent().IsValid() {
		t.Fatalf("ship parent not the admission span: %v", ship.Parent())
	}
}

// Without a stored traceparent (unsampled/tracing-off entry) shipOne still ships
// — the ship span is just a new root rather than a continuation.
func TestShipOne_NoTrace_NewRoot(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	w := newFakeWAL()
	w.seed(0, hashFor(0), wireFor(0)) // seed leaves TraceContext == ""
	s := NewShipper(w, newFakeBytestore(), fastConfig())
	s.shipOne(context.Background(), wal.SequencedEntry{Seq: 0, Hash: hashFor(0)})

	ship := lastNamed(rec.Ended(), "shipper.ship")
	if ship == nil {
		t.Fatal("no ship span")
	}
	if ship.Parent().IsValid() {
		t.Errorf("expected a root ship span (no admission trace), got parent %v", ship.Parent())
	}
	if !ship.SpanContext().TraceID().IsValid() {
		t.Error("ship span has no valid trace id")
	}
}
