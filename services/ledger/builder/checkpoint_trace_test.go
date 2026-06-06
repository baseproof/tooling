package builder

import (
	"context"
	"fmt"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// fakeEntryTrace returns a valid, distinct W3C traceparent for every seq — as if
// each committed entry had been admitted under its own sampled trace.
type fakeEntryTrace struct{}

func (fakeEntryTrace) TraceContextAt(_ context.Context, seq uint64) (string, error) {
	// version-trace(16B)-span(8B)-sampled. seq+1 keeps both IDs non-zero (valid).
	return fmt.Sprintf("00-%032x-%016x-01", seq+1, seq+1), nil
}

func cycleSpan(spans []sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	for i := len(spans) - 1; i >= 0; i-- {
		if spans[i].Name() == "checkpoint.cycle" {
			return spans[i]
		}
	}
	return nil
}

// A working checkpoint LINKS its cycle span (N:1) to a bounded, evenly-spaced
// sample of the entries it commits — so an operator can pivot checkpoint ⇄ entry.
func TestCheckpoint_CycleLinksCommittedEntries(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	// commit at seq 41 ⇒ delta [0..41] = 42 entries; frontier at genesis.
	commit := &fakeCommit{seq: 41, root: rootN(0x11)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	loop := newLoop(commit, frontier, newFakeTiles(), &fakeWitness{}, &fakePublisher{})
	loop.SetEntryTraceReader(fakeEntryTrace{})

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}

	cycle := cycleSpan(rec.Ended())
	if cycle == nil {
		t.Fatal("no checkpoint.cycle span recorded")
	}
	// 42 entries, capped at maxCheckpointLinks → exactly maxCheckpointLinks links.
	if got := len(cycle.Links()); got != maxCheckpointLinks {
		t.Fatalf("cycle links = %d, want %d (bounded even sample over the delta)", got, maxCheckpointLinks)
	}
	// Each link targets a valid, distinct entry trace.
	seenTrace := map[trace.TraceID]bool{}
	for _, l := range cycle.Links() {
		if !l.SpanContext.IsValid() {
			t.Error("checkpoint link has an invalid span context")
		}
		seenTrace[l.SpanContext.TraceID()] = true
	}
	if len(seenTrace) != maxCheckpointLinks {
		t.Errorf("distinct linked traces = %d, want %d", len(seenTrace), maxCheckpointLinks)
	}
	// The cycle span records how many it linked.
	var linkedAttr int64 = -1
	for _, kv := range cycle.Attributes() {
		if kv.Key == "ledger.linked_entries" {
			linkedAttr = kv.Value.AsInt64()
		}
	}
	if linkedAttr != int64(maxCheckpointLinks) {
		t.Errorf("ledger.linked_entries = %d, want %d", linkedAttr, maxCheckpointLinks)
	}
}

// A small delta links exactly one-per-entry (no padding, no over-read).
func TestCheckpoint_CycleLinks_SmallDelta(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	// commit at seq 2 ⇒ delta [0..2] = 3 entries; frontier at genesis.
	commit := &fakeCommit{seq: 2, root: rootN(0x22)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	loop := newLoop(commit, frontier, newFakeTiles(), &fakeWitness{}, &fakePublisher{})
	loop.SetEntryTraceReader(fakeEntryTrace{})

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	cycle := cycleSpan(rec.Ended())
	if cycle == nil {
		t.Fatal("no checkpoint.cycle span")
	}
	if got := len(cycle.Links()); got != 3 {
		t.Fatalf("cycle links = %d, want 3 (one per entry in a 3-entry delta)", got)
	}
}

// No reader wired ⇒ the cycle span is still recorded (always-on batch trace),
// just with zero entry links.
func TestCheckpoint_NoReader_StillSpansNoLinks(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	commit := &fakeCommit{seq: 5, root: rootN(0x33)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	loop := newLoop(commit, frontier, newFakeTiles(), &fakeWitness{}, &fakePublisher{})
	// no SetEntryTraceReader

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	cycle := cycleSpan(rec.Ended())
	if cycle == nil {
		t.Fatal("cycle span must still be recorded without a reader")
	}
	if got := len(cycle.Links()); got != 0 {
		t.Errorf("links = %d, want 0 (no reader)", got)
	}
}

// An IDLE tick (nothing newly committed) must NOT emit a checkpoint.cycle span —
// the always-on batch trace must not flood the tracer at the loop cadence.
func TestCheckpoint_IdleTick_NoSpan(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	commit := &fakeCommit{seq: 7, root: rootN(0x44)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	loop := newLoop(commit, frontier, newFakeTiles(), &fakeWitness{}, &fakePublisher{})

	// First cycle: works + publishes + sets lastPublishedSize.
	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("first CheckpointOnce: %v", err)
	}
	if cycleSpan(rec.Ended()) == nil {
		t.Fatal("first (working) cycle should record a span")
	}

	// Second cycle with the SAME commit cursor: nothing new ⇒ skip ⇒ NO span.
	rec.Reset()
	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("second CheckpointOnce: %v", err)
	}
	if got := len(rec.Ended()); got != 0 {
		t.Fatalf("idle tick recorded %d spans, want 0 (must not flood)", got)
	}
}
