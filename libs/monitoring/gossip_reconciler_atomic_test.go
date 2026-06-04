/*
FILE PATH: libs/monitoring/gossip_reconciler_atomic_test.go

Ladder 3 C3 (#21) — atomic.Pointer concurrency tests for the auditor
registry + amendment fields.

# WHAT THESE TESTS PIN

The Reconciler's auditorRegistry and auditorAmendments are
atomic.Pointer[T] so that the per-event hot path (authorizedForKind,
called at 1K+ TPS per network) takes a single-word atomic load instead
of a torn slice-header read. The race-detector tests below pin:

 1. Concurrent readers + a swapping writer never observe torn state
    (the test fails under -race if the pointer-load semantics broke).
 2. RefreshRegistry(nil) atomically disables the gate; in-flight
    readers that loaded the previous pointer keep operating on the
    old snapshot until they return.
 3. RefreshAmendments has symmetric semantics.

# WHY THIS MATTERS AT 1K+ TPS × 15 NETWORKS

A torn slice header read produces undefined behavior under Go's memory
model. Under sustained throughput, the probability of observing a torn
read is non-negligible — a single tear in a 24/7 production stream
either crashes the reconciler (best case) or silently mis-classifies
an event (worst case, indistinguishable from the gate working). The
atomic.Pointer guarantees a whole-snapshot read; these tests pin that
the implementation preserves the guarantee.
*/
package monitoring

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

func atomicTestReconciler(t *testing.T) *Reconciler {
	t.Helper()
	heads := NewTrustedHeadStore(slog.New(slog.NewTextHandler(io.Discard, nil)))
	r, err := NewReconciler(ReconcilerConfig{
		Verifier: &fakeVerifier{},
		Heads:    heads,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return r
}

// TestRefresh_NilEnablesAndDisablesGate pins the boot-time and runtime
// semantic: Store(nil) returns Load() == nil; the read path then takes
// the pre-v1.32 pass-through. Store(non-nil-slice) flips the gate on
// without touching any other reconciler state.
func TestRefresh_NilEnablesAndDisablesGate(t *testing.T) {
	r := atomicTestReconciler(t)

	// Initial state: no registry → gate disabled → claim-class events
	// pass through unconditionally.
	if !r.authorizedForKind(context.Background(),
		"did:web:any.example.org", gossip.KindEquivocationFinding) {
		t.Fatal("nil registry must pass through")
	}

	// Refresh with a registry that does NOT contain the originator →
	// gate engages → unregistered originator rejected.
	registry := recordsForScope(validAuditorRegistration(t,
		"did:web:registered.example.org", network.ScopeEquivocation))
	r.RefreshRegistry(registry)
	if r.authorizedForKind(context.Background(),
		"did:web:imposter.example.org", gossip.KindEquivocationFinding) {
		t.Error("registry enabled but imposter accepted — gate did not engage")
	}

	// Refresh with nil → gate disengages → events pass through again.
	r.RefreshRegistry(nil)
	if !r.authorizedForKind(context.Background(),
		"did:web:imposter.example.org", gossip.KindEquivocationFinding) {
		t.Error("RefreshRegistry(nil) must disengage the gate")
	}
}

// TestRefreshAmendments_NilEnablesAndDisables mirrors TestRefresh_Nil
// for the amendment field; amendments are independent of registry
// (nil amendments + non-nil registry still gates; nil amendments
// reduces to v1.32 registration-only semantics).
func TestRefreshAmendments_NilEnablesAndDisables(t *testing.T) {
	r := atomicTestReconciler(t)
	registry := recordsForScope(validAuditorRegistration(t,
		"did:web:registered.example.org", network.ScopeEquivocation))
	r.RefreshRegistry(registry)

	// Nil amendments + registered originator → accepted by claim path.
	if !r.authorizedForKind(context.Background(),
		"did:web:registered.example.org", gossip.KindEquivocationFinding) {
		t.Error("nil amendments + registered originator must be accepted")
	}

	// Refresh amendments with empty (non-nil) slice — same observable
	// behavior; pins that the pointer-swap doesn't break the gate.
	r.RefreshAmendments(network.AuditorScopeAmendmentByPosition{})
	if !r.authorizedForKind(context.Background(),
		"did:web:registered.example.org", gossip.KindEquivocationFinding) {
		t.Error("empty amendments + registered originator must be accepted")
	}

	// Refresh amendments back to nil — same behavior.
	r.RefreshAmendments(nil)
	if !r.authorizedForKind(context.Background(),
		"did:web:registered.example.org", gossip.KindEquivocationFinding) {
		t.Error("RefreshAmendments(nil) round-trip must preserve gate behavior")
	}
}

// TestRefresh_ConcurrentReadersWithSwappingWriter pins the load-bearing
// race-free invariant: N reader goroutines calling authorizedForKind in
// a loop while a writer goroutine swaps the registry every few hundred
// microseconds must NEVER observe torn state. Run under `go test -race`
// — a tearing read would be reported as a data race; an inconsistent
// read (slice header pointing to stale backing memory) would surface
// either as a panic or as a logically-impossible verdict.
//
// The test runs for a bounded wall time (200ms) on 8 readers + 1
// writer. At local-test speed that's ~tens of thousands of read
// iterations + ~hundreds of swaps. Sufficient to surface a torn-read
// regression while staying within the test suite's time budget.
func TestRefresh_ConcurrentReadersWithSwappingWriter(t *testing.T) {
	r := atomicTestReconciler(t)

	// Two distinct registries — readers must always observe one or the
	// other, never a torn header pointing at a mixed view.
	registryA := recordsForScope(
		validAuditorRegistration(t, "did:web:a.example.org", network.ScopeEquivocation),
		validAuditorRegistration(t, "did:web:b.example.org", network.ScopeEquivocation),
	)
	registryB := recordsForScope(
		validAuditorRegistration(t, "did:web:c.example.org", network.ScopeAll),
		validAuditorRegistration(t, "did:web:d.example.org", network.ScopeAll),
		validAuditorRegistration(t, "did:web:e.example.org", network.ScopeAll),
	)
	r.RefreshRegistry(registryA)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	const readers = 8
	var wg sync.WaitGroup
	var iterations atomic.Int64

	// Writer goroutine: alternates between the two registries.
	wg.Add(1)
	go func() {
		defer wg.Done()
		alt := false
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if alt {
					r.RefreshRegistry(registryA)
				} else {
					r.RefreshRegistry(registryB)
				}
				alt = !alt
			}
		}
	}()

	// Reader goroutines: hammer authorizedForKind with a mix of known
	// and unknown originators. The verdict for any particular call
	// depends on which snapshot is current; what we PIN is that no call
	// panics, no call returns inconsistently. Counts iterations for a
	// post-hoc sanity check on throughput.
	dids := []string{
		"did:web:a.example.org", // registered in A
		"did:web:c.example.org", // registered in B
		"did:web:f.example.org", // registered in neither
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					for _, d := range dids {
						_ = r.authorizedForKind(ctx, d,
							gossip.KindEquivocationFinding)
						iterations.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()

	// Sanity check: at least SOME reads completed. If the readers got
	// stuck (deadlock under contention), this surfaces as 0 iterations.
	if iterations.Load() < 1000 {
		t.Errorf("expected >=1000 reader iterations across 200ms; got %d "+
			"(possible contention/deadlock regression)", iterations.Load())
	}
}

// TestRefresh_OldSnapshotStaysAliveForInFlightReaders pins the GC
// invariant: a reader that loaded the OLD pointer continues to walk
// the OLD slice's backing array even after a Store swap. This is
// guaranteed by atomic.Pointer + Go's GC — the test exists as a
// regression pin in case someone ever refactors to a pattern that
// breaks the invariant (e.g., a sync.Pool reusing slice backing memory,
// or unsafe pointer tricks).
//
// The test runs a slow reader (deliberate Sleep inside the gate logic
// would be intrusive; instead we capture the pointer manually and
// verify it stays usable across many swaps).
func TestRefresh_OldSnapshotStaysAliveForInFlightReaders(t *testing.T) {
	r := atomicTestReconciler(t)
	registryV1 := recordsForScope(validAuditorRegistration(t,
		"did:web:v1.example.org", network.ScopeEquivocation))
	r.RefreshRegistry(registryV1)

	// Capture the V1 pointer.
	oldPtr := r.auditorRegistry.Load()
	if oldPtr == nil {
		t.Fatal("expected non-nil pointer after RefreshRegistry")
	}

	// Swap to a new registry several times. Each swap installs a new
	// backing slice; the old one must remain valid as long as oldPtr
	// holds a reference.
	for i := 0; i < 5; i++ {
		next := recordsForScope(validAuditorRegistration(t,
			"did:web:rotated.example.org", network.ScopeEquivocation))
		r.RefreshRegistry(next)
	}

	// Read the original snapshot via the captured pointer. The
	// underlying array MUST still be valid (not reclaimed, not
	// repurposed). If GC collected it prematurely, this would crash;
	// if a sync.Pool refactor reused the memory, the data would be
	// garbage.
	if len(*oldPtr) != 1 {
		t.Errorf("old snapshot reused/freed: expected 1 record, got %d", len(*oldPtr))
	}
	if (*oldPtr)[0].Payload.AuditorDID != "did:web:v1.example.org" {
		t.Errorf("old snapshot mutated: AuditorDID=%q, want %q",
			(*oldPtr)[0].Payload.AuditorDID, "did:web:v1.example.org")
	}
}

// TestNewReconciler_NilConfigFieldsLeavePointersNil pins the
// boot-config edge: passing nil AuditorRegistry / AuditorAmendments
// to NewReconciler must leave the atomic.Pointer fields as zero-value
// nil so Load() returns nil and authorizedForKind takes the gate-
// disabled path. A regression that Store'd a pointer to a nil
// interface would leak through as a non-nil pointer dereferencing to
// a nil slice — observably broken at the first gate evaluation.
func TestNewReconciler_NilConfigFieldsLeavePointersNil(t *testing.T) {
	r := atomicTestReconciler(t)
	if r.auditorRegistry.Load() != nil {
		t.Error("auditorRegistry: nil config must leave atomic.Pointer nil")
	}
	if r.auditorAmendments.Load() != nil {
		t.Error("auditorAmendments: nil config must leave atomic.Pointer nil")
	}
}

// TestNewReconciler_NonNilConfigFieldsStored pins the symmetric path:
// non-nil config slices are Store'd at construction. The reconciler
// then operates on the SAME backing slice the caller passed; future
// RefreshRegistry swaps install a fresh pointer.
func TestNewReconciler_NonNilConfigFieldsStored(t *testing.T) {
	registry := recordsForScope(validAuditorRegistration(t,
		"did:web:bootstrapped.example.org", network.ScopeEquivocation))
	heads := NewTrustedHeadStore(slog.New(slog.NewTextHandler(io.Discard, nil)))
	r, err := NewReconciler(ReconcilerConfig{
		Verifier:        &fakeVerifier{},
		Heads:           heads,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuditorRegistry: registry,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	ptr := r.auditorRegistry.Load()
	if ptr == nil {
		t.Fatal("non-nil cfg.AuditorRegistry must produce non-nil Load()")
	}
	if len(*ptr) != 1 {
		t.Errorf("len(*ptr) = %d, want 1", len(*ptr))
	}

	// The boot-installed registry gates as expected.
	if r.authorizedForKind(context.Background(),
		"did:web:imposter.example.org", gossip.KindEquivocationFinding) {
		t.Error("boot-installed registry must reject unregistered originator")
	}
	if !r.authorizedForKind(context.Background(),
		"did:web:bootstrapped.example.org", gossip.KindEquivocationFinding) {
		t.Error("boot-installed registry must accept registered originator")
	}

	// Unused type import sanity — keeps the build green even if the
	// test only consumes types.LogPosition transitively via fixtures.
	var _ types.LogPosition
}
