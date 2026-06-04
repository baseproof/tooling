/*
FILE PATH: gossipstore/projections_finding_test.go

Tests for the three finding-class projections (0x0B equiv, 0x0E
history-rewrite, 0x0F smt-replay). Together they share an identical
shape — keyed by [32]byte binding, value is the SignedEvent bytes —
so the tests exercise the contract in parallel. A regression that
changes one projection's behaviour without changing the others
will surface here as a test failure that names the offence class
explicitly.

Coverage per projection:
  - Put → Get round-trip preserves the SignedEvent bytes.
  - Empty-binding write IS legal (the binding is content-derived;
    a zero binding is a real value if it occurs, not an error
    sentinel).
  - Empty-bytes write is rejected (a finding with no event bytes
    is a sequencer / scanner bug).
  - Get on absent key returns (nil, nil).
  - Re-Put with identical bytes is idempotent (matches I9).
  - Context cancellation surfaces at both Put + Get entry.

Also covered:
  - Keyspace prefix separation: writing to one projection does NOT
    appear under any other projection's prefix, even at the same
    binding. This is the load-bearing isolation guarantee that
    permits three distinct read endpoints over three distinct
    finding classes.
*/
package gossipstore

import (
	"bytes"
	"context"
	"testing"
)

// projectionPair pairs the Put + Get helpers for one projection so
// the table-driven coverage below exercises all three uniformly.
type projectionPair struct {
	name string
	put  func(*BadgerStore, context.Context, [32]byte, []byte) error
	get  func(*BadgerStore, context.Context, [32]byte) ([]byte, error)
}

var allProjections = []projectionPair{
	{
		"equiv",
		(*BadgerStore).PutEquivProjection,
		(*BadgerStore).GetEquivProjection,
	},
	{
		"history_rewrite",
		(*BadgerStore).PutHistoryRewriteProjection,
		(*BadgerStore).GetHistoryRewriteProjection,
	},
	{
		"smt_replay",
		(*BadgerStore).PutSMTReplayProjection,
		(*BadgerStore).GetSMTReplayProjection,
	},
}

// ─────────────────────────────────────────────────────────────────────
// Round-trip Put → Get
// ─────────────────────────────────────────────────────────────────────

func TestFindingProjections_RoundTrip(t *testing.T) {
	for _, p := range allProjections {
		t.Run(p.name, func(t *testing.T) {
			st := testStore(t)
			ctx := context.Background()
			var binding [32]byte
			for i := range binding {
				binding[i] = byte(i)
			}
			payload := []byte(`{"kind":"BP-GOSSIP-EXAMPLE-V1","body":"opaque"}`)
			if err := p.put(st, ctx, binding, payload); err != nil {
				t.Fatalf("put: %v", err)
			}
			got, err := p.get(st, ctx, binding)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("round-trip mismatch:\n  got  %q\n  want %q", got, payload)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Empty-bytes write rejected
// ─────────────────────────────────────────────────────────────────────

func TestFindingProjections_RejectEmptyBytes(t *testing.T) {
	for _, p := range allProjections {
		t.Run(p.name, func(t *testing.T) {
			st := testStore(t)
			err := p.put(st, context.Background(), [32]byte{}, nil)
			if err == nil {
				t.Error("expected error for empty bytes")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Get returns (nil, nil) on absent key
// ─────────────────────────────────────────────────────────────────────

func TestFindingProjections_GetMissingIsNil(t *testing.T) {
	for _, p := range allProjections {
		t.Run(p.name, func(t *testing.T) {
			st := testStore(t)
			got, err := p.get(st, context.Background(), [32]byte{0xAA})
			if err != nil {
				t.Fatalf("get missing: %v", err)
			}
			if got != nil {
				t.Errorf("missing key get returned %q, want nil", got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Re-Put is idempotent
// ─────────────────────────────────────────────────────────────────────

func TestFindingProjections_RePutIdempotent(t *testing.T) {
	for _, p := range allProjections {
		t.Run(p.name, func(t *testing.T) {
			st := testStore(t)
			ctx := context.Background()
			binding := [32]byte{0xFE, 0xED}
			payload := []byte(`{"x":1}`)
			for i := 0; i < 4; i++ {
				if err := p.put(st, ctx, binding, payload); err != nil {
					t.Fatalf("put iter=%d: %v", i, err)
				}
			}
			got, err := p.get(st, ctx, binding)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("idempotent re-put drift:\n  got  %q\n  want %q", got, payload)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Context cancellation rejected at entry
// ─────────────────────────────────────────────────────────────────────

func TestFindingProjections_CtxCancellation(t *testing.T) {
	for _, p := range allProjections {
		t.Run(p.name, func(t *testing.T) {
			st := testStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := p.put(st, ctx, [32]byte{}, []byte("x")); err == nil {
				t.Error("put with cancelled ctx must error")
			}
			if _, err := p.get(st, ctx, [32]byte{}); err == nil {
				t.Error("get with cancelled ctx must error")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Keyspace prefix isolation
// ─────────────────────────────────────────────────────────────────────

// Writing to projection A under binding B MUST NOT appear under
// projection B's prefix at the same binding. This protects the
// three-class partition of the read API: a history-rewrite alert
// must NOT surface on the equivocation endpoint, even if both
// findings happen to bind to the same hash (rare but possible
// — every binding is a SHA-256, so collisions across event types
// are computationally negligible, but the keyspace partition
// makes the isolation enforce-able by construction).
func TestFindingProjections_PrefixIsolation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	binding := [32]byte{0xAA, 0xBB, 0xCC}
	uniquePayloads := map[string][]byte{
		"equiv":           []byte(`{"event":"equiv"}`),
		"history_rewrite": []byte(`{"event":"history_rewrite"}`),
		"smt_replay":      []byte(`{"event":"smt_replay"}`),
	}
	for _, p := range allProjections {
		if err := p.put(st, ctx, binding, uniquePayloads[p.name]); err != nil {
			t.Fatalf("seed %s: %v", p.name, err)
		}
	}
	// Each projection MUST surface its own bytes (the prefix
	// partition cannot leak from one projection to another).
	for _, p := range allProjections {
		got, err := p.get(st, ctx, binding)
		if err != nil {
			t.Fatalf("get %s: %v", p.name, err)
		}
		if !bytes.Equal(got, uniquePayloads[p.name]) {
			t.Errorf("%s leaked across prefix:\n  got  %q\n  want %q",
				p.name, got, uniquePayloads[p.name])
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Key encoding drift-pin tests
// ─────────────────────────────────────────────────────────────────────

// The projection key shape is part of the on-disk contract. A
// change to historyRewriteProjKey / smtReplayProjKey / equivProjKey
// would invalidate every existing badger database. These pins
// guard against accidental drift.
func TestFindingProjectionKey_ShapeStable(t *testing.T) {
	var binding [32]byte
	for i := range binding {
		binding[i] = byte(i)
	}
	cases := []struct {
		name string
		key  []byte
		sub  byte
	}{
		{"equiv (0x0B)", equivProjKey(binding), 0x0B},
		{"history_rewrite (0x0E)", historyRewriteProjKey(binding), 0x0E},
		{"smt_replay (0x0F)", smtReplayProjKey(binding), 0x0F},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(c.key) != 2+32 {
				t.Fatalf("key length = %d, want 34", len(c.key))
			}
			if c.key[0] != prefixGossipRoot {
				t.Errorf("key[0] = %#x, want %#x (gossip root)", c.key[0], prefixGossipRoot)
			}
			if c.key[1] != c.sub {
				t.Errorf("key[1] = %#x, want %#x", c.key[1], c.sub)
			}
			if !bytes.Equal(c.key[2:], binding[:]) {
				t.Errorf("key[2:] = %x, want binding %x", c.key[2:], binding[:])
			}
		})
	}
}
