// FILE PATH: libs/witnessrotation/journal_resolver_test.go
//
// Tests for the journal-first position-aware resolver — including the GAP it
// closes: a process that never wires head-anchored resolution verifies every
// inbound head against the LIVE current-set snapshot. At a rotation boundary
// the ledger legitimately keeps emitting heads cosigned by the OUTGOING set
// for a while (the operationally-fuzzy cosign switch); the snapshot path
// REJECTS those transitional heads (a false fork alarm), while head-anchored
// journal resolution accepts them against their own era set.
// TestJournalResolver_TransitionalHead_BoundaryRegression pins both halves.
package witnessrotation

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/libs/auditing/gossipverify"
	"github.com/baseproof/tooling/libs/witnessrotation/internal/rottest"
)

// Static conformance: the resolver satisfies the verify path's head-anchored
// seam. (Consumer-internal seams — e.g. the auditor's equivocation
// EraWitnessSetResolver — are asserted by those consumers' own suites.)
var _ gossipverify.HeadWitnessSetResolver = (*JournalWitnessSetResolver)(nil)

const (
	jrLogDID     = "did:web:source-log.journal.test" // canonical (what findings stamp)
	jrOriginator = "did:key:zJournalOriginator"      // the gossip alias the verify path uses
)

// memRecordSource is a bare in-memory RotationRecordSource (the resolver's
// read seam in isolation; the full journal implementations have their own
// contract suites).
type memRecordSource struct {
	byLog map[string][]types.WitnessRotationRecord
}

func (m *memRecordSource) RecordsFor(_ context.Context, logDID string) ([]types.WitnessRotationRecord, error) {
	return m.byLog[logDID], nil
}

// eraKit bundles a fixture-kit set; set/keys/privs alias the kit's fields.
type eraKit struct {
	ws    *witnesstest.Set
	set   *cosign.WitnessKeySet
	keys  []types.WitnessPublicKey
	privs []*ecdsa.PrivateKey
}

func newEraKit(t *testing.T, n, k int, netID cosign.NetworkID) eraKit {
	t.Helper()
	ws := witnesstest.NewSet(t, netID, n, k)
	return eraKit{ws: ws, set: ws.KeySet, keys: ws.Keys, privs: ws.Privs}
}

// twoEraFixture journals one verified rotation s0→s1 (at seq 100, keyed by the
// CANONICAL log DID, exactly as the gossip reconciler records it) and returns
// the resolver plus both era kits.
func twoEraFixture(t *testing.T) (*JournalWitnessSetResolver, eraKit, eraKit) {
	t.Helper()
	netID := rottest.NetID()
	s0, s1 := newEraKit(t, 3, 2, netID), newEraKit(t, 3, 2, netID)
	src := &memRecordSource{byLog: map[string][]types.WitnessRotationRecord{
		jrLogDID: {{
			Rotation:     witnesstest.MintRotation(t, netID, s0.ws, s1.ws, 2),
			EffectivePos: types.LogPosition{LogDID: jrLogDID, Sequence: 100},
		}},
	}}
	r, err := NewJournalWitnessSetResolver(src, []LogTrustRoot{{
		LogDID:  jrLogDID,
		Aliases: []string{jrOriginator},
		Genesis: s0.set,
	}})
	if err != nil {
		t.Fatalf("NewJournalWitnessSetResolver: %v", err)
	}
	return r, s0, s1
}

// TestJournalResolver_TransitionalHead_BoundaryRegression is the boundary
// proof: a post-rotation head still cosigned by the OUTGOING set fails the
// live current-set snapshot check (the position-blind behavior — a false
// alarm), and resolves correctly era-anchored through the journal.
func TestJournalResolver_TransitionalHead_BoundaryRegression(t *testing.T) {
	r, s0, s1 := twoEraFixture(t)
	netID := rottest.NetID()

	// The transitional head: TreeSize 150 (> the rotation at 100) but cosigned
	// by the OUTGOING set s0 — the fuzzy-window shape the SDK documents.
	th := rottest.FullTreeHead(150)
	transitional := rottest.CosignHead(t, th, s0.keys, s0.privs, 2, netID)

	// (a) The position-blind snapshot path: the live set is s1 after the
	// rotation applies, and the transitional head does NOT satisfy it — the
	// false rejection this resolver exists to fix.
	s1Set, err := cosign.NewWitnessKeySet(s1.keys, netID, 2, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	if cosign.VerifyTreeHeadCosignatures(transitional, s1Set) >= s1Set.Quorum() {
		t.Fatal("test fixture broken: the transitional head must NOT satisfy the new set")
	}

	// (b) Head-anchored journal resolution: the head identifies its own era.
	got, err := r.SetForHead(context.Background(), jrOriginator, transitional)
	if err != nil {
		t.Fatalf("SetForHead(transitional): %v", err)
	}
	if got.SetHash() != s0.set.SetHash() {
		t.Fatal("transitional head must resolve to the OUTGOING era set")
	}

	// (c) And a new-set head resolves to the new era — most-recent-first.
	adopted := rottest.CosignHead(t, rottest.FullTreeHead(160), s1.keys, s1.privs, 2, netID)
	got, err = r.SetForHead(context.Background(), jrOriginator, adopted)
	if err != nil {
		t.Fatalf("SetForHead(adopted): %v", err)
	}
	if got.SetHash() == s0.set.SetHash() {
		t.Fatal("adopted head must resolve to the NEW era set")
	}

	// (d) Fail-closed: a head cosigned by keys on NO chain is rejected.
	rogue := newEraKit(t, 3, 2, netID)
	offChain := rottest.CosignHead(t, rottest.FullTreeHead(170), rogue.keys, rogue.privs, 2, netID)
	if _, err := r.SetForHead(context.Background(), jrOriginator, offChain); err == nil {
		t.Fatal("off-chain head must fail closed")
	}
}

// TestJournalResolver_SetAt_AliasAndEraCorrect: SetAt resolves era-correct sets
// when queried BY THE GOSSIP ALIAS with an alias-named asOf — proving the
// canonicalization rewrite (the raw SDK walk would reject the alias asOf with
// ErrAsOfLogMismatch against canonical-keyed records).
func TestJournalResolver_SetAt_AliasAndEraCorrect(t *testing.T) {
	r, s0, _ := twoEraFixture(t)

	before, err := r.SetAt(context.Background(), jrOriginator,
		types.LogPosition{LogDID: jrOriginator, Sequence: 99})
	if err != nil {
		t.Fatalf("SetAt(99): %v", err)
	}
	if before.SetHash() != s0.set.SetHash() {
		t.Fatal("asOf before the rotation must resolve the genesis set")
	}

	at, err := r.SetAt(context.Background(), jrOriginator,
		types.LogPosition{LogDID: jrOriginator, Sequence: 100})
	if err != nil {
		t.Fatalf("SetAt(100): %v", err)
	}
	if at.SetHash() == s0.set.SetHash() {
		t.Fatal("asOf at the rotation boundary (inclusive) must resolve the NEW set")
	}
}

// TestJournalResolver_CurrentSet_BootReconstruction: CurrentSet replays the
// full chain — the value a restart must seed the live registry with.
func TestJournalResolver_CurrentSet_BootReconstruction(t *testing.T) {
	r, s0, _ := twoEraFixture(t)
	cur, err := r.CurrentSet(context.Background(), jrLogDID)
	if err != nil {
		t.Fatalf("CurrentSet: %v", err)
	}
	if cur.SetHash() == s0.set.SetHash() {
		t.Fatal("CurrentSet after one rotation must NOT be the genesis set")
	}
}

// TestJournalResolver_UnknownLog_FailsClosed: a log with no configured trust
// root must never resolve.
func TestJournalResolver_UnknownLog_FailsClosed(t *testing.T) {
	r, _, _ := twoEraFixture(t)
	if _, err := r.CurrentSet(context.Background(), "did:web:stranger"); err == nil {
		t.Fatal("unknown log must fail closed")
	}
}

// TestJournalResolver_PoisonedChain_FailsClosed: a journal carrying a record
// that does NOT chain from the genesis trust root never resolves — the
// root-at-genesis invariant at the verify altitude (the boot altitude is the
// consumer's roster cross-check).
func TestJournalResolver_PoisonedChain_FailsClosed(t *testing.T) {
	netID := rottest.NetID()
	s0, sX, sY := newEraKit(t, 3, 2, netID), newEraKit(t, 3, 2, netID), newEraKit(t, 3, 2, netID)
	// A rotation authorized by sX — a chain rooted ANYWHERE but s0.
	foreign := witnesstest.MintRotation(t, netID, sX.ws, sY.ws, 2)
	src := &memRecordSource{byLog: map[string][]types.WitnessRotationRecord{
		jrLogDID: {{Rotation: foreign, EffectivePos: types.LogPosition{LogDID: jrLogDID, Sequence: 50}}},
	}}
	r, err := NewJournalWitnessSetResolver(src, []LogTrustRoot{{LogDID: jrLogDID, Genesis: s0.set}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.CurrentSet(context.Background(), jrLogDID); err == nil {
		t.Fatal("a chain not rooted at the genesis trust root must fail closed")
	}
	if _, err := r.SetAt(context.Background(), jrLogDID, types.LogPosition{LogDID: jrLogDID, Sequence: 60}); err == nil {
		t.Fatal("SetAt over a poisoned chain must fail closed")
	}
}

// TestNewJournalWitnessSetResolver_ConfigRefusals: construction is fail-closed
// on every malformed trust-root shape.
func TestNewJournalWitnessSetResolver_ConfigRefusals(t *testing.T) {
	netID := rottest.NetID()
	s0 := newEraKit(t, 3, 2, netID)
	src := &memRecordSource{byLog: map[string][]types.WitnessRotationRecord{}}

	if _, err := NewJournalWitnessSetResolver(nil, nil); err == nil {
		t.Fatal("nil record source must refuse")
	}
	if _, err := NewJournalWitnessSetResolver(src, []LogTrustRoot{{LogDID: "", Genesis: s0.set}}); err == nil {
		t.Fatal("empty LogDID must refuse")
	}
	if _, err := NewJournalWitnessSetResolver(src, []LogTrustRoot{{LogDID: "did:web:a"}}); err == nil {
		t.Fatal("nil genesis must refuse")
	}
	if _, err := NewJournalWitnessSetResolver(src, []LogTrustRoot{
		{LogDID: "did:web:a", Genesis: s0.set, Aliases: []string{"did:key:shared"}},
		{LogDID: "did:web:b", Genesis: s0.set, Aliases: []string{"did:key:shared"}},
	}); err == nil {
		t.Fatal("an alias collision across roots must refuse")
	}
}
