// FILE PATH: services/auditor/internal/store/journal_resolver_test.go
//
// Tests for the journal-first position-aware resolver — including the GAP it
// closes: the shipped auditor never wired a HeadWitnessSetResolver, so every
// inbound head was verified against the LIVE current-set snapshot. At a
// rotation boundary the ledger legitimately keeps emitting heads cosigned by
// the OUTGOING set for a while (the operationally-fuzzy cosign switch); the
// snapshot path REJECTS those transitional heads (a false fork alarm), while
// head-anchored journal resolution accepts them against their own era set.
// TestJournalResolver_TransitionalHead_BoundaryRegression pins both halves.
//
// Reuses genWitnessSet/cosignHead/fullTreeHead/rotTestNetID
// (witness_rotation_journal_test.go) + newKitHWS/dualSignedRotation
// (historical_witness_set_test.go).
package store

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/auditing/gossipverify"
	"github.com/baseproof/tooling/libs/witnessrotation"
	"github.com/baseproof/tooling/services/auditor/internal/equivocation"
)

// Static conformance: the resolver satisfies BOTH consumer seams, and the STH
// adapter satisfies the scan reconciler's fallback seam.
var (
	_ gossipverify.HeadWitnessSetResolver = (*JournalWitnessSetResolver)(nil)
	_ equivocation.EraWitnessSetResolver  = (*JournalWitnessSetResolver)(nil)
	_ witnessrotation.VerifiedHeadSource  = (*STHHeadSource)(nil)
)

const (
	jrLogDID     = "did:web:court.journal.test" // canonical (what findings stamp)
	jrOriginator = "did:key:zJournalOriginator" // the gossip alias the verify path uses
)

// memRecordSource is an in-memory RotationRecordSource.
type memRecordSource struct {
	byLog map[string][]types.WitnessRotationRecord
}

func (m *memRecordSource) RecordsFor(_ context.Context, logDID string) ([]types.WitnessRotationRecord, error) {
	return m.byLog[logDID], nil
}

// twoEraFixture journals one verified rotation s0→s1 (at seq 100, keyed by the
// CANONICAL log DID, exactly as the gossip reconciler records it) and returns
// the resolver plus both era kits.
func twoEraFixture(t *testing.T) (*JournalWitnessSetResolver, witnessSetKitHWS, witnessSetKitHWS) {
	t.Helper()
	netID := rotTestNetID()
	s0, s1 := newKitHWS(t, 3, 2, netID), newKitHWS(t, 3, 2, netID)
	src := &memRecordSource{byLog: map[string][]types.WitnessRotationRecord{
		jrLogDID: {{
			Rotation:     dualSignedRotation(t, s0, s1, 2, netID),
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

// TestJournalResolver_TransitionalHead_BoundaryRegression is the Gap-1 proof:
// a post-rotation head still cosigned by the OUTGOING set fails the live
// current-set snapshot check (the pre-fix behavior — a false alarm), and
// resolves correctly era-anchored through the journal.
func TestJournalResolver_TransitionalHead_BoundaryRegression(t *testing.T) {
	r, s0, s1 := twoEraFixture(t)
	netID := rotTestNetID()

	// The transitional head: TreeSize 150 (> the rotation at 100) but cosigned
	// by the OUTGOING set s0 — the fuzzy-window shape the SDK documents.
	th := fullTreeHead(150)
	transitional := cosignHead(t, th, s0.keys, s0.privs, 2, netID)

	// (a) The position-blind snapshot path (production before the fix): the
	// live set is s1 after ApplyVerifiedRotation, and the transitional head
	// does NOT satisfy it — the false rejection this resolver exists to fix.
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
	adopted := cosignHead(t, fullTreeHead(160), s1.keys, s1.privs, 2, netID)
	got, err = r.SetForHead(context.Background(), jrOriginator, adopted)
	if err != nil {
		t.Fatalf("SetForHead(adopted): %v", err)
	}
	if got.SetHash() == s0.set.SetHash() {
		t.Fatal("adopted head must resolve to the NEW era set")
	}

	// (d) Fail-closed: a head cosigned by keys on NO chain is rejected.
	rogue := newKitHWS(t, 3, 2, netID)
	offChain := cosignHead(t, fullTreeHead(170), rogue.keys, rogue.privs, 2, netID)
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

// memSTHSource fakes the evidence store's LatestSTH.
type memSTHSource struct {
	byOriginator map[string]gossip.SignedEvent
}

func (m *memSTHSource) LatestSTH(_ context.Context, originator string) (gossip.SignedEvent, bool, error) {
	ev, ok := m.byOriginator[originator]
	return ev, ok, nil
}

// TestSTHHeadSource_DecodesAndTranslates: the adapter decodes the persisted
// finding back to a CosignedTreeHead and translates the canonical log DID to
// the originator key the evidence store uses.
func TestSTHHeadSource_DecodesAndTranslates(t *testing.T) {
	netID := rotTestNetID()
	s0 := newKitHWS(t, 3, 2, netID)
	head := cosignHead(t, fullTreeHead(42), s0.keys, s0.privs, 2, netID)
	finding, err := findings.NewCosignedTreeHeadFinding(head, "https://ledger.example")
	if err != nil {
		t.Fatalf("NewCosignedTreeHeadFinding: %v", err)
	}
	body, err := finding.EncodeWireBody()
	if err != nil {
		t.Fatalf("EncodeWireBody: %v", err)
	}
	src := &memSTHSource{byOriginator: map[string]gossip.SignedEvent{
		jrOriginator: {Kind: finding.Kind(), Originator: jrOriginator, Body: body},
	}}

	hs, err := NewSTHHeadSource(src, map[string]string{jrLogDID: jrOriginator})
	if err != nil {
		t.Fatalf("NewSTHHeadSource: %v", err)
	}
	// Query by the CANONICAL log DID — the adapter must translate.
	got, ok, err := hs.LatestVerifiedHead(context.Background(), jrLogDID)
	if err != nil || !ok {
		t.Fatalf("LatestVerifiedHead: ok=%v err=%v", ok, err)
	}
	if got.TreeSize != 42 || len(got.Signatures) != 2 {
		t.Fatalf("decoded head = size %d / %d sigs, want 42 / 2", got.TreeSize, len(got.Signatures))
	}
	if _, ok, _ := hs.LatestVerifiedHead(context.Background(), "did:web:stranger"); ok {
		t.Fatal("unknown log must report no head")
	}
}
