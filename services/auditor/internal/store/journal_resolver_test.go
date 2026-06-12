// FILE PATH: services/auditor/internal/store/journal_resolver_test.go
//
// STHHeadSource tests (the auditor-owned evidence-store adapter) + the
// CONSUMER-side conformance asserts for the lifted journal-first resolution
// machinery: the auditor's seams are the auditor's to prove satisfied
// (the resolver's own behavior suite lives with it in libs/witnessrotation).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/libs/auditing/gossipverify"
	"github.com/baseproof/tooling/libs/witnessrotation"
	"github.com/baseproof/tooling/libs/witnessrotation/journalpg"
	"github.com/baseproof/tooling/services/auditor/internal/equivocation"
)

// Static conformance — the auditor's consumer seams, satisfied by the LIFTED
// machinery: the verify path's head-anchored resolver, the equivocation
// slasher's era resolver, the scan reconciler's fallback source, and both
// reconciler journal seams on the durable journal.
var (
	_ gossipverify.HeadWitnessSetResolver = (*witnessrotation.JournalWitnessSetResolver)(nil)
	_ equivocation.EraWitnessSetResolver  = (*witnessrotation.JournalWitnessSetResolver)(nil)
	_ witnessrotation.VerifiedHeadSource  = (*STHHeadSource)(nil)
	_ witnessrotation.RotationJournal     = (*journalpg.PostgresWitnessRotationJournal)(nil)
)

const (
	jrLogDID     = "did:web:court.journal.test" // canonical (what findings stamp)
	jrOriginator = "did:key:zJournalOriginator" // the gossip alias the verify path uses
)

// rotTestNetID is a fixed non-zero network id (NewWitnessKeySet rejects zero).
func rotTestNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// genWitnessSet mints an n-key, k-quorum ECDSA witness set via the SDK fixture
// kit (the kit's private keys sign rotations / cosign heads under the set).
func genWitnessSet(t *testing.T, n, k int, netID cosign.NetworkID) *witnesstest.Set {
	t.Helper()
	return witnesstest.NewSet(t, netID, n, k)
}

// buildRotation mints a valid rotation old → next through the production
// assembly path: the first sigCount OLD members authorize and every joiner
// countersigns (Step-6 consent), so witness.VerifyRotation accepts it under
// every current rule.
func buildRotation(t *testing.T, old, next *witnesstest.Set, sigCount int, netID cosign.NetworkID) types.WitnessRotation {
	t.Helper()
	return witnesstest.MintRotation(t, netID, old, next, sigCount)
}

// cosignHead produces a K-of-N cosigned tree head signed by the supplied set's
// private keys — a real witness-cosigned head for the decode round-trip.
func cosignHead(t *testing.T, head types.TreeHead, ws *witnesstest.Set, sigCount int, netID cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	payload := cosign.NewTreeHeadPayload(head)
	sigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sb, err := cosign.SignECDSA(payload, netID, cosign.HashAlgoSHA256, ws.Privs[i])
		if err != nil {
			t.Fatalf("SignECDSA head: %v", err)
		}
		sigs[i] = types.WitnessSignature{PubKeyID: ws.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
	}
	return types.CosignedTreeHead{TreeHead: head, Signatures: sigs}
}

// fullTreeHead returns a TreeHead with all commitment roots populated — cosign's
// dual-commitment binding rejects an all-zero RootHash/SMTRoot.
func fullTreeHead(size uint64) types.TreeHead {
	return types.TreeHead{
		RootHash:    [32]byte{0x01, 0xC0, 0x5C},
		SMTRoot:     [32]byte{0x02, 0x5A, 0x7B},
		ReceiptRoot: [32]byte{0x03, 0x4C, 0x7D},
		TreeSize:    size,
	}
}

// memSTHSource fakes the evidence store's LatestSTHWithTime.
type memSTHSource struct {
	byOriginator map[string]gossip.SignedEvent
	observedAt   time.Time
}

func (m *memSTHSource) LatestSTHWithTime(_ context.Context, originator string) (gossip.SignedEvent, time.Time, bool, error) {
	ev, ok := m.byOriginator[originator]
	return ev, m.observedAt, ok, nil
}

// TestSTHHeadSource_DecodesAndTranslates: the adapter decodes the persisted
// finding back to a CosignedTreeHead and translates the canonical log DID to
// the originator key the evidence store uses.
func TestSTHHeadSource_DecodesAndTranslates(t *testing.T) {
	netID := rotTestNetID()
	s0 := witnesstest.NewSet(t, netID, 3, 2)
	head := cosignHead(t, fullTreeHead(42), s0, 2, netID)
	finding, err := findings.NewCosignedTreeHeadFinding(head, "https://ledger.example")
	if err != nil {
		t.Fatalf("NewCosignedTreeHeadFinding: %v", err)
	}
	body, err := finding.EncodeWireBody()
	if err != nil {
		t.Fatalf("EncodeWireBody: %v", err)
	}
	observed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	src := &memSTHSource{
		byOriginator: map[string]gossip.SignedEvent{
			jrOriginator: {Kind: finding.Kind(), Originator: jrOriginator, Body: body},
		},
		observedAt: observed,
	}

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
	// The time-bearing variant surfaces the persistence clock for the
	// frozen-log freshness check.
	_, at, ok, err := hs.LatestVerifiedHeadWithTime(context.Background(), jrLogDID)
	if err != nil || !ok || !at.Equal(observed) {
		t.Fatalf("LatestVerifiedHeadWithTime: at=%v ok=%v err=%v, want observed=%v", at, ok, err, observed)
	}
	if _, ok, _ := hs.LatestVerifiedHead(context.Background(), "did:web:stranger"); ok {
		t.Fatal("unknown log must report no head")
	}
}
