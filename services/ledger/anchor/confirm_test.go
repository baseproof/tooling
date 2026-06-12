package anchor

// confirm_test.go — the read-back contract: the confirmer finds OUR anchor on
// the parent by its network-bound tree_head_ref, records a confirmation with
// the parent position + the payload's claim, treats not-found as a retryable
// error (published-but-unconfirmed, never silent), and stamps verified_at
// from the observation clock — durability/immutability is the store's law,
// pinned in store/anchor_confirmations_embedded_test.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	sdkanchor "github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store"
)

type fakeParentFetcher struct{ entries map[uint64][]byte }

func (f *fakeParentFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	raw, ok := f.entries[pos.Sequence]
	if !ok {
		return nil, fmt.Errorf("no entry at %d", pos.Sequence)
	}
	return &types.EntryWithMetadata{CanonicalBytes: raw, Position: pos}, nil
}

type fakeRecorder struct{ rows []store.AnchorConfirmation }

func (r *fakeRecorder) RecordFirstSeen(_ context.Context, c store.AnchorConfirmation) (time.Time, error) {
	r.rows = append(r.rows, c)
	return c.VerifiedAt, nil
}

// mkSignedAnchorEntry builds a REAL anchor entry for ourHead exactly as the
// publisher does (NewCosignedAnchorV1 under ourNID), signed so Serialize
// accepts it.
func mkSignedAnchorEntry(t *testing.T, ourLogDID string, ourHead types.CosignedTreeHead, ourNID cosign.NetworkID) []byte {
	t.Helper()
	a, err := sdkanchor.NewCosignedAnchorV1(ourLogDID, ourHead, "https://child.example", ourNID)
	if err != nil {
		t.Fatalf("NewCosignedAnchorV1: %v", err)
	}
	payload, err := a.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	e, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   kp.DID,
		Destination: "did:baseproof:network:parent",
		EventTime:   1_700_000_000_000_000,
	}, payload)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	h := sha256.Sum256(envelope.SigningPayload(e))
	sig, err := signatures.SignEntry(h, kp.PrivateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	e.Signatures = []envelope.Signature{{SignerDID: kp.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	raw, err := envelope.Serialize(e)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return raw
}

func mkHead(treeSize uint64, seed byte) types.CosignedTreeHead {
	var root, smtRoot [32]byte
	root[0], smtRoot[0] = seed, seed+1
	return types.CosignedTreeHead{
		TreeHead: types.TreeHead{RootHash: root, SMTRoot: smtRoot, TreeSize: treeSize},
		Signatures: []types.WitnessSignature{{
			PubKeyID: [32]byte{seed}, SchemeTag: 1, SigBytes: []byte{0xde, 0xad},
		}},
	}
}

func TestParentAnchorConfirmer(t *testing.T) {
	ourLogDID := "did:baseproof:network:child"
	parentDID := "did:baseproof:network:parent"
	var ourNID cosign.NetworkID
	ourNID[0] = 0xC1

	ourHead := mkHead(1000, 0x10)
	otherHead := mkHead(900, 0x20)

	fetcher := &fakeParentFetcher{entries: map[uint64][]byte{
		4: mkSignedAnchorEntry(t, ourLogDID, otherHead, ourNID), // an older anchor of ours
		9: mkSignedAnchorEntry(t, ourLogDID, ourHead, ourNID),   // the one we just submitted
	}}
	rec := &fakeRecorder{}
	nowT := time.Unix(1_700_002_000, 0).UTC()

	confirm, err := NewParentAnchorConfirmer(ParentReadBackConfig{
		ParentLogDID:  parentDID,
		OwnLogDID:     ourLogDID,
		OwnNetworkID:  ourNID,
		FetchSeqs:     func(context.Context) ([]uint64, error) { return []uint64{4, 9}, nil },
		ParentFetcher: fetcher,
		Recorder:      rec,
		Now:           func() time.Time { return nowT },
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	if err := confirm(context.Background(), ourHead); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if len(rec.rows) != 1 {
		t.Fatalf("recorded %d rows, want exactly the matching anchor", len(rec.rows))
	}
	row := rec.rows[0]
	wantDigest, _ := cosign.TreeHeadDigest(ourHead.TreeHead, ourNID)
	if row.TreeHeadRef != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("recorded ref %s != our head's network-bound digest", row.TreeHeadRef)
	}
	if row.ParentLogDID != parentDID || row.ParentSeq != 9 || row.AnchoredTreeSize != 1000 {
		t.Fatalf("row = %+v, want parent seq 9 / tree size 1000", row)
	}
	if row.AnchoredAt.IsZero() {
		t.Fatal("the payload's AnchoredAt claim was dropped")
	}
	if !row.VerifiedAt.Equal(nowT) {
		t.Fatalf("verified_at = %v, want the observation clock %v", row.VerifiedAt, nowT)
	}

	// Not-yet-discoverable: a head with no anchor on the parent is a
	// retryable ERROR (published-but-unconfirmed), never a silent success.
	if err := confirm(context.Background(), mkHead(2000, 0x30)); err == nil {
		t.Fatal("undiscoverable anchor confirmed silently")
	}
	if len(rec.rows) != 1 {
		t.Fatalf("phantom confirmation recorded: %d rows", len(rec.rows))
	}
}

func TestParentAnchorConfirmer_RefusesPartialWiring(t *testing.T) {
	_, err := NewParentAnchorConfirmer(ParentReadBackConfig{
		ParentLogDID: "did:p", OwnLogDID: "did:c",
		// FetchSeqs / ParentFetcher / Recorder missing.
	})
	if err == nil {
		t.Fatal("a no-op confirmer was constructed — the read-back must not silently disable")
	}
}

// Compile-time: the real store satisfies the recorder seam.
var _ ConfirmationRecorder = (*store.AnchorConfirmationStore)(nil)
