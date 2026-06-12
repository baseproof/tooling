package anchorfeed

// feed_test.go — the feed's composition contract:
//
//   - entries are read through the MultiLog (parent provenance), decoded with
//     the SDK codec, and assembled into AnchorEvidence with the parent pin +
//     the payload's claim + the durable first-seen;
//   - FirstSeen wins over the observation clock (the lazy-fresh defense's
//     persistence half);
//   - a NON-anchor entry is an error item, never silent;
//   - THE LOAD-BEARING NEGATIVE: a head cosigned by a FOREIGN set flows
//     THROUGH un-judged. The feed performs no lineage binding — that rule
//     lives in verifier.LatestAnchorObservation against the rotation-replayed
//     current set. A feed that rejected it here would duplicate the rule
//     against the wrong set.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/types"
)

// signEntry author-signs an unsigned envelope with a fresh did:key so
// Serialize accepts it (the envelope demands >=1 signature).
func signEntry(t *testing.T, e *envelope.Entry) []byte {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	e.Header.SignerDID = kp.DID
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

// fakeFetcher is the parent log's trusted read backend in the MultiLog.
type fakeFetcher struct {
	entries map[uint64][]byte
}

func (f *fakeFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	raw, ok := f.entries[pos.Sequence]
	if !ok {
		return nil, fmt.Errorf("no entry at %d", pos.Sequence)
	}
	return &types.EntryWithMetadata{CanonicalBytes: raw, Position: pos}, nil
}

func mkAnchorEntry(t *testing.T, sourceLogDID, anchoredAt string) []byte {
	t.Helper()
	hex64 := func(b byte) string { return fmt.Sprintf("%064x", [32]byte{0: b}) }
	a := anchor.CosignedAnchorV1{
		AnchorType:   anchor.CosignedAnchorType,
		SourceLogDID: sourceLogDID,
		// A structurally DECODABLE head whose "cosignatures" are garbage —
		// the forged-lineage shape. The feed must pass it through; only the
		// SDK reduction may ignore it.
		Head: gossip.WireCosignedTreeHeadBody{
			Head: gossip.WireCosignedTreeHead{
				RootHash:    hex64(0xAA),
				SMTRoot:     hex64(0xBB),
				ReceiptRoot: hex64(0x00),
				TreeSize:    42,
				Signatures: []types.WireWitnessSignature{
					{PubKeyID: hex64(0x01), SchemeTag: 1, SigBytes: "deadbeef"},
				},
			},
		},
		TreeHeadRef: fmt.Sprintf("%064x", sha256.Sum256([]byte(sourceLogDID+anchoredAt))),
		AnchoredAt:  anchoredAt,
	}
	payload, err := a.Marshal()
	if err != nil {
		t.Fatalf("marshal anchor: %v", err)
	}
	e, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:key:zChildPublisher",
		Destination: "did:web:parent.example",
		EventTime:   1_700_000_000_000_000,
	}, payload)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	return signEntry(t, e)
}

func mkPlainEntry(t *testing.T) []byte {
	t.Helper()
	e, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:key:zSomeone",
		Destination: "did:web:parent.example",
		EventTime:   1_700_000_000_000_000,
	}, []byte(`{"kind":"BP-ENTRY-WITNESS-ENDPOINT-V1"}`))
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	return signEntry(t, e)
}

func TestCollectEvidence_CompositionContract(t *testing.T) {
	parentDID := "did:baseproof:network:parent"
	var parentPin [32]byte
	parentPin[0] = 0x9A
	claim := time.Unix(1_700_000_000, 0).UTC()

	fetcher := &fakeFetcher{entries: map[uint64][]byte{
		3: mkAnchorEntry(t, "did:baseproof:network:child", claim.Format(time.RFC3339)),
		5: mkPlainEntry(t),                                  // not an anchor → error item
		8: mkAnchorEntry(t, "did:baseproof:network:c2", ""), // no claim → zero AnchoredAt
	}}
	ml := anchor.NewMultiLog(map[string]anchor.LogConfig{
		parentDID: {Fetcher: fetcher},
	})

	durable := time.Unix(1_600_000_000, 0).UTC() // first-seen long before "now"
	firstSeen := func(_ string, seq uint64, _ string, observedAt time.Time) time.Time {
		if seq == 3 {
			return durable // the store remembers an earlier observation
		}
		return observedAt
	}
	nowT := time.Unix(1_700_001_000, 0).UTC()
	items, errs := CollectEvidence(context.Background(), ml, parentDID, parentPin,
		[]uint64{3, 5, 8, 99}, firstSeen, func() time.Time { return nowT })

	if len(items) != 2 {
		t.Fatalf("items = %d, want 2 (seq 3 + 8)", len(items))
	}
	if len(errs) != 2 {
		t.Fatalf("errs = %d, want 2 (non-anchor seq 5 + missing seq 99): %v", len(errs), errs)
	}
	ev3 := items[0].Evidence
	if ev3.AnchorNetworkID != parentPin {
		t.Fatal("evidence not attributed to the parent pin")
	}
	if !ev3.AnchoredAt.Equal(claim) {
		t.Fatalf("AnchoredAt = %v, want the payload claim %v", ev3.AnchoredAt, claim)
	}
	if !ev3.VerifiedAt.Equal(durable) {
		t.Fatalf("VerifiedAt = %v, want the DURABLE first-seen %v (re-observation must not refresh)", ev3.VerifiedAt, durable)
	}
	ev8 := items[1].Evidence
	if !ev8.AnchoredAt.IsZero() {
		t.Fatal("missing claim must surface as the zero AnchoredAt (the SDK reduction ignores it — fail-closed lives there)")
	}
	if !ev8.VerifiedAt.Equal(nowT) {
		t.Fatalf("first observation must stamp the observation clock, got %v", ev8.VerifiedAt)
	}
}

// TestCollectEvidence_NoLineageJudgment pins the altitude rule: the feed does
// not verify the embedded head against ANY witness set. An anchor whose head
// carries garbage "signatures" (a forged lineage's shape) flows through as
// evidence — the SDK reduction is the one place that ignores it.
func TestCollectEvidence_NoLineageJudgment(t *testing.T) {
	parentDID := "did:baseproof:network:parent"
	fetcher := &fakeFetcher{entries: map[uint64][]byte{
		1: mkAnchorEntry(t, "did:baseproof:network:forged-child", time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339)),
	}}
	ml := anchor.NewMultiLog(map[string]anchor.LogConfig{parentDID: {Fetcher: fetcher}})

	items, errs := CollectEvidence(context.Background(), ml, parentDID, [32]byte{0xEE},
		[]uint64{1}, nil, func() time.Time { return time.Unix(1_700_001_000, 0) })
	if len(errs) != 0 || len(items) != 1 {
		t.Fatalf("the feed judged evidence (items=%d errs=%v) — lineage binding belongs to the SDK reduction", len(items), errs)
	}
}

func TestFetchBySourceSeqs_WalksPages(t *testing.T) {
	// Parent serves two pages: [1,2] then [7] (short page ends the walk).
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		start := r.URL.Query().Get("start")
		var entries []map[string]any
		switch start {
		case "0":
			entries = []map[string]any{{"sequence_number": 1}, {"sequence_number": 2}}
		case "3":
			entries = []map[string]any{{"sequence_number": 7}}
		default:
			t.Errorf("unexpected start=%s", start)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries, "count": len(entries)})
	}))
	defer srv.Close()

	seqs, err := FetchBySourceSeqs(context.Background(), srv.Client(), srv.URL, "did:baseproof:network:child", 2)
	if err != nil {
		t.Fatalf("pager: %v", err)
	}
	if fmt.Sprint(seqs) != "[1 2 7]" || calls != 2 {
		t.Fatalf("seqs=%v calls=%d, want [1 2 7] in 2 calls", seqs, calls)
	}

	// nil client is refused (no silent transport fallback).
	if _, err := FetchBySourceSeqs(context.Background(), nil, srv.URL, "x", 1); err == nil {
		t.Fatal("nil client accepted")
	}
}
