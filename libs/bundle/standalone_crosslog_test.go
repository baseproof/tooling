package bundle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
)

// A non-federated gather (empty registry) yields a null cross_log_anchors with no
// HTTP — the common case.
func TestCrossLog_EmptyRegistry_Null(t *testing.T) {
	g := &StandaloneLedgerGather{} // federation nil
	raw, err := g.crossLogSection(context.Background())
	if err != nil {
		t.Fatalf("crossLogSection: %v", err)
	}
	if raw != nil {
		t.Errorf("a non-federated gather must yield a null section, got %s", raw)
	}
}

// keepLatestPerNetwork reduces to the highest seq per cited network.
func TestKeepLatestPerNetwork(t *testing.T) {
	out := keepLatestPerNetwork([]discoveredAnchor{
		{seq: 5, sourceLogDID: "did:b"},
		{seq: 9, sourceLogDID: "did:b"}, // latest for b
		{seq: 3, sourceLogDID: "did:c"},
		{seq: 1, sourceLogDID: "did:b"},
	})
	got := map[string]uint64{}
	for _, da := range out {
		got[da.sourceLogDID] = da.seq
	}
	if len(got) != 2 {
		t.Fatalf("want 2 networks, got %d: %v", len(got), got)
	}
	if got["did:b"] != 9 {
		t.Errorf("did:b latest = %d, want 9", got["did:b"])
	}
	if got["did:c"] != 3 {
		t.Errorf("did:c latest = %d, want 3", got["did:c"])
	}
}

// extractAnchorHead round-trips the embedded head — the pin the nested proof binds
// to (verifyCrossLogAnchors requires nested checkpoint == this head).
func TestExtractAnchorHead(t *testing.T) {
	_, signers := witnessKit(t, 2)
	nid := cosign.NetworkID{0x7}
	head := headCosignedBy(t, signers, nid)

	a, err := anchor.NewCosignedAnchorV1("did:web:b.example", head, "https://b.example", nid)
	if err != nil {
		t.Fatalf("NewCosignedAnchorV1: %v", err)
	}
	got, err := extractAnchorHead(a)
	if err != nil {
		t.Fatalf("extractAnchorHead: %v", err)
	}
	if got.RootHash != head.RootHash || got.SMTRoot != head.SMTRoot || got.TreeSize != head.TreeSize {
		t.Errorf("extracted head %+v != embedded %+v", got.TreeHead, head.TreeHead)
	}
}

type smtProofBody struct {
	Type  string         `json:"type"`
	Proof types.SMTProof `json:"proof"`
}

// resolveCitedMemberSeq reads the cited member's origin sequence from its SMT
// membership proof at the pinned head's root.
func TestResolveCitedMemberSeq(t *testing.T) {
	key := [32]byte{0xAB}
	body, err := json.Marshal(smtProofBody{
		Type: "membership",
		Proof: types.SMTProof{
			Key:          key,
			TerminalLeaf: &types.SMTLeaf{Key: key, OriginTip: types.LogPosition{LogDID: "did:web:b", Sequence: 42}},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	seq, err := resolveCitedMemberSeq(context.Background(), srv.Client(), srv.URL, key, [32]byte{0x22})
	if err != nil {
		t.Fatalf("resolveCitedMemberSeq: %v", err)
	}
	if seq != 42 {
		t.Errorf("seq = %d, want 42 (OriginTip)", seq)
	}
}

// A non-membership SMT response ⇒ error: the cited member isn't present at the
// pinned head, so no valid nested proof can be built (fail closed, never seq 0).
func TestResolveCitedMemberSeq_NonMembership(t *testing.T) {
	body, _ := json.Marshal(smtProofBody{Type: "non_membership", Proof: types.SMTProof{}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	if _, err := resolveCitedMemberSeq(context.Background(), srv.Client(), srv.URL, [32]byte{0x1}, [32]byte{0x2}); err == nil {
		t.Fatal("a non-membership SMT response must error (member not present at the pinned head)")
	}
}
