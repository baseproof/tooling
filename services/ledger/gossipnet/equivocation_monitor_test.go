/*
FILE PATH: gossipnet/equivocation_monitor_test.go

End-to-end tests for EquivocationMonitor. Constructs two
genuinely-cosigned tree heads with the SAME tree_size and
DIFFERENT root_hash (the only structural shape of a
cryptographic equivocation), exercises one monitor tick, and
asserts the publisher fired by checking the local store for a
new KindEquivocationFinding event.

# WHY USE REAL CRYPTO

Mocking witness signers would let buggy verification logic pass
the test. The SDK's witness.DetectEquivocation runs cosign.Verify
against the witness key set and the K-of-N threshold; that path
must succeed against real signatures or the test reports a false
green. Generating real keys + signatures is fast (sub-millisecond
each) so the cost is negligible.
*/
package gossipnet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/did"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/quorum"
)

// fixtureWitnesses generates k witnesses with did:key DIDs.
type fixtureWitnesses struct {
	dids    []string
	signers []cosign.WitnessSigner
	keys    []types.WitnessPublicKey
}

func newFixtureWitnesses(t *testing.T, k int) fixtureWitnesses {
	t.Helper()
	out := fixtureWitnesses{
		dids:    make([]string, 0, k),
		signers: make([]cosign.WitnessSigner, 0, k),
	}
	for i := 0; i < k; i++ {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatal(err)
		}
		out.dids = append(out.dids, kp.DID)
		out.signers = append(out.signers, cosign.NewECDSAWitnessSigner(kp.PrivateKey))
	}
	keys, err := witness.KeysFromDIDs(out.dids)
	if err != nil {
		t.Fatalf("witness.KeysFromDIDs: %v", err)
	}
	out.keys = keys
	return out
}

// cosignHead has every fixture witness sign head; returns a
// fully-cosigned types.CosignedTreeHead suitable for embedding in
// a KindCosignedTreeHead body or feeding to DetectEquivocation.
func cosignHead(t *testing.T, ws fixtureWitnesses, head types.TreeHead, networkID cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	payload := cosign.NewTreeHeadPayload(head)
	sigs := make([]types.WitnessSignature, 0, len(ws.signers))
	for _, s := range ws.signers {
		sig, err := s.Sign(context.Background(), payload, networkID, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		sigs = append(sigs, sig)
	}
	return types.CosignedTreeHead{TreeHead: head, Signatures: sigs}
}

// stubLatestSTH serves /v1/gossip/sth/latest with a fixed
// SignedEvent body. originator query param ignored.
func stubLatestSTH(t *testing.T, sth sdkgossip.SignedEvent) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sdkgossip.LatestSTHResponse{
			Kind:    sth.Kind,
			Event:   sth,
			Lamport: sth.LamportTime,
		})
	}))
}

// signSTHEvent constructs a KindCosignedTreeHead SignedEvent for
// originator under the supplied signer + lamport=1 (first chain
// position). Body is gossip.WireCosignedTreeHeadBody.
func signSTHEvent(t *testing.T, originatorSigner cosign.WitnessSigner, originatorDID string, head types.CosignedTreeHead, networkID cosign.NetworkID) sdkgossip.SignedEvent {
	t.Helper()
	finding, err := findings.NewCosignedTreeHeadFinding(head, "https://ledger.example")
	if err != nil {
		t.Fatalf("NewCosignedTreeHeadFinding: %v", err)
	}
	se, err := sdkgossip.Sign(context.Background(), finding,
		originatorSigner, networkID, originatorDID, [32]byte{}, 1)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return se
}

// TestEquivocationMonitor_DetectsAndPublishes is the full e2e
// happy path: divergent heads → DetectEquivocation succeeds →
// Verify succeeds → publisher fires → local Store gains a
// KindEquivocationFinding event.
func TestEquivocationMonitor_DetectsAndPublishes(t *testing.T) {
	const K = 2
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	// "peer" originator: same DID for both heads; this is the
	// equivocator.
	peerKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)

	// Two heads at the SAME tree_size but DIFFERENT root_hash —
	// the cryptographic equivocation shape. SMTRoot also differs
	// to mirror real divergence (state forks alongside log forks);
	// non-zero values are required by baseproof v0.8.0+ Validate.
	headA := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xA5}}
	headB := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xBB}, SMTRoot: [32]byte{0xB5}}
	cosA := cosignHead(t, ws, headA, netID)
	cosB := cosignHead(t, ws, headB, netID)

	// Local store: contains the peer's STH for headA (the version
	// we know about).
	store := sdkgossip.NewInMemoryStore()
	localSTH := signSTHEvent(t, peerSigner, peerKP.DID, cosA, netID)
	if err := store.Append(context.Background(), localSTH); err != nil {
		t.Fatalf("seed local store: %v", err)
	}

	// Stub peer endpoint: returns headB (the conflicting version).
	peerSTH := signSTHEvent(t, peerSigner, peerKP.DID, cosB, netID)
	srv := stubLatestSTH(t, peerSTH)
	defer srv.Close()

	// Ledger's own signer (signs the published equivocation
	// finding).
	opKP, _ := did.GenerateDIDKeySecp256k1()
	opSigner := cosign.NewECDSAWitnessSigner(opKP.PrivateKey)

	publisher, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Store:      store,
		Sink:       sdkgossip.NopSink,
		Signer:     opSigner,
		NetworkID:  netID,
		Originator: opKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessSet, err := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:       store,
		Peers:       []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys: quorum.NewManager(witnessSet),
		Publisher:   publisher,
		Interval:    1 * time.Hour, // long; we tick manually
		HTTPClient:  testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	// Local store should now have:
	//   1. peer's KindCosignedTreeHead (seeded)
	//   2. ledger's KindEquivocationFinding (published)
	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2 (1 seed + 1 published)", stats.EventCount)
	}
	// Confirm the new event is from the ledger's originator.
	if stats.Heads[opKP.DID] != 1 {
		t.Errorf("ledger chain lamport = %d, want 1 (one published finding)",
			stats.Heads[opKP.DID])
	}
}

// recordingSink captures every broadcast SignedEvent so a test can decode the
// published wire body. Implements sdkgossip.Sink.
type recordingSink struct{ events []sdkgossip.SignedEvent }

func (s *recordingSink) Broadcast(_ context.Context, ev sdkgossip.SignedEvent) error {
	s.events = append(s.events, ev)
	return nil
}

func (s *recordingSink) Close(context.Context) error { return nil }

// TestEquivocationMonitor_PopulatesTargetLogDID proves the monitor stamps the
// equivocating peer's DID onto the published finding's TargetLogDID — the
// position-aware routing hint that lets a downstream auditor resolve the
// TARGET log's era-correct witness set. The target (the equivocator) differs
// from the relaying originator (this ledger), so without the hint a relayed
// historical equivocation falls back to originator resolution and can be
// falsely rejected. Decodes the actual broadcast wire body to assert it.
func TestEquivocationMonitor_PopulatesTargetLogDID(t *testing.T) {
	const K = 2
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	// The peer is the equivocator → its DID must land in TargetLogDID.
	peerKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)

	headA := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xA5}}
	headB := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xBB}, SMTRoot: [32]byte{0xB5}}
	cosA := cosignHead(t, ws, headA, netID)
	cosB := cosignHead(t, ws, headB, netID)

	store := sdkgossip.NewInMemoryStore()
	if err := store.Append(context.Background(), signSTHEvent(t, peerSigner, peerKP.DID, cosA, netID)); err != nil {
		t.Fatalf("seed local store: %v", err)
	}
	srv := stubLatestSTH(t, signSTHEvent(t, peerSigner, peerKP.DID, cosB, netID))
	defer srv.Close()

	// Distinct ledger originator (the relayer) — proves target ≠ originator.
	opKP, _ := did.GenerateDIDKeySecp256k1()
	sink := &recordingSink{}
	publisher, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Store:      store,
		Sink:       sink,
		Signer:     cosign.NewECDSAWitnessSigner(opKP.PrivateKey),
		NetworkID:  netID,
		Originator: opKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessSet, err := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:       store,
		Peers:       []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys: quorum.NewManager(witnessSet),
		Publisher:   publisher,
		Interval:    1 * time.Hour, // long; we tick manually
		HTTPClient:  testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	if len(sink.events) != 1 {
		t.Fatalf("broadcast events = %d, want 1 (one published equivocation)", len(sink.events))
	}
	evt, err := findings.FromWire(sink.events[0].Kind, sink.events[0].Body)
	if err != nil {
		t.Fatalf("FromWire: %v", err)
	}
	eq, ok := evt.(*findings.EquivocationFinding)
	if !ok {
		t.Fatalf("published event = %T, want *findings.EquivocationFinding", evt)
	}
	if eq.TargetLogDID != peerKP.DID {
		t.Errorf("TargetLogDID = %q, want the equivocating peer DID %q", eq.TargetLogDID, peerKP.DID)
	}
}

// TestEquivocationMonitor_NoFalsePositiveOnIdenticalHeads
// confirms identical roots → no publish.
func TestEquivocationMonitor_NoFalsePositiveOnIdenticalHeads(t *testing.T) {
	const K = 1
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, _ := did.GenerateDIDKeySecp256k1()
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)
	head := types.TreeHead{TreeSize: 50, RootHash: [32]byte{0x42}, SMTRoot: [32]byte{0x42, 0x57}}
	cos := cosignHead(t, ws, head, netID)

	store := sdkgossip.NewInMemoryStore()
	localSTH := signSTHEvent(t, peerSigner, peerKP.DID, cos, netID)
	if err := store.Append(context.Background(), localSTH); err != nil {
		t.Fatal(err)
	}
	srv := stubLatestSTH(t, localSTH) // identical event
	defer srv.Close()

	witnessSet, err := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:       store,
		Peers:       []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys: quorum.NewManager(witnessSet),
		Publisher:   nil, // detection-only mode
		HTTPClient:  testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (no equivocation, no publish)",
			stats.EventCount)
	}
}

// TestEquivocationMonitor_NoFalsePositiveOnDifferentSizes
// confirms different tree_sizes → no publish (legitimate
// out-of-sync state).
func TestEquivocationMonitor_NoFalsePositiveOnDifferentSizes(t *testing.T) {
	const K = 1
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, _ := did.GenerateDIDKeySecp256k1()
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)
	headA := types.TreeHead{TreeSize: 50, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xA5}}
	headB := types.TreeHead{TreeSize: 60, RootHash: [32]byte{0xBB}, SMTRoot: [32]byte{0xB5}}
	cosA := cosignHead(t, ws, headA, netID)
	cosB := cosignHead(t, ws, headB, netID)

	store := sdkgossip.NewInMemoryStore()
	localSTH := signSTHEvent(t, peerSigner, peerKP.DID, cosA, netID)
	store.Append(context.Background(), localSTH)
	srv := stubLatestSTH(t, signSTHEvent(t, peerSigner, peerKP.DID, cosB, netID))
	defer srv.Close()

	witnessSet, err := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:       store,
		Peers:       []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys: quorum.NewManager(witnessSet),
		HTTPClient:  testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (different sizes, not equivocation)",
			stats.EventCount)
	}
}

// TestEquivocationMonitor_RejectsConfig exercises the constructor's
// validation surface. v0.1.1: keys/K/networkID/blsVerifier are
// encapsulated in *cosign.WitnessKeySet, so the cfg surface
// rejects on a missing Store or a nil WitnessSet — the SDK's
// NewWitnessKeySet handles the rest at boot.
func TestEquivocationMonitor_RejectsConfig(t *testing.T) {
	validSet, err := cosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{ecdsaWitnessKey(t, 1)},
		nonZeroNetworkID(), 1, nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	cases := []struct {
		name string
		cfg  EquivocationMonitorConfig
		want string
	}{
		{
			name: "nil store",
			cfg: EquivocationMonitorConfig{
				WitnessKeys: quorum.NewManager(validSet),
			},
			want: "Store",
		},
		{
			name: "nil witness keys",
			cfg: EquivocationMonitorConfig{
				Store: sdkgossip.NewInMemoryStore(),
			},
			want: "WitnessKeys",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEquivocationMonitor(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want contains %q", err, tc.want)
			}
		})
	}
}

// hexDecodeForMonitor — keep encoding/hex live in case future
// debugging needs raw byte inspection.
var _ = hex.EncodeToString

// silenceLinter forces a use of the signatures import (kept for
// future scheme-tag assertions in the test fixture).
var _ = signatures.SchemeECDSA
