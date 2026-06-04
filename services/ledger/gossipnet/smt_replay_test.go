/*
FILE PATH: gossipnet/smt_replay_test.go

Tests for the Part II.4 SMT-replay detection branch in
EquivocationMonitor + the SMTReplayPublisher.

Coverage:
  - Constructor validation for SMTReplayPublisher (NetworkID,
    Store, Sink, Signer, Originator required).
  - Monitor detects same-TreeSize + same-RootHash +
    DIFFERENT-SMTRoot and emits a KindSMTReplayFinding event via
    SMTReplayPublisher (full end-to-end with real crypto, mirroring
    TestEquivocationMonitor_DetectsAndPublishes).
  - Monitor does NOT detect SMT replay when SMTRoots match (no
    false positive).
  - Monitor does NOT detect SMT replay when RootHashes differ (that
    is the equivocation path, not the SMT-replay path — distinct
    Kinds, distinct dashboards).
  - Monitor falls through to no-publish when both publishers are
    nil (observe-only posture).

These tests use the same fixtureWitnesses + cosignHead + stubLatestSTH
helpers as TestEquivocationMonitor_*, so the SMT-replay code path is
exercised against the same crypto surface the existing equivocation
path uses.
*/
package gossipnet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/quorum"
)

// ─────────────────────────────────────────────────────────────────────
// SMTReplayPublisher constructor validation
// ─────────────────────────────────────────────────────────────────────

func TestSMTReplayPublisher_RejectsZeroNetworkID(t *testing.T) {
	kp, _ := did.GenerateDIDKeySecp256k1()
	_, err := NewSMTReplayPublisher(SMTReplayPublisherConfig{
		Store:      sdkgossip.NewInMemoryStore(),
		Sink:       sdkgossip.NopSink,
		Signer:     cosign.NewECDSAWitnessSigner(kp.PrivateKey),
		Originator: kp.DID,
	})
	if err == nil {
		t.Fatal("zero NetworkID must be rejected")
	}
}

func TestSMTReplayPublisher_RejectsMissingFields(t *testing.T) {
	kp, _ := did.GenerateDIDKeySecp256k1()
	signer := cosign.NewECDSAWitnessSigner(kp.PrivateKey)
	netID := nonZeroNetworkID()
	cases := []struct {
		name string
		cfg  SMTReplayPublisherConfig
	}{
		{"missing Store", SMTReplayPublisherConfig{
			NetworkID: netID, Sink: sdkgossip.NopSink, Signer: signer, Originator: kp.DID,
		}},
		{"missing Sink", SMTReplayPublisherConfig{
			NetworkID: netID, Store: sdkgossip.NewInMemoryStore(), Signer: signer, Originator: kp.DID,
		}},
		{"missing Signer", SMTReplayPublisherConfig{
			NetworkID: netID, Store: sdkgossip.NewInMemoryStore(), Sink: sdkgossip.NopSink, Originator: kp.DID,
		}},
		{"missing Originator", SMTReplayPublisherConfig{
			NetworkID: netID, Store: sdkgossip.NewInMemoryStore(), Sink: sdkgossip.NopSink, Signer: signer,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewSMTReplayPublisher(c.cfg); err == nil {
				t.Error("expected error")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// End-to-end: monitor detects SMT replay and publishes
// ─────────────────────────────────────────────────────────────────────

// TestEquivocationMonitor_DetectsSMTReplayAndPublishes is the full
// e2e SMT-replay path: same TreeSize + same RootHash + DIFFERENT
// SMTRoot → DetectSMTReplay succeeds → Verify succeeds → SMT-replay
// publisher fires → local Store gains a KindSMTReplayFinding event.
func TestEquivocationMonitor_DetectsSMTReplayAndPublishes(t *testing.T) {
	const K = 2
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)

	// Same TreeSize + same RootHash + DIFFERENT SMTRoot. This is
	// the cryptographic SMT-replay shape — chronological log
	// honest, derived state forged.
	headA := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xA5}}
	headB := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xB5}}
	cosA := cosignHead(t, ws, headA, netID)
	cosB := cosignHead(t, ws, headB, netID)

	store := sdkgossip.NewInMemoryStore()
	localSTH := signSTHEvent(t, peerSigner, peerKP.DID, cosA, netID)
	if err := store.Append(context.Background(), localSTH); err != nil {
		t.Fatalf("seed local store: %v", err)
	}

	peerSTH := signSTHEvent(t, peerSigner, peerKP.DID, cosB, netID)
	srv := stubLatestSTH(t, peerSTH)
	defer srv.Close()

	opKP, _ := did.GenerateDIDKeySecp256k1()
	opSigner := cosign.NewECDSAWitnessSigner(opKP.PrivateKey)

	smtPub, err := NewSMTReplayPublisher(SMTReplayPublisherConfig{
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
		Store:              store,
		Peers:              []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys:        quorum.NewManager(witnessSet),
		SMTReplayPublisher: smtPub,
		Interval:           1 * time.Hour,
		HTTPClient:         testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	// Local store should now have:
	//   1. peer's KindCosignedTreeHead (seeded)
	//   2. ledger's KindSMTReplayFinding (published)
	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2 (1 seed + 1 published SMT replay)", stats.EventCount)
	}
	if stats.Heads[opKP.DID] != 1 {
		t.Errorf("ledger chain lamport = %d, want 1 (one published SMT-replay finding)",
			stats.Heads[opKP.DID])
	}
}

// ─────────────────────────────────────────────────────────────────────
// False-positive guards
// ─────────────────────────────────────────────────────────────────────

// Identical heads → no SMT replay (no false positive).
func TestEquivocationMonitor_NoSMTReplayOnIdenticalHeads(t *testing.T) {
	const K = 1
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, _ := did.GenerateDIDKeySecp256k1()
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)
	head := types.TreeHead{TreeSize: 50, RootHash: [32]byte{0x42}, SMTRoot: [32]byte{0x57}}
	cos := cosignHead(t, ws, head, netID)

	store := sdkgossip.NewInMemoryStore()
	localSTH := signSTHEvent(t, peerSigner, peerKP.DID, cos, netID)
	if err := store.Append(context.Background(), localSTH); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := stubLatestSTH(t, localSTH)
	defer srv.Close()

	opKP, _ := did.GenerateDIDKeySecp256k1()
	smtPub, err := NewSMTReplayPublisher(SMTReplayPublisherConfig{
		Store:      store,
		Sink:       sdkgossip.NopSink,
		Signer:     cosign.NewECDSAWitnessSigner(opKP.PrivateKey),
		NetworkID:  netID,
		Originator: opKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessSet, _ := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:              store,
		Peers:              []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys:        quorum.NewManager(witnessSet),
		SMTReplayPublisher: smtPub,
		Interval:           1 * time.Hour,
		HTTPClient:         testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (only the seed; no false-positive publish)",
			stats.EventCount)
	}
}

// Different RootHashes → equivocation path, NOT SMT-replay path.
// The SMTReplayPublisher MUST NOT fire when the offence is
// equivocation; that lets the audit dashboard route by Kind.
func TestEquivocationMonitor_DiffRootHashes_PublishesEquivocationNotSMTReplay(t *testing.T) {
	const K = 1
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, _ := did.GenerateDIDKeySecp256k1()
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)
	// Same TreeSize, DIFFERENT RootHash → equivocation
	// (NOT SMT replay — that needs same RootHash).
	headA := types.TreeHead{TreeSize: 10, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xA0}}
	headB := types.TreeHead{TreeSize: 10, RootHash: [32]byte{0xBB}, SMTRoot: [32]byte{0xB0}}
	cosA := cosignHead(t, ws, headA, netID)
	cosB := cosignHead(t, ws, headB, netID)

	store := sdkgossip.NewInMemoryStore()
	_ = store.Append(context.Background(), signSTHEvent(t, peerSigner, peerKP.DID, cosA, netID))
	srv := stubLatestSTH(t, signSTHEvent(t, peerSigner, peerKP.DID, cosB, netID))
	defer srv.Close()

	opKP, _ := did.GenerateDIDKeySecp256k1()
	opSigner := cosign.NewECDSAWitnessSigner(opKP.PrivateKey)

	equivPub, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Store: store, Sink: sdkgossip.NopSink,
		Signer: opSigner, NetworkID: netID, Originator: opKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}
	smtPub, err := NewSMTReplayPublisher(SMTReplayPublisherConfig{
		Store: store, Sink: sdkgossip.NopSink,
		Signer: opSigner, NetworkID: netID, Originator: opKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessSet, _ := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:              store,
		Peers:              []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys:        quorum.NewManager(witnessSet),
		Publisher:          equivPub,
		SMTReplayPublisher: smtPub,
		Interval:           1 * time.Hour,
		HTTPClient:         testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	// One equivocation, ZERO SMT-replay. Total events = 2 (seed +
	// 1 equivocation), NOT 3 (seed + 1 equivocation + 1
	// SMT-replay).
	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2 (seed + 1 equivocation); "+
			"the SMT-replay branch must NOT fire on a RootHash divergence",
			stats.EventCount)
	}
}

// Observe-only posture: nil SMTReplayPublisher → detection still
// happens (no panic) but no event is published.
func TestEquivocationMonitor_SMTReplayObserveOnly(t *testing.T) {
	const K = 1
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, _ := did.GenerateDIDKeySecp256k1()
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)
	headA := types.TreeHead{TreeSize: 33, RootHash: [32]byte{0x77}, SMTRoot: [32]byte{0xA1}}
	headB := types.TreeHead{TreeSize: 33, RootHash: [32]byte{0x77}, SMTRoot: [32]byte{0xB1}}
	cosA := cosignHead(t, ws, headA, netID)
	cosB := cosignHead(t, ws, headB, netID)

	store := sdkgossip.NewInMemoryStore()
	_ = store.Append(context.Background(), signSTHEvent(t, peerSigner, peerKP.DID, cosA, netID))
	srv := stubLatestSTH(t, signSTHEvent(t, peerSigner, peerKP.DID, cosB, netID))
	defer srv.Close()

	witnessSet, _ := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:       store,
		Peers:       []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys: quorum.NewManager(witnessSet),
		// Publisher + SMTReplayPublisher BOTH nil → observe-only.
		Interval:   1 * time.Hour,
		HTTPClient: testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	// No publishing; the seed event is the only event in the store.
	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (no publish under observe-only)",
			stats.EventCount)
	}
}

// _ keeps imports stable.
var _ = http.HandlerFunc(nil)
var _ = httptest.NewRequest
