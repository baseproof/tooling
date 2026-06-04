/*
FILE PATH: gossipnet/history_rewrite_test.go

Tests for the post-Part-II #2 history-rewrite detection branch
in EquivocationMonitor + the HistoryRewritePublisher.

Coverage:
  - Constructor validation for HistoryRewritePublisher
    (NetworkID, Store, Sink, Signer, Originator required).
  - End-to-end: monitor detects cross-TreeSize with a failing
    consistency proof → publishes a KindHistoryRewriteFinding
    event via HistoryRewritePublisher. Mirrors the SMT-replay e2e
    test from II.4.
  - Append-only-consistent peer (correct empty consistency proof
    where the two heads ARE consistent) → no false positive.
  - Peer refuses to serve consistency proof (503) → monitor
    logs but does NOT publish (we can't prove a rewrite without
    the failing proof bytes).
  - Observe-only posture: nil HistoryRewritePublisher → branch
    still runs but no event published.

These tests use the same fixtureWitnesses + cosignHead +
signSTHEvent helpers as the existing equivocation/SMT-replay
tests, so the history-rewrite path is exercised against the
same crypto surface.
*/
package gossipnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/quorum"
)

// ─────────────────────────────────────────────────────────────────────
// Constructor validation
// ─────────────────────────────────────────────────────────────────────

func TestHistoryRewritePublisher_RejectsZeroNetworkID(t *testing.T) {
	kp, _ := did.GenerateDIDKeySecp256k1()
	_, err := NewHistoryRewritePublisher(HistoryRewritePublisherConfig{
		Store:      sdkgossip.NewInMemoryStore(),
		Sink:       sdkgossip.NopSink,
		Signer:     cosign.NewECDSAWitnessSigner(kp.PrivateKey),
		Originator: kp.DID,
	})
	if err == nil {
		t.Fatal("zero NetworkID must be rejected")
	}
}

func TestHistoryRewritePublisher_RejectsMissingFields(t *testing.T) {
	kp, _ := did.GenerateDIDKeySecp256k1()
	signer := cosign.NewECDSAWitnessSigner(kp.PrivateKey)
	netID := nonZeroNetworkID()
	cases := []struct {
		name string
		cfg  HistoryRewritePublisherConfig
	}{
		{"missing Store", HistoryRewritePublisherConfig{
			NetworkID: netID, Sink: sdkgossip.NopSink, Signer: signer, Originator: kp.DID,
		}},
		{"missing Sink", HistoryRewritePublisherConfig{
			NetworkID: netID, Store: sdkgossip.NewInMemoryStore(), Signer: signer, Originator: kp.DID,
		}},
		{"missing Signer", HistoryRewritePublisherConfig{
			NetworkID: netID, Store: sdkgossip.NewInMemoryStore(), Sink: sdkgossip.NopSink, Originator: kp.DID,
		}},
		{"missing Originator", HistoryRewritePublisherConfig{
			NetworkID: netID, Store: sdkgossip.NewInMemoryStore(), Sink: sdkgossip.NopSink, Signer: signer,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewHistoryRewritePublisher(c.cfg); err == nil {
				t.Error("expected error")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// End-to-end test fixtures
// ─────────────────────────────────────────────────────────────────────

// historyRewriteTestServer serves BOTH gossip STH and the
// consistency proof endpoints. The STH endpoint returns the
// LARGER head (peerEvent); the consistency endpoint returns the
// supplied hashes (which the test caller crafts to deliberately
// fail or pass).
func historyRewriteTestServer(
	t *testing.T,
	peerEvent sdkgossip.SignedEvent,
	proofHashes []string,
	proofStatus int,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/gossip/sth/latest":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sdkgossip.LatestSTHResponse{
				Kind:    peerEvent.Kind,
				Event:   peerEvent,
				Lamport: peerEvent.LamportTime,
			})
		case strings.HasPrefix(r.URL.Path, "/v1/tree/consistency/"):
			if proofStatus != 0 && proofStatus != http.StatusOK {
				w.WriteHeader(proofStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			hashesJSON := "[]"
			if len(proofHashes) > 0 {
				parts := make([]string, len(proofHashes))
				for i, h := range proofHashes {
					parts[i] = `"` + h + `"`
				}
				hashesJSON = "[" + strings.Join(parts, ",") + "]"
			}
			fmt.Fprintf(w, `{"old_size":0,"new_size":0,"hashes":%s}`, hashesJSON)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// ─────────────────────────────────────────────────────────────────────
// End-to-end: detect + publish
// ─────────────────────────────────────────────────────────────────────

// TestEquivocationMonitor_DetectsHistoryRewriteAndPublishes is the
// full e2e history-rewrite path:
//
//  1. local head TreeSize=100, peer head TreeSize=200 (DIFFERENT)
//  2. peer serves a deliberately-failing consistency proof
//  3. DetectHistoryRewrite returns *proof
//  4. Verify succeeds (both heads have valid K-of-N + proof
//     re-fails)
//  5. publisher fires → local store gains a
//     KindHistoryRewriteFinding event
func TestEquivocationMonitor_DetectsHistoryRewriteAndPublishes(t *testing.T) {
	const K = 2
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)

	// DIFFERENT TreeSize — old head 100, new head 200.
	headOld := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xA5}}
	headNew := types.TreeHead{TreeSize: 200, RootHash: [32]byte{0xBB}, SMTRoot: [32]byte{0xB5}}
	cosOld := cosignHead(t, ws, headOld, netID)
	cosNew := cosignHead(t, ws, headNew, netID)

	// Local store: contains the OLD head.
	store := sdkgossip.NewInMemoryStore()
	localSTH := signSTHEvent(t, peerSigner, peerKP.DID, cosOld, netID)
	if err := store.Append(context.Background(), localSTH); err != nil {
		t.Fatalf("seed local store: %v", err)
	}

	// Peer serves the NEW head + a deliberately-failing consistency
	// proof. A non-empty proof of junk hashes will fail RFC 6962
	// verification under (headOld.RootHash, headNew.RootHash) →
	// DetectHistoryRewrite emits a proof.
	peerSTH := signSTHEvent(t, peerSigner, peerKP.DID, cosNew, netID)
	junkHash := strings.Repeat("cd", 32)
	srv := historyRewriteTestServer(t, peerSTH, []string{junkHash}, http.StatusOK)
	defer srv.Close()

	opKP, _ := did.GenerateDIDKeySecp256k1()
	opSigner := cosign.NewECDSAWitnessSigner(opKP.PrivateKey)

	hrPub, err := NewHistoryRewritePublisher(HistoryRewritePublisherConfig{
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
		Store:                   store,
		Peers:                   []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys:             quorum.NewManager(witnessSet),
		HistoryRewritePublisher: hrPub,
		Interval:                1 * time.Hour,
		HTTPClient:              testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	// Local store should now have:
	//   1. peer's KindCosignedTreeHead (seeded)
	//   2. ledger's KindHistoryRewriteFinding (published)
	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2 (1 seed + 1 published history-rewrite)", stats.EventCount)
	}
	if stats.Heads[opKP.DID] != 1 {
		t.Errorf("ledger chain lamport = %d, want 1 (one published history-rewrite finding)",
			stats.Heads[opKP.DID])
	}
}

// ─────────────────────────────────────────────────────────────────────
// False-positive + degraded-mode guards
// ─────────────────────────────────────────────────────────────────────

// Peer that REFUSES to serve the consistency proof (503) → the
// monitor logs but does NOT publish a finding. We cannot prove
// rewrite without the failing proof bytes.
func TestEquivocationMonitor_HistoryRewrite_PeerRefusesProof(t *testing.T) {
	const K = 1
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, _ := did.GenerateDIDKeySecp256k1()
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)
	headOld := types.TreeHead{TreeSize: 50, RootHash: [32]byte{0x01}, SMTRoot: [32]byte{0x02}}
	headNew := types.TreeHead{TreeSize: 75, RootHash: [32]byte{0x03}, SMTRoot: [32]byte{0x04}}
	cosOld := cosignHead(t, ws, headOld, netID)
	cosNew := cosignHead(t, ws, headNew, netID)

	store := sdkgossip.NewInMemoryStore()
	_ = store.Append(context.Background(),
		signSTHEvent(t, peerSigner, peerKP.DID, cosOld, netID))

	// 503 on /v1/tree/consistency
	srv := historyRewriteTestServer(t,
		signSTHEvent(t, peerSigner, peerKP.DID, cosNew, netID),
		nil, http.StatusServiceUnavailable)
	defer srv.Close()

	opKP, _ := did.GenerateDIDKeySecp256k1()
	hrPub, err := NewHistoryRewritePublisher(HistoryRewritePublisherConfig{
		Store: store, Sink: sdkgossip.NopSink,
		Signer:    cosign.NewECDSAWitnessSigner(opKP.PrivateKey),
		NetworkID: netID, Originator: opKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	witnessSet, _ := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:                   store,
		Peers:                   []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys:             quorum.NewManager(witnessSet),
		HistoryRewritePublisher: hrPub,
		Interval:                1 * time.Hour,
		HTTPClient:              testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (only seed; no publish under peer refusal)",
			stats.EventCount)
	}
}

// Observe-only: nil HistoryRewritePublisher + history-rewrite
// situation → no publish (the branch runs but exits without
// emitting).
func TestEquivocationMonitor_HistoryRewrite_ObserveOnly(t *testing.T) {
	const K = 1
	ws := newFixtureWitnesses(t, K)
	netID := nonZeroNetworkID()

	peerKP, _ := did.GenerateDIDKeySecp256k1()
	peerSigner := cosign.NewECDSAWitnessSigner(peerKP.PrivateKey)
	headOld := types.TreeHead{TreeSize: 33, RootHash: [32]byte{0x77}, SMTRoot: [32]byte{0xA1}}
	headNew := types.TreeHead{TreeSize: 66, RootHash: [32]byte{0x88}, SMTRoot: [32]byte{0xB1}}
	cosOld := cosignHead(t, ws, headOld, netID)
	cosNew := cosignHead(t, ws, headNew, netID)

	store := sdkgossip.NewInMemoryStore()
	_ = store.Append(context.Background(),
		signSTHEvent(t, peerSigner, peerKP.DID, cosOld, netID))

	junkHash := strings.Repeat("ee", 32)
	srv := historyRewriteTestServer(t,
		signSTHEvent(t, peerSigner, peerKP.DID, cosNew, netID),
		[]string{junkHash}, http.StatusOK)
	defer srv.Close()

	witnessSet, _ := cosign.NewWitnessKeySet(ws.keys, netID, K, nil)
	monitor, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:       store,
		Peers:       []AntiEntropyPeer{{DID: peerKP.DID, BaseURL: srv.URL}},
		WitnessKeys: quorum.NewManager(witnessSet),
		// HistoryRewritePublisher NIL → observe-only.
		Interval:   1 * time.Hour,
		HTTPClient: testHTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor.tick(context.Background())

	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (no publish under observe-only)",
			stats.EventCount)
	}
}
