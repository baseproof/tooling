/*
FILE PATH: witnessclient/rotation_cross_network_test.go

Cross-network replay defense for witness rotations at the
RotationHandler boundary.

# PROPERTY UNDER TEST

A types.WitnessRotation signed under NetworkID="jurisdiction-A"
MUST be rejected by a RotationHandler whose current witness set
is bound to NetworkID="jurisdiction-B". The audit-flagged Trust
Alignment #11 invariant (Cryptographic Domain Separation)
applied at the rotation path — the most security-critical
operation on the network: a forged rotation that admits a
peer-network's quorum as our own would let auditors verify
signatures from witnesses we never authorized.

# WHY HERE, NOT ONLY IN THE SDK

The SDK's tests/witness_rotation_finding_verify_test.go pins the
property at the FINDING surface. This test pins it at the LEDGER
boundary — RotationHandler.ProcessRotation, which is the
function we'll call from admin paths + inbound gossip handlers.
A regression that drops Verify from ProcessRotation's path (e.g.,
a future refactor that "optimizes" the verify step away) fails
loudly here, distinguishable in CI output from a SDK-side
regression.

The test deliberately uses a nil *pgxpool.Pool: Verify runs
BEFORE the DB write in ProcessRotation's load-bearing ordering.
A rotation that fails verification must never reach the database;
if a regression reorders the steps and tries the DB first, the
nil-pool nil-pointer dereference surfaces as a panic.
*/
package witnessclient_test

import (
	"context"
	"strings"
	"testing"

	envelope "github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// fakeRotationAppender commits a rotation payload as a (fake) on-log entry
// at a fixed sequence, returning a structurally-valid one-leaf inclusion
// proof. The proof is NOT root-checked by ProcessRotation/Validate, so a
// minimal structurally-valid proof suffices. Shared by the cross-network
// test here and the DB-backed history suite (both `witnessclient_test`).
type fakeRotationAppender struct {
	logDID string
	seq    uint64
	err    error // optional injected failure
}

func (f fakeRotationAppender) AppendRotationEntry(_ context.Context, payload []byte) ([]byte, types.LogPosition, *types.MerkleProof, error) {
	if f.err != nil {
		return nil, types.LogPosition{}, nil, f.err
	}
	entry, err := envelope.NewEntry(
		envelope.ControlHeader{SignerDID: "did:web:ledger.example.gov", Destination: "did:web:ledger.example.gov"},
		payload,
		[]envelope.Signature{{SignerDID: "did:web:ledger.example.gov", AlgoID: 1, Bytes: make([]byte, 64)}},
	)
	if err != nil {
		return nil, types.LogPosition{}, nil, err
	}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		return nil, types.LogPosition{}, nil, err
	}
	// On-log entry leaf = H(0x00 || EntryIdentity); the ledger feeds Tessera
	// the 32-byte identity, so a real proof binds to OnLogEntryLeafHash, not
	// EntryLeafHashBytes(canonical). Mirrors the real ledger (baseproof v1.43.0).
	leaf := envelope.OnLogEntryLeafHash(canonical)
	pos := types.LogPosition{LogDID: f.logDID, Sequence: f.seq}
	proof := &types.MerkleProof{LeafPosition: f.seq, LeafHash: leaf, Siblings: nil, TreeSize: f.seq + 1}
	return canonical, pos, proof, nil
}

var _ witnessclient.RotationLogAppender = fakeRotationAppender{}

// ─────────────────────────────────────────────────────────────────────
// Helpers — mirror the SDK's tests/witness_rotation_helpers_test.go
// shape. Replicated here because the SDK's tests/ helpers are
// internal-test-package and not importable.
// ─────────────────────────────────────────────────────────────────────

// netID returns a non-zero NetworkID with every byte set to b.
// Two distinct values produce two distinct NetworkIDs.
func netID(b byte) cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = b
	}
	return n
}

// Rotation fixtures are minted through witness/witnesstest (NewSet +
// MintRotation): valid-by-construction under every current verifier rule
// (predecessor quorum, Step-6 per-joiner consent, 2K>N). The hand-rolled
// buildValidRotation/freshKeys that placed placeholder NewSignatures predated
// per-joiner consent and the rc4 verifier rejects them — they are gone.

// ─────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────

// TestRotationHandler_CrossNetworkReplay_Rejects pins the load-
// bearing property: a rotation signed under Network-A's NetworkID
// MUST fail RotationHandler.ProcessRotation when the handler's
// current witness set is bound to Network-B's NetworkID. The
// rejection happens in the SDK Verify step (no DB write, no
// emit), so we can run the test with a nil *pgxpool.Pool — if a
// regression reorders the verify-before-persist invariant and
// tries the DB first, the test surfaces as a nil-pointer panic.
func TestRotationHandler_CrossNetworkReplay_Rejects(t *testing.T) {
	t.Parallel()

	const K, N = 2, 3
	netA := netID('A')
	netB := netID('B')

	// Mint a valid, joiner-consented rotation under Network-A's NetworkID.
	oldA := witnesstest.NewSet(t, netA, N, K)
	rotation := witnesstest.MintRotation(t, netA, oldA, witnesstest.NewSet(t, netA, N, K), K)

	// Handler holds a WitnessKeySet bound to Network-B's NetworkID
	// — the keys match the rotation's OLD set, but the NetworkID
	// is the wrong jurisdiction. The cryptographic domain-
	// separation invariant should refuse the rotation.
	setB, err := cosign.NewWitnessKeySet(oldA.Keys, netB, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet[netB]: %v", err)
	}
	rh := witnessclient.NewRotationHandler(
		nil, // *pgxpool.Pool — load-bearing nil; the test asserts
		// the verify rejection short-circuits before any DB write.
		quorum.NewManager(setB),
		signatures.SchemeECDSA,
		"https://ledger.example/", // LedgerEndpoint
		nil,                       // logger → default
	)

	// Capture emit attempts so we can assert the emitter is NEVER
	// invoked on a rotation that fails Verify.
	cap := &countingEmitter{}
	rh.WithEmitter(cap)

	// Wire a (never-reached) on-log appender so the handler is fully
	// configured — ProcessRotation requires one (it fails closed with
	// "appender not wired" otherwise). The cross-network rotation is
	// rejected at the Verify step (Step 2), which runs BEFORE the
	// appender (Step 2b), so the appender is never invoked here; wiring
	// it proves the rejection is the Verify check, not the unwired-
	// appender guard.
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.example.gov", seq: 1})

	newSet, err := rh.ProcessRotation(context.Background(), rotation)
	if err == nil {
		t.Fatal("ProcessRotation accepted cross-network rotation — domain separation BROKEN")
	}
	if newSet != nil {
		t.Errorf("expected nil newSet on verify failure, got %v", newSet)
	}
	// The error MUST come from the verify step. The wrap shape is
	// "witness/rotation: verify: ...". A regression that catches
	// the error after DB-write would surface as a different wrap.
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("err = %v, want substring 'verify' (failure must surface from the Verify step)", err)
	}
	// Emitter MUST NOT fire on verify failure. The handler's
	// step ordering pin: verify-before-emit.
	if cap.calls != 0 {
		t.Errorf("emitter fired %d times on verify-failed rotation; want 0 (verify-before-emit invariant)", cap.calls)
	}
}

// TestRotationHandler_SameNetwork_AcceptControl is the load-
// bearing control: if signing AND verifying under the SAME
// NetworkID also fails, the cross-network test's failure isn't
// attributable to the network mismatch — it would be a broken
// fixture. This test rules that class of false-positive out by
// exercising the SDK finding's Verify directly (which is the
// step ProcessRotation calls internally). We don't drive the
// handler's full hot path here because the downstream DB step
// would deref the unit-test environment's nil *pgxpool.Pool.
func TestRotationHandler_SameNetwork_AcceptControl(t *testing.T) {
	t.Parallel()

	const K, N = 2, 3
	netA := netID('A')

	oldA := witnesstest.NewSet(t, netA, N, K)
	rotation := witnesstest.MintRotation(t, netA, oldA, witnesstest.NewSet(t, netA, N, K), K)

	setA, err := cosign.NewWitnessKeySet(oldA.Keys, netA, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet[netA]: %v", err)
	}

	// Build the v1.39 self-contained finding the same way ProcessRotation
	// does: encode the rotation as the on-log entry payload (Step 1), commit
	// it through the on-log appender to obtain (entryCanonical, effectivePos,
	// proof) (Step 2b), then construct the finding (Step 5). The fake
	// appender's position is never root-checked here — Verify is a pure
	// authenticity check over the decoded rotation.
	payload, err := witness.EncodeWitnessRotationPayload(rotation)
	if err != nil {
		t.Fatalf("EncodeWitnessRotationPayload: %v", err)
	}
	canonical, pos, proof, err := fakeRotationAppender{
		logDID: "did:web:ledger.example.gov", seq: 1,
	}.AppendRotationEntry(context.Background(), payload)
	if err != nil {
		t.Fatalf("fake AppendRotationEntry: %v", err)
	}
	finding, err := findings.NewWitnessRotationFinding(canonical, pos, proof, "https://ledger.example/")
	if err != nil {
		t.Fatalf("NewWitnessRotationFinding: %v", err)
	}

	// Drive Verify directly — the exact authenticity check ProcessRotation
	// makes at rotation_handler.go::Step 2 (Verify decodes the rotation from
	// the entry bytes and runs witness.VerifyRotation under setA). If THIS
	// rejects the fixture, the cross-network test's "verify rejected" signal
	// isn't attributable to the network mismatch.
	if err := finding.Verify(setA); err != nil {
		t.Fatalf("same-network Verify rejected the fixture — "+
			"cross-network test signal is unreliable: %v", err)
	}
}

// countingEmitter records every Emit call. Used to assert the
// emit-after-verify-after-persist invariant in
// TestRotationHandler_CrossNetworkReplay_Rejects.
type countingEmitter struct {
	calls int
}

func (c *countingEmitter) Emit(_ context.Context, _ *findings.WitnessRotationFinding) {
	c.calls++
}

var _ witnessclient.WitnessRotationEmitter = (*countingEmitter)(nil)
