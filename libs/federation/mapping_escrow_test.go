/*
FILE PATH: libs/federation/mapping_escrow_test.go

COVERAGE:

	Every code path in mapping_escrow.go: constructor validation
	(nil store, threshold range, empty dealer/destination), V2
	happy path, atomic-emission invariant (every successful create
	yields CommitmentEntry + Commitment), recovery-with-commitment-
	verification round-trip, and TransferMapping to a fresh node set.
*/
package federation

import (
	"context"
	"crypto/ecdsa"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/baseproof/baseproof/core/vss"
	"github.com/baseproof/baseproof/crypto/escrow"
	"github.com/baseproof/baseproof/exchange/identity"
	"github.com/baseproof/baseproof/storage"
)

// ─── Helpers ────────────────────────────────────────────────────────

// newEscrowNodes generates a fresh set of secp256k1 EscrowNodes. The
// SDK's ECIES path requires keys on the secp256k1 curve (verified
// via on-curve check); P-256 keys are rejected.
func newEscrowNodes(t *testing.T, n int) ([]identity.EscrowNode, []*ecdsa.PrivateKey) {
	t.Helper()
	nodes := make([]identity.EscrowNode, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		sk, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("genkey: %v", err)
		}
		ek := sk.ToECDSA()
		nodes[i] = identity.EscrowNode{
			DID:    diDForNode(i),
			PubKey: &ek.PublicKey,
		}
		privs[i] = ek
	}
	return nodes, privs
}

func diDForNode(i int) string {
	switch i {
	case 0:
		return "did:web:node0"
	case 1:
		return "did:web:node1"
	case 2:
		return "did:web:node2"
	case 3:
		return "did:web:node3"
	case 4:
		return "did:web:node4"
	default:
		return "did:web:node-other"
	}
}

func freshConfig(t *testing.T, threshold, total int) MappingEscrowConfig {
	t.Helper()
	nodes, _ := newEscrowNodes(t, total)
	return MappingEscrowConfig{
		ContentStore: storage.NewInMemoryContentStore(),
		Nodes:        nodes,
		Threshold:    threshold,
		DealerDID:    "did:web:consortium-dealer",
		Destination:  "did:web:exchange.test",
	}
}

func mkRecord() (h [32]byte, ref identity.CredentialRef) {
	for i := range h {
		h[i] = byte(i + 1)
	}
	ref = identity.CredentialRef{LogDID: "did:web:l", Sequence: 100}
	return
}

// ─── Constructor validation ────────────────────────────────────────

func TestNewMappingEscrowManager_NilContentStore(t *testing.T) {
	cfg := freshConfig(t, 3, 5)
	cfg.ContentStore = nil
	_, err := NewMappingEscrowManager(cfg)
	if err == nil {
		t.Fatal("expected error for nil content store")
	}
}

func TestNewMappingEscrowManager_BadThreshold(t *testing.T) {
	cfg := freshConfig(t, 0, 5)
	if _, err := NewMappingEscrowManager(cfg); err == nil {
		t.Fatal("threshold=0 must error")
	}
	cfg.Threshold = 6 // > node count
	if _, err := NewMappingEscrowManager(cfg); err == nil {
		t.Fatal("threshold>nodes must error")
	}
}

func TestNewMappingEscrowManager_EmptyDealerDID(t *testing.T) {
	cfg := freshConfig(t, 3, 5)
	cfg.DealerDID = ""
	if _, err := NewMappingEscrowManager(cfg); err == nil {
		t.Fatal("empty dealer must error")
	}
}

func TestNewMappingEscrowManager_EmptyDestination(t *testing.T) {
	cfg := freshConfig(t, 3, 5)
	cfg.Destination = ""
	if _, err := NewMappingEscrowManager(cfg); err == nil {
		t.Fatal("empty destination must error")
	}
}

// ─── CreateMapping happy path: atomic emission invariant ───────────

func TestCreateMapping_V2_AtomicCommitmentEmission(t *testing.T) {
	ctx := context.Background()
	mgr, err := NewMappingEscrowManager(freshConfig(t, 3, 5))
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	identityHash, credRef := mkRecord()
	res, err := mgr.CreateMapping(ctx, identityHash, credRef, 1700000000)
	if err != nil {
		t.Fatalf("CreateMapping: %v", err)
	}
	if res.Stored == nil {
		t.Error("Stored must be non-nil")
	}
	if res.Commitment == nil {
		t.Error("Commitment must be non-nil")
	}
	if res.CommitmentEntry == nil {
		t.Error("CommitmentEntry must be non-nil — atomic-emission invariant")
	}
	if res.CommitmentEntry.Header.Destination != "did:web:exchange.test" {
		t.Errorf("Destination = %q", res.CommitmentEntry.Header.Destination)
	}
	if res.CommitmentEntry.Header.SignerDID != "did:web:consortium-dealer" {
		t.Errorf("SignerDID = %q", res.CommitmentEntry.Header.SignerDID)
	}
	if len(res.EncShares) != 5 {
		t.Errorf("EncShares len = %d, want 5", len(res.EncShares))
	}
	if res.Commitment.M != 3 || res.Commitment.N != 5 {
		t.Errorf("Commitment M/N = %d/%d, want 3/5", res.Commitment.M, res.Commitment.N)
	}
}

// ─── Distinct CreateMapping calls produce distinct SplitIDs ────────

func TestCreateMapping_DistinctCalls_DistinctSplitIDs(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewMappingEscrowManager(freshConfig(t, 3, 5))
	idA, refA := mkRecord()
	idB, refB := mkRecord()
	idB[0] = 0xFF // make distinct
	refB.Sequence = 200

	resA, err := mgr.CreateMapping(ctx, idA, refA, 1700000000)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	resB, err := mgr.CreateMapping(ctx, idB, refB, 1700000000)
	if err != nil {
		t.Fatalf("B: %v", err)
	}

	if resA.Commitment.SplitID == resB.Commitment.SplitID {
		t.Error("two distinct mappings must have distinct SplitIDs (random nonce)")
	}
}

// ─── TransferMapping creates a fresh, distinct mapping ─────────────

func TestTransferMapping_FreshNodeSet(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewMappingEscrowManager(freshConfig(t, 3, 5))
	identityHash, credRef := mkRecord()

	original, err := mgr.CreateMapping(ctx, identityHash, credRef, 1700000000)
	if err != nil {
		t.Fatalf("orig: %v", err)
	}

	newCfg := freshConfig(t, 2, 3)
	newCfg.DealerDID = "did:web:successor-dealer"
	newCfg.Destination = "did:web:successor-exchange"

	transferred, err := mgr.TransferMapping(ctx, identityHash, credRef, newCfg, 1700000001)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	// New SplitID, new commitment entry, new dealer signed it.
	if transferred.Commitment.SplitID == original.Commitment.SplitID {
		t.Error("TransferMapping must produce a new SplitID")
	}
	if transferred.CommitmentEntry.Header.SignerDID != "did:web:successor-dealer" {
		t.Errorf("transferred signer = %q", transferred.CommitmentEntry.Header.SignerDID)
	}
	if len(transferred.EncShares) != 3 {
		t.Errorf("transferred EncShares = %d, want 3", len(transferred.EncShares))
	}
}

// ─── TransferMapping init failure surfaces ─────────────────────────

func TestTransferMapping_InitFailure_Errors(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewMappingEscrowManager(freshConfig(t, 3, 5))
	identityHash, credRef := mkRecord()
	bad := freshConfig(t, 0, 5) // threshold=0
	if _, err := mgr.TransferMapping(ctx, identityHash, credRef, bad, 0); err == nil {
		t.Error("TransferMapping must surface bad-config error")
	}
}

// ─── RecoverMapping: short share count rejects ─────────────────────

func TestRecoverMapping_ShortShares_Rejected(t *testing.T) {
	mgr, _ := NewMappingEscrowManager(freshConfig(t, 3, 5))
	_, err := mgr.RecoverMapping(nil, vss.Commitments{})
	if err == nil {
		t.Error("nil shares must error")
	}
}

// ─── RecoverMapping: enough shares but invalid commitments rejects ──

func TestRecoverMapping_InvalidCommitments_Rejected(t *testing.T) {
	mgr, _ := NewMappingEscrowManager(freshConfig(t, 3, 5))
	// Three placeholder shares — the count satisfies the threshold
	// but the commitments are empty, so ReconstructV2 rejects at
	// the verification step.
	shares := []escrow.Share{
		{Index: 1}, {Index: 2}, {Index: 3},
	}
	_, err := mgr.RecoverMapping(shares, vss.Commitments{})
	if err == nil {
		t.Error("empty commitments must reject reconstruct")
	}
}

// ─── RecoverMapping: round-trip with real SplitV2 output ──────────

func TestRecoverMapping_HappyPath_RoundTrip(t *testing.T) {
	mgr, _ := NewMappingEscrowManager(freshConfig(t, 3, 5))
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}
	shares, commitments, _, err := escrow.SplitV2(secret, 3, 5, "did:web:dealer-test", nonce)
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}

	// Use any 3 of the 5 shares.
	got, err := mgr.RecoverMapping(shares[:3], commitments)
	if err != nil {
		t.Fatalf("RecoverMapping: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("recovered = %x, want %x", got, secret)
	}
}

// ─── CreateMapping: SDK error from underlying StoreMappingV2 ──────

func TestCreateMapping_SDKError_Surfaces(t *testing.T) {
	ctx := context.Background()
	cfg := freshConfig(t, 3, 5)
	mgr, _ := NewMappingEscrowManager(cfg)
	// CredentialRef with empty LogDID violates the SDK precondition.
	identityHash := [32]byte{0x01}
	_, err := mgr.CreateMapping(ctx, identityHash, identity.CredentialRef{}, 0)
	if err == nil {
		t.Error("SDK should reject empty CredentialRef.LogDID")
	}
}
