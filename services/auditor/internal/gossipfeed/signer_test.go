package gossipfeed

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
)

func mustGenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

func encodeKeyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	var scalar [32]byte
	k.D.FillBytes(scalar[:])
	return pem.EncodeToMemory(&pem.Block{Type: signingKeyPEMType, Bytes: scalar[:]})
}

func TestLoadSigningKeyPEM_RoundTrip(t *testing.T) {
	key := mustGenKey(t)
	path := filepath.Join(t.TempDir(), "gossip.key")
	if err := os.WriteFile(path, encodeKeyPEM(t, key), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	got, err := LoadSigningKeyPEM(path)
	if err != nil {
		t.Fatalf("LoadSigningKeyPEM: %v", err)
	}
	if got.D.Cmp(key.D) != 0 {
		t.Fatalf("round-trip scalar mismatch")
	}
}

func TestDecodeSigningKeyPEM_WrongType(t *testing.T) {
	// A stdlib SEC1 P-256 envelope must fail loudly, not parse on the
	// wrong curve.
	bad := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: make([]byte, 32)})
	_, err := decodeSigningKeyPEM(bad)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig for wrong PEM type, got %v", err)
	}
}

func TestDecodeSigningKeyPEM_NoBlock(t *testing.T) {
	_, err := decodeSigningKeyPEM([]byte("not a pem"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig for missing block, got %v", err)
	}
}

func TestDIDKeyForSigningKey(t *testing.T) {
	did, err := DIDKeyForSigningKey(mustGenKey(t))
	if err != nil {
		t.Fatalf("DIDKeyForSigningKey: %v", err)
	}
	// secp256k1 did:key is the zQ3s… multibase form.
	if !strings.HasPrefix(did, "did:key:zQ3s") {
		t.Fatalf("derived DID = %q, want did:key:zQ3s… (secp256k1)", did)
	}
}

func TestNewEventSigner_Validation(t *testing.T) {
	signer := cosign.NewECDSAWitnessSigner(mustGenKey(t))
	nid := cosign.NetworkID{1}

	if _, err := NewEventSigner(nil, nid, "did:web:x"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil signer: want ErrInvalidConfig, got %v", err)
	}
	if _, err := NewEventSigner(signer, cosign.NetworkID{}, "did:web:x"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero networkID: want ErrInvalidConfig, got %v", err)
	}
	if _, err := NewEventSigner(signer, nid, ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty originator: want ErrInvalidConfig, got %v", err)
	}
}

func mustCTHFinding(t *testing.T) gossip.Event {
	t.Helper()
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			TreeSize: 1,
			RootHash: [32]byte{0x01},
			SMTRoot:  [32]byte{0x02},
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0x03}, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0x04}},
		},
	}
	f, err := findings.NewCosignedTreeHeadFinding(head, "https://ledger.example")
	if err != nil {
		t.Fatalf("NewCosignedTreeHeadFinding: %v", err)
	}
	return f
}

// TestEventSigner_MonotonicAndChained is the protocol-critical test:
// successive signs must advance the Lamport clock by exactly one and
// chain prev = EventIDOf(previous). A regression here makes peers reject
// JN's findings as replays (ErrLamportRegression) or chain breaks.
func TestEventSigner_MonotonicAndChained(t *testing.T) {
	key := mustGenKey(t)
	originator, err := DIDKeyForSigningKey(key)
	if err != nil {
		t.Fatalf("DIDKeyForSigningKey: %v", err)
	}
	es, err := NewEventSigner(cosign.NewECDSAWitnessSigner(key), cosign.NetworkID{1}, originator)
	if err != nil {
		t.Fatalf("NewEventSigner: %v", err)
	}
	ctx := context.Background()
	ev := mustCTHFinding(t)

	e1, err := es.Sign(ctx, ev)
	if err != nil {
		t.Fatalf("sign #1: %v", err)
	}
	e2, err := es.Sign(ctx, ev)
	if err != nil {
		t.Fatalf("sign #2: %v", err)
	}

	if e1.Originator != originator {
		t.Fatalf("originator = %q, want %q", e1.Originator, originator)
	}
	// D3: clock seeded from wall-clock ns ⇒ first emitted tick is huge,
	// guaranteeing a restarted JN never reuses an old sequence.
	if e1.LamportTime < 1_000_000_000_000_000_000 {
		t.Fatalf("LamportTime = %d, want wall-clock-seeded (>1e18)", e1.LamportTime)
	}
	if e2.LamportTime != e1.LamportTime+1 {
		t.Fatalf("LamportTime not +1: e1=%d e2=%d", e1.LamportTime, e2.LamportTime)
	}
	// First event has zero prev (chain genesis); second links to first.
	if e1.PrevHash != "" {
		t.Fatalf("e1.PrevHash = %q, want empty (genesis)", e1.PrevHash)
	}
	id1, err := gossip.EventIDOf(e1)
	if err != nil {
		t.Fatalf("EventIDOf(e1): %v", err)
	}
	if want := hex.EncodeToString(id1[:]); e2.PrevHash != want {
		t.Fatalf("e2.PrevHash = %q, want %q (chain link)", e2.PrevHash, want)
	}
}
