package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/schema"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// mkEntry builds a real, serializable, signed envelope with the given header signer
// and domain payload. The signature is structurally valid (Serialize requires one)
// but not key-bound to headerSigner — the chain helpers read only the payload +
// header signer, never verify the author signature (that is the SDK verifier's job).
func mkEntry(t *testing.T, headerSigner string, payload []byte) []byte {
	t.Helper()
	e, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   headerSigner,
		Destination: "did:web:dest.example",
		EventTime:   1700000000,
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	h := sha256.Sum256(envelope.SigningPayload(e))
	sig, err := signatures.SignEntry(h, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	e.Signatures = []envelope.Signature{{SignerDID: headerSigner, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	b, err := envelope.Serialize(e)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return b
}

// mkRotation builds a real signer-rotation entry whose PAYLOAD rotates payloadSigner
// (which may differ from the entry's headerSigner — the authority-issued case).
func mkRotation(t *testing.T, payloadSigner, headerSigner string) []byte {
	t.Helper()
	p, err := verifier.EncodeRotationPayload(verifier.RotationPayload{
		SignerDID:    payloadSigner,
		NewPublicKey: bytes.Repeat([]byte{0x02}, 33),
	})
	if err != nil {
		t.Fatalf("EncodeRotationPayload: %v", err)
	}
	return mkEntry(t, headerSigner, p)
}

// mkSchema builds a real schema entry whose params carry the given predecessor (nil
// = root of the chain).
func mkSchema(t *testing.T, predecessor *types.LogPosition) []byte {
	t.Helper()
	p := &types.SchemaParameters{
		PredecessorSchema:     predecessor,
		CommutativeOperations: []uint32{},
	}
	payload, err := schema.MarshalParameters(p)
	if err != nil {
		t.Fatalf("MarshalParameters: %v", err)
	}
	return mkEntry(t, "did:web:schema.author", payload)
}

// mapFetch returns a fetch func backed by a seq→canonical map.
func mapFetch(m map[uint64][]byte) func(context.Context, uint64) ([]byte, error) {
	return func(_ context.Context, seq uint64) ([]byte, error) {
		b, ok := m[seq]
		if !ok {
			return nil, errNoEntry(seq)
		}
		return b, nil
	}
}

type errNoEntry uint64

func (e errNoEntry) Error() string { return "no entry at sequence" }

const (
	signerX   = "did:key:zQ3shXXXX"
	signerY   = "did:key:zQ3shYYYY"
	authority = "did:web:authority.example"
)

// filterRotationsForSigner keeps exactly the rotations whose PAYLOAD signer is the
// target — including an authority-issued rotation (header signer ≠ payload signer),
// which a signer_did index would miss — and skips a non-rotation entry sharing the
// rotation schema.
func TestFilterRotationsForSigner(t *testing.T) {
	entries := map[uint64][]byte{
		3:  mkRotation(t, signerX, signerX),                       // X self-rotation
		5:  mkRotation(t, signerY, signerY),                       // Y's rotation — excluded
		8:  mkRotation(t, signerX, authority),                     // authority-issued rotation OF X — kept
		11: mkEntry(t, signerX, []byte(`{"kind":"other","x":1}`)), // not a rotation — skipped
	}
	candidates := []DiscoveredEntry{{3}, {5}, {8}, {11}}
	got, err := filterRotationsForSigner(context.Background(), candidates, signerX, mapFetch(entries))
	if err != nil {
		t.Fatalf("filterRotationsForSigner: %v", err)
	}
	if len(got) != 2 || got[0].Sequence != 3 || got[1].Sequence != 8 {
		t.Fatalf("kept = %+v, want sequences [3 8] (X self + authority-issued of X)", got)
	}
}

// A malformed rotation payload (correct kind, invalid body) on the rotation schema
// is a hard error — not silently skipped.
func TestFilterRotationsForSigner_MalformedIsError(t *testing.T) {
	entries := map[uint64][]byte{
		4: mkEntry(t, signerX, []byte(`{"kind":"BP-ENTRY-SIGNER-ROTATION-PAYLOAD-V1"}`)), // no signer_did/new_public_key
	}
	_, err := filterRotationsForSigner(context.Background(), []DiscoveredEntry{{4}}, signerX, mapFetch(entries))
	if err == nil {
		t.Fatal("a malformed rotation payload must be a hard error")
	}
}

// walkSchemaPredecessors follows predecessor_schema from the pinned ref to the root.
func TestWalkSchemaPredecessors(t *testing.T) {
	const did = "did:web:net.example"
	v1 := types.LogPosition{LogDID: did, Sequence: 10}
	v2 := types.LogPosition{LogDID: did, Sequence: 20}
	v3 := types.LogPosition{LogDID: did, Sequence: 30}
	entries := map[uint64][]byte{
		30: mkSchema(t, &v2), // v3 → v2
		20: mkSchema(t, &v1), // v2 → v1
		10: mkSchema(t, nil), // v1 root
	}
	got, err := walkSchemaPredecessors(context.Background(), v3, mapFetch(entries))
	if err != nil {
		t.Fatalf("walkSchemaPredecessors: %v", err)
	}
	if len(got) != 3 || got[0].Sequence != 30 || got[1].Sequence != 20 || got[2].Sequence != 10 {
		t.Fatalf("chain = %+v, want [30 20 10]", got)
	}
}

// A single schema with no predecessor is a one-element chain.
func TestWalkSchemaPredecessors_Root(t *testing.T) {
	const did = "did:web:net.example"
	root := types.LogPosition{LogDID: did, Sequence: 7}
	got, err := walkSchemaPredecessors(context.Background(), root, mapFetch(map[uint64][]byte{7: mkSchema(t, nil)}))
	if err != nil || len(got) != 1 || got[0].Sequence != 7 {
		t.Fatalf("root-only chain = %+v, err=%v", got, err)
	}
}

// A predecessor cycle fails closed.
func TestWalkSchemaPredecessors_Cycle(t *testing.T) {
	const did = "did:web:net.example"
	a := types.LogPosition{LogDID: did, Sequence: 1}
	b := types.LogPosition{LogDID: did, Sequence: 2}
	entries := map[uint64][]byte{
		2: mkSchema(t, &a), // b → a
		1: mkSchema(t, &b), // a → b  (cycle)
	}
	if _, err := walkSchemaPredecessors(context.Background(), b, mapFetch(entries)); err == nil {
		t.Fatal("a schema-chain cycle must fail closed")
	}
}

// A predecessor on a foreign log is rejected (out of single-network scope) rather
// than silently truncating the chain.
func TestWalkSchemaPredecessors_ForeignLog(t *testing.T) {
	const did = "did:web:net.example"
	foreign := types.LogPosition{LogDID: "did:web:other.example", Sequence: 9}
	start := types.LogPosition{LogDID: did, Sequence: 5}
	entries := map[uint64][]byte{5: mkSchema(t, &foreign)}
	if _, err := walkSchemaPredecessors(context.Background(), start, mapFetch(entries)); err == nil {
		t.Fatal("a foreign-log predecessor must be rejected")
	}
}
