package bundle

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/storage"
	sdktypes "github.com/baseproof/baseproof/types"
)

// bundleCarrying returns a minimal, round-trippable bundle whose single entry
// carries wire as its opaque WireBytes.
func bundleCarrying(wire []byte) *sdkbundle.Bundle {
	return &sdkbundle.Bundle{
		Format:        sdkbundle.FormatV1,
		NetworkID:     [32]byte{0xAA, 0xBB},
		NetworkDID:    "did:baseproof:network:kindtest",
		BootstrapHash: [32]byte{0x11, 0x22},
		Entry: sdkbundle.BundleEntry{
			WireBytes: wire,
			Sequence:  7,
			LogTime:   time.Unix(1700000000, 0).UTC(),
		},
		CosignedHead: sdktypes.CosignedTreeHead{
			TreeHead: sdktypes.TreeHead{TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xBB}},
			Signatures: []sdktypes.WitnessSignature{{
				PubKeyID: [32]byte{0xCC}, SchemeTag: 0x01, SigBytes: []byte{0xDD, 0xEE},
			}},
		},
		InclusionProof: sdktypes.MerkleProof{LeafPosition: 7, TreeSize: 100},
		SMTProof: sdktypes.SMTProof{
			TerminalKind: sdktypes.SMTTerminalLeaf,
			TerminalLeaf: &sdktypes.SMTLeaf{Key: [32]byte{0x01}},
		},
		WitnessSetHint: sdkbundle.WitnessSetHint{SetHash: [32]byte{0xEE}},
		Algorithms:     sdkbundle.DefaultAlgorithmsHint(),
	}
}

// TestBundle_KindAgnostic_PassesNewKinds is the Tier-7b FORCED confirmation
// (issue #39): a bundle carries an entry of ANY kind as opaque WireBytes and
// never parses the DomainPayload. The new baseproof#97 kinds therefore ride
// through bundle encode/decode byte-for-byte, with no bundle change.
//
// For each new-kind payload, a bundle carrying it round-trips through
// sdkbundle.Encode → Decode with the WireBytes preserved exactly — the proof
// that the bundle layer is kind-agnostic (it pins the leaf's opaque identity,
// not its semantics).
func TestBundle_KindAgnostic_PassesNewKinds(t *testing.T) {
	// One representative payload per new kind, in its real on-log wire form.
	genesis, err := storage.EncodeArtifactGenesisPayload(storage.ArtifactGenesis{
		ArtifactCID: storage.Compute([]byte("a docket pdf")),
		MIMEType:    "application/pdf",
		MaxSize:     1 << 20,
		Owner:       "did:court:5",
	})
	if err != nil {
		t.Fatalf("encode artifact-genesis: %v", err)
	}
	commitmentRef, err := json.Marshal(storage.NewSMTDerivationCommitmentRef(
		sdktypes.SMTDerivationCommitment{
			LogRangeStart: sdktypes.LogPosition{Sequence: 1},
			LogRangeEnd:   sdktypes.LogPosition{Sequence: 1000},
			PriorSMTRoot:  [32]byte{0xaa}, PostSMTRoot: [32]byte{0xbb}, MutationCount: 873,
		},
		storage.Compute([]byte("the mutations blob")),
	))
	if err != nil {
		t.Fatalf("marshal commitment-ref: %v", err)
	}

	cases := []struct {
		kind string
		wire []byte
	}{
		{"SMTDerivationCommitmentRef", commitmentRef},
		{"ArtifactGenesis", genesis},
		// A custody-shaped opaque payload stands in for the custody lifecycle
		// kinds — the bundle cannot and does not distinguish it from any other.
		{"ArtifactCustody(opaque)", []byte(`{"content_digest":"sha256:00","owner":"did:court:5"}`)},
	}

	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			raw, err := sdkbundle.Encode(bundleCarrying(tc.wire))
			if err != nil {
				t.Fatalf("Encode bundle carrying %s: %v", tc.kind, err)
			}
			got, err := sdkbundle.Decode(raw)
			if err != nil {
				t.Fatalf("Decode bundle carrying %s: %v", tc.kind, err)
			}
			if !bytes.Equal(got.Entry.WireBytes, tc.wire) {
				t.Fatalf("%s: WireBytes not preserved through the bundle — the bundle must carry "+
					"new-kind entries opaquely, never parsing the payload", tc.kind)
			}
		})
	}
}
