package cli

/*
require_proof_test.go — require-network offline proofs (#75 residual item 1,
closed by baseproof#51 in SDK v0.0.4-rc7).

The proof embeds the constitution in its ONE transport form (the endorsed
serving form) and D1 verifies the genesis ceremony OFFLINE. This file pins the
CLI's half of that contract — and the end-to-end round-trip that was
structurally impossible before rc7 runs here un-skipped:

  - RefusesStrippedRequire — trustRootFromProof refuses a require constitution
    stripped of its ceremony (the strip attack at the offline gate);
  - AcceptsEndorsedRequire — the same gate accepts the transport form and
    derives the trust root from the verified document alone;
  - EndToEnd_RoundTrip — generateProof → file → verifyProofFile on a REQUIRE
    network, the network class production ships.
*/

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/protocol"
)

// proofWithEmbeddedBootstrap builds the minimal StandaloneProof shape
// trustRootFromProof reads: the genesis section is exactly the embedded
// document (one wire field — nothing in the proof restates what it pins).
func proofWithEmbeddedBootstrap(doc []byte) *sdkbundle.StandaloneProof {
	return &sdkbundle.StandaloneProof{
		SelfAnchor: sdkbundle.SelfAnchor{
			GenesisBootstrap: sdkbundle.GenesisBootstrap{
				BootstrapDocument: doc,
			},
		},
	}
}

// TestTrustRootFromProof_RefusesStrippedRequire: a require constitution embedded
// WITHOUT its endorsements (the canonical/identity form) is rejected at the
// offline gate — the genesis ceremony cannot verify, so no trust root derives.
func TestTrustRootFromProof_RefusesStrippedRequire(t *testing.T) {
	_, stripped, _ := mintRequireNetwork(t)

	_, err := trustRootFromProof(proofWithEmbeddedBootstrap(stripped))
	if err == nil {
		t.Fatal("trustRootFromProof accepted a STRIPPED require constitution — the strip attack would verify offline")
	}
	if !strings.Contains(err.Error(), "first-contact verification") {
		t.Fatalf("refusal did not come from the ceremony gate: %v", err)
	}
}

// TestTrustRootFromProof_AcceptsEndorsedRequire: fed the transport form (what
// the rc7 builder embeds), the gate verifies the ceremony and yields the trust
// root — witness DIDs, the constitutional K, and the canonical-subset hash all
// read from the verified document.
func TestTrustRootFromProof_AcceptsEndorsedRequire(t *testing.T) {
	endorsed, _, _ := mintRequireNetwork(t)

	roots, err := trustRootFromProof(proofWithEmbeddedBootstrap(endorsed))
	if err != nil {
		t.Fatalf("trustRootFromProof refused an ENDORSED require constitution: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("expected exactly one genesis trust root, got %d", len(roots))
	}
	for nid, tr := range roots {
		if tr.QuorumK != 1 {
			t.Fatalf("trust root QuorumK=%d, want the constitutional 1", tr.QuorumK)
		}
		if cosign.NetworkID(tr.NetworkID) != nid {
			t.Fatal("trust root NetworkID does not match its map key")
		}
		if tr.BootstrapDocumentHash != [32]byte(tr.NetworkID) {
			t.Fatal("trust root bind hash != NetworkID — for v2 they are the same canonical-subset digest")
		}
	}
}

// TestRequireProof_EndToEnd_RoundTrip: the full contract on a REQUIRE network —
// the CLI builds a real-crypto proof through the SDK v2 builder (which embeds
// the endorsed transport form), writes it to a file, and verifies it fully
// offline. This is the round-trip that was structurally broken before
// baseproof#51; it runs un-skipped from birth on rc7.
func TestRequireProof_EndToEnd_RoundTrip(t *testing.T) {
	ctx := context.Background()
	g, _, seq := mustRequireGather(t, 3, 2)

	proof, err := generateProof(ctx, g, seq)
	if err != nil {
		t.Fatalf("generateProof (require network): %v", err)
	}
	path := filepath.Join(t.TempDir(), "require.proof")
	if err := writeProofFile(proof, path); err != nil {
		t.Fatalf("writeProofFile: %v", err)
	}
	_, res, err := verifyProofFile(ctx, path, "")
	if err != nil {
		t.Fatalf("require-network proof failed offline verification: %v", err)
	}
	if !res.Valid {
		t.Fatal("require-network proof verified not-valid")
	}
}

// mustRequireGather is mustRealGather with a require-endorsement constitution —
// the gather a require network's ledger hands the v2 builder.
func mustRequireGather(t *testing.T, n, k int) (*realGather, map[cosign.NetworkID]protocol.GenesisTrustRoot, uint64) {
	fx := buildRealFixture(t, n, k, true)
	g := &realGather{
		bdoc: fx.bdoc, k: fx.k, entry: fx.entryBytes, logTime: fx.logTime,
		head: fx.head, inc: *fx.inc, smt: *fx.smtProof,
	}
	return g, fx.trustRoots, fx.seq
}
