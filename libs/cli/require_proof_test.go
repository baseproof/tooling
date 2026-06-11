package cli

/*
require_proof_test.go — #75 residual (item 1): require-network offline proofs.

A require-endorsement network's proof→verify round-trip is structurally broken
at HEAD: the SDK's v2 builder embeds the CANONICAL (endorsement-stripped) form,
so first-contact verification of the embedded constitution refuses it. The fix
is a coordinated SDK build↔verify change (baseproof/baseproof#51).

This file pins BOTH halves of tooling's gate contract, so neither the current
refusal nor the future acceptance can regress unnoticed:

  - RefusesStrippedRequire — today's behavior: trustRootFromProof refuses a
    stripped require constitution (the ceremony cannot verify).
  - AcceptsEndorsedRequire — tooling's acceptance half, pinned in ADVANCE: fed
    the endorsed form directly, the SAME gate accepts it. When #51 lands and the
    builder embeds the endorsed form, this is the byte shape it will embed.
  - EndToEnd_RoundTrip — the full SDK build→verify round-trip, SKIPPED on #51.

The end-to-end test cannot pass until the SDK embeds the endorsed form (the gate
sees stripped bytes through generateProof today), which is precisely the boundary
worth a skipped test naming the issue.
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
// trustRootFromProof reads: the embedded genesis bootstrap bytes + its quorum K.
func proofWithEmbeddedBootstrap(doc []byte, quorumK int) *sdkbundle.StandaloneProof {
	return &sdkbundle.StandaloneProof{
		SelfAnchor: sdkbundle.SelfAnchor{
			GenesisBootstrap: sdkbundle.GenesisBootstrap{
				BootstrapDocument: doc,
				QuorumK:           quorumK,
			},
		},
	}
}

// TestTrustRootFromProof_RefusesStrippedRequire pins today's refusal: a require
// constitution embedded WITHOUT its endorsements (the canonical form the SDK
// builder embeds) is rejected at the offline gate — the genesis ceremony cannot
// verify, so the trust root cannot be derived.
func TestTrustRootFromProof_RefusesStrippedRequire(t *testing.T) {
	_, stripped, _ := mintRequireNetwork(t) // mintRequireNetwork uses GenesisQuorumK=1

	_, err := trustRootFromProof(proofWithEmbeddedBootstrap(stripped, 1))
	if err == nil {
		t.Fatal("trustRootFromProof accepted a STRIPPED require constitution — the strip attack would verify offline")
	}
	if !strings.Contains(err.Error(), "first-contact verification") {
		t.Fatalf("refusal did not come from the ceremony gate: %v", err)
	}
}

// TestTrustRootFromProof_AcceptsEndorsedRequire pins tooling's acceptance half
// in ADVANCE of the SDK fix: fed the ENDORSED form directly (the bytes the
// builder will embed once baseproof/baseproof#51 lands), the SAME gate runs the
// ceremony, verifies it, and yields the genesis trust root. No tooling change is
// needed when the SDK starts embedding this shape.
func TestTrustRootFromProof_AcceptsEndorsedRequire(t *testing.T) {
	endorsed, _, _ := mintRequireNetwork(t)

	roots, err := trustRootFromProof(proofWithEmbeddedBootstrap(endorsed, 1))
	if err != nil {
		t.Fatalf("trustRootFromProof refused an ENDORSED require constitution — tooling's acceptance half is broken: %v", err)
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
		var zero [32]byte
		if tr.BootstrapDocumentHash == zero {
			t.Fatal("trust root carries a zero bootstrap-document hash")
		}
	}
}

// TestRequireProof_EndToEnd_RoundTrip is the canary for the full contract.
// SKIPPED until baseproof/baseproof#51: generateProof goes through the SDK v2
// builder, which embeds the canonical (stripped) form, so verifyProofFile
// refuses the require network at first contact. Un-skip when the builder embeds
// the endorsed form and D1 hashes the canonical subset — then this round-trip
// is the proof the whole arc works end to end.
func TestRequireProof_EndToEnd_RoundTrip(t *testing.T) {
	t.Skip("blocked on baseproof/baseproof#51 — v2 builder embeds canonical (stripped) bytes; a require-network proof is refused at first-contact verification. Un-skip when #51 ships.")

	ctx := context.Background()
	g, _, seq := mustRequireGather(t, 3, 2)

	proof, err := generateProof(ctx, g, seq)
	if err != nil {
		t.Fatalf("generateProof: %v", err)
	}
	path := filepath.Join(t.TempDir(), "require.proof")
	if err := writeProofFile(proof, path); err != nil {
		t.Fatalf("writeProofFile: %v", err)
	}
	if _, _, err := verifyProofFile(ctx, path, ""); err != nil {
		t.Fatalf("require-network proof failed offline verification: %v", err)
	}
}

// mustRequireGather is mustRealGather with a require-endorsement constitution —
// the gather a require network's ledger would hand the v2 builder.
func mustRequireGather(t *testing.T, n, k int) (*realGather, map[cosign.NetworkID]protocol.GenesisTrustRoot, uint64) {
	fx := buildRealFixture(t, n, k, true)
	g := &realGather{
		bdoc: fx.bdoc, k: fx.k, entry: fx.entryBytes, logTime: fx.logTime,
		head: fx.head, inc: *fx.inc, smt: *fx.smtProof,
	}
	return g, fx.trustRoots, fx.seq
}
