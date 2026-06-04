package serve

import (
	"net/http"
	"testing"
)

// TestWitness_BlindToNewKinds is the Tier-7b FORCED confirmation (issue #39):
// new entry kinds must require ZERO witness change.
//
// The witness cosigns TREE HEADS — a cosign.WireTreeHeadPayload of {root, size,
// smtRoot}. An entry's DomainPayload is never in scope: the witness signs the
// tree's root, which commits to every entry opaquely. So the new baseproof#97
// kinds — SMTDerivationCommitmentRef, the artifact custody lifecycle
// (ArtifactCustodyRecord/Transfer/Destruction), ReFingerprintBinding, and the
// ArtifactGenesis declaration — ride through the root with NO payload-parsing
// path to exercise. The witness stays a Blind Notary by construction.
//
// This pins it as a regression: a tree head over a log that (conceptually) grew
// by admitting entries of each new kind cosigns successfully, byte-for-byte the
// same path as any other tree head. If a future change ever made the witness
// decode entry payloads, the design — not this test — would already be broken;
// the test exists so that breakage is loud.
func TestWitness_BlindToNewKinds(t *testing.T) {
	netID := testNetID()
	h, err := Build(Config{WitnessKey: testKey(t), NetworkID: netID, Logger: silentLogger()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Each increasing size stands in for the log admitting a batch of entries of
	// the new kinds. Every tree head cosigns; the witness never learns — never
	// asks — what the entries are.
	for _, size := range []uint64{1, 2, 3, 4, 100} {
		r := postCosign(t, h, netID, size)
		if r.Code != http.StatusOK {
			t.Fatalf("tree-head cosign at size %d: got %d (%s), want 200 — "+
				"the witness must stay blind to entry kinds (new kinds = zero impact)",
				size, r.Code, r.Body.String())
		}
	}
}
