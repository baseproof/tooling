package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
)

// Group A (tier T1) — the constitutional-quorum contract at the ledger's front
// door. genesis_quorum_k is REQUIRED and bound into the NetworkID since rc4, so
// a bootstrap that omits it or dilutes the set (2K<=N) must be refused at config
// load — before Postgres is touched — and the off-log LEDGER_WITNESS_QUORUM_K
// knob is demoted to a cross-check. These exercise the same validation the
// ledger runs in the witnessActive block of config.go (doc.IDs() +
// reconcileWitnessQuorumK), kept PG-free so they run in the default gate.

// bootstrapWithQuorum mints a structurally-valid genesis bootstrap with N
// placeholder witness DIDs and the given GenesisQuorumK. Everything except K is
// held constant so doc.IDs() fails only on the quorum. doc.IDs() validates
// structure, not key resolvability, so placeholder DIDs suffice (mirrors
// api.validBootstrap).
func bootstrapWithQuorum(n, k int) network.BootstrapDocument {
	dids := make([]string, n)
	for i := range dids {
		dids[i] = fmt.Sprintf("did:key:zwitness%d", i+1)
	}
	return network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:test.example",
		NetworkName:       "clarity-quorum-test",
		GenesisWitnessSet: dids,
		GenesisQuorumK:    k,
		GenesisTreeHead:   network.GenesisTreeHead{RootHash: strings.Repeat("00", 32)},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: false, CostMode: "uncharged",
		},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{1},
			AllowedCosignSchemeTags: []uint8{1},
			MinSignaturesPerEntry:   1,
		},
	}
}

// TestBoot_RejectsBootstrapMissingQuorumK [A1]: an rc2-era bootstrap with no
// genesis_quorum_k (zero value) is refused at config load with an error that
// NAMES the field — not a late nil/panic in wireWitnessQuorum. The ledger calls
// doc.IDs() in the witnessActive block before any quorum is wired, so the
// field-level message is what an operator sees.
func TestBoot_RejectsBootstrapMissingQuorumK(t *testing.T) {
	_, err := bootstrapWithQuorum(3, 0).IDs() // K omitted
	if err == nil {
		t.Fatal("a bootstrap missing genesis_quorum_k must be rejected at load")
	}
	if !strings.Contains(err.Error(), "QuorumK") && !strings.Contains(err.Error(), "quorum_k") {
		t.Fatalf("error must name the GenesisQuorumK field (operator UX); got: %v", err)
	}
}

// TestBoot_RejectsQuorumRatioViolation [A2]: a constitution whose K dilutes the
// set (2K<=N) is refused at the ledger's front door; a conformant ratio boots.
// The quorum-intersection invariant surfaces at config load, before PG connect.
func TestBoot_RejectsQuorumRatioViolation(t *testing.T) {
	for _, c := range []struct {
		k, n int
		ok   bool
	}{
		{1, 1, true},  // 2>1
		{1, 2, false}, // 2<=2 — two disjoint 1-quorums
		{2, 3, true},  // 4>3
		{2, 4, false}, // 4<=4 — dilution
		{3, 5, true},  // 6>5
		{3, 6, false}, // 6<=6 — dilution
	} {
		_, err := bootstrapWithQuorum(c.n, c.k).IDs()
		if c.ok && err != nil {
			t.Errorf("K=%d N=%d (2K>N) must boot: %v", c.k, c.n, err)
		}
		if !c.ok && err == nil {
			t.Errorf("K=%d N=%d (2K<=N) must be refused (quorum-intersection)", c.k, c.n)
		}
	}
}

// TestBoot_QuorumEnvDemotion [A5]: the three arms of the LEDGER_WITNESS_QUORUM_K
// demotion rule. The constitution is the single source of truth; the env is a
// cross-check only — unset adopts it, an equal value is honoured, a different
// value is fatal (an off-log knob can't override the NetworkID-bound quorum).
func TestBoot_QuorumEnvDemotion(t *testing.T) {
	doc := bootstrapWithQuorum(3, 2) // constitutional K=2

	// Arm 1: unset → adopt the constitutional value.
	t.Setenv("LEDGER_WITNESS_QUORUM_K", "")
	if k, err := reconcileWitnessQuorumK(doc, "bootstrap.json"); err != nil || k != 2 {
		t.Fatalf("unset arm: got K=%d err=%v, want K=2 (constitutional)", k, err)
	}

	// Arm 2: set and equal → honoured.
	t.Setenv("LEDGER_WITNESS_QUORUM_K", "2")
	if k, err := reconcileWitnessQuorumK(doc, "bootstrap.json"); err != nil || k != 2 {
		t.Fatalf("set==doc arm: got K=%d err=%v, want K=2", k, err)
	}

	// Arm 3: set and different → fatal.
	t.Setenv("LEDGER_WITNESS_QUORUM_K", "3")
	if _, err := reconcileWitnessQuorumK(doc, "bootstrap.json"); err == nil {
		t.Fatal("set!=doc arm: an env K disagreeing with the constitution must be fatal")
	}

	// A non-integer env value is a hard error, never a silent fallback.
	t.Setenv("LEDGER_WITNESS_QUORUM_K", "two")
	if _, err := reconcileWitnessQuorumK(doc, "bootstrap.json"); err == nil {
		t.Fatal("non-integer LEDGER_WITNESS_QUORUM_K must error, not fall back")
	}
}
