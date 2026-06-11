package quorum

import (
	"fmt"

	"github.com/baseproof/baseproof/network"
)

// ReconcileFlagK demotes a -quorum flag to a cross-check of the constitutional
// doc.GenesisQuorumK. Since rc4, genesis_quorum_k is hashed into the NetworkID —
// the single source of truth for K — so an off-log flag must never silently
// override it. The three arms of the demotion rule (shared by every governance
// tool; the ledger's LEDGER_WITNESS_QUORUM_K twin is reconcileWitnessQuorumK):
//
//	0 (unset)       → adopt the constitutional value (doc.GenesisQuorumK)
//	set, == doc     → honoured (the operator's assertion agrees with the chain)
//	set, != doc     → fatal (the flag disagrees with the identity-bound quorum)
//
// doc.IDs() (called by each tool before this) already enforced 1<=K<=N and the
// quorum-intersection invariant 2K>N, so the returned K is known-valid.
func ReconcileFlagK(doc network.BootstrapDocument, flagK int) (int, error) {
	if flagK != 0 && flagK != doc.GenesisQuorumK {
		return 0, fmt.Errorf(
			"-quorum=%d disagrees with the constitutional genesis_quorum_k=%d in the bootstrap: "+
				"the quorum is bound into the NetworkID, so a flag override cannot change it — "+
				"omit -quorum to adopt the constitutional value",
			flagK, doc.GenesisQuorumK)
	}
	return doc.GenesisQuorumK, nil
}
