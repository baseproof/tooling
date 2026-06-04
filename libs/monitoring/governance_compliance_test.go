package monitoring

import (
	"github.com/baseproof/baseproof/core/envelope"
	sdkmon "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

// Shared fixtures for the three governance-compliance monitor tests.

const govTestLogDID = "did:web:ledger.example"

func gpos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: govTestLogDID, Sequence: seq}
}

// mkEntry builds an admitted business entry at seq, signed by `signer` under
// wire version `ver`, carrying one signature per algorithm in `algos`.
func mkEntry(seq uint64, signer string, ver uint16, algos ...uint16) crosslog.EntryAtPosition {
	sigs := make([]envelope.Signature, len(algos))
	for i, a := range algos {
		sigs[i] = envelope.Signature{SignerDID: signer, AlgoID: a}
	}
	return crosslog.EntryAtPosition{
		Position: gpos(seq),
		Entry: &envelope.Entry{
			Header:     envelope.ControlHeader{SignerDID: signer, ProtocolVersion: ver},
			Signatures: sigs,
		},
	}
}

func countSeverity(alerts []sdkmon.Alert, sev sdkmon.Severity) int {
	n := 0
	for _, a := range alerts {
		if a.Severity == sev {
			n++
		}
	}
	return n
}
