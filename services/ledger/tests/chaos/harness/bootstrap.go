/*
FILE PATH: tests/chaos/harness/bootstrap.go

Bootstrap document generation for chaos tests. The ledger
binary requires:

	LEDGER_NETWORK_BOOTSTRAP_FILE — JSON file path containing the
	  network.BootstrapDocument (defines NetworkID + witness DIDs).

This file builds the bootstrap, writes it to disk, and returns
metadata the rest of the harness needs (NetworkID for witness
validation, file path to point the env var at).

# LEDGER SIGNER KEY — INTENTIONALLY EPHEMERAL

We do NOT write a LEDGER_SIGNER_KEY_FILE. The ledger generates
an ephemeral secp256k1 key in-process when the env var is empty
(cmd/ledger/signers.go). For chaos tests this is the correct
trade-off:

  - Chaos tests don't assert on the ledger's signer DID. The
    submitter's signing identity (Submitter.signerPriv) is
    constructed in-test and is stable; that's the DID that
    matters for kill-restart correctness.

  - The cost: across a kill-restart cycle, the ledger's own
    DID changes. If a chaos test scenario ever included a
    ledger-published anchor or commitment, the post-restart
    anchor would have a different SignerDID than pre-restart.
    No current chaos test exercises that path within its
    timeout window (anchor publisher runs on a periodic
    interval far longer than test wall-time).

If a future chaos test needs a stable LEDGER_DID across restart,
write a raw 32-byte secp256k1 scalar as hex to a file and point
LEDGER_SIGNER_KEY_FILE at it (the loader reads that dialect — see
cmd/ledger/signers.go; generate one with `genesis-ceremony dev
-out-ledger-key`). secp256k1 is not a stdlib x509 curve, so the
loader takes a hex scalar, not a PEM.
*/
package harness

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"
)

// BootstrapBundle is everything needed to wire up a ledger
// subprocess: path to the JSON file (for env var) and the
// computed NetworkID (which the witness fixture also needs so
// it accepts incoming requests).
type BootstrapBundle struct {
	// BootstrapPath is the absolute path to the bootstrap.json
	// file. Set LEDGER_NETWORK_BOOTSTRAP_FILE to this.
	BootstrapPath string

	// NetworkID is the SHA-256 of the canonical bootstrap doc.
	// The witness fixture must be constructed with this NetworkID
	// in its AllowedNetworks set, otherwise cosign requests will
	// be rejected with a network-mismatch error.
	NetworkID cosign.NetworkID
}

// BuildBootstrap writes a fresh bootstrap.json into dir and
// returns the bundle metadata. n witnessDIDs must be supplied
// (typically Witnesses.DIDs()) so the bootstrap doc's
// genesis_witness_set field matches what the witness fixture
// will sign as. ExchangeDID + NetworkName are caller-controlled
// so different test cases can produce different NetworkIDs.
//
// On any failure, t.Fatalf is called.
func BuildBootstrap(t *testing.T, dir string, exchangeDID, networkName string, witnessDIDs []string, witnessPrivs []*ecdsa.PrivateKey) BootstrapBundle {
	t.Helper()
	if exchangeDID == "" {
		t.Fatal("BuildBootstrap: empty exchangeDID")
	}
	if networkName == "" {
		t.Fatal("BuildBootstrap: empty networkName")
	}
	if len(witnessDIDs) == 0 {
		t.Fatal("BuildBootstrap: empty witnessDIDs")
	}

	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       exchangeDID,
		NetworkName:       networkName,
		GenesisWitnessSet: append([]string(nil), witnessDIDs...),
		// GenesisQuorumK is REQUIRED under rc4 (bound into the NetworkID). The
		// harness is a bootstrap producer, so it mints a constitutional quorum:
		// a simple majority (N/2+1), which always satisfies the
		// quorum-intersection invariant 2K>N that validate() enforces.
		GenesisQuorumK: len(witnessDIDs)/2 + 1,
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: false,
			CostMode:       "uncharged",
		},
		// GenesisSignaturePolicy is REQUIRED (hashed into the NetworkID): emit
		// the zero-trust default — secp256k1-ECDSA entry signatures + ECDSA
		// cosignatures — matching genesis-ceremony so a chaos network admits the
		// same set a real one does.
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
		// Born-endorsed, like a production mint: the require policy is
		// canonical-bytes material (set BEFORE IDs() below), and every
		// witness key the fixture holds self-endorses N-of-N. A chaos
		// network must exercise the same first-contact ceremony gate a
		// real network does.
		GenesisEndorsementPolicy: network.GenesisEndorsementRequire,
	}
	// Validate by computing IDs — surfaces malformed inputs at
	// construction time rather than at subprocess boot.
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("BuildBootstrap: bootstrap.IDs (validation): %v", err)
	}
	if len(witnessPrivs) != len(witnessDIDs) {
		t.Fatalf("BuildBootstrap: %d witness keys for %d DIDs — the ceremony is N-of-N", len(witnessPrivs), len(witnessDIDs))
	}
	for i, priv := range witnessPrivs {
		e, eErr := network.EndorseGenesis(doc, priv)
		if eErr != nil {
			t.Fatalf("BuildBootstrap: witness #%d EndorseGenesis: %v", i, eErr)
		}
		doc.GenesisEndorsements = append(doc.GenesisEndorsements, e)
	}
	// The verified seal: refuses a partial ceremony and emits the SERVED
	// (endorsed) form — the same bytes every consumer first-contacts.
	body, err := network.EndorsedBootstrapBytes(doc)
	if err != nil {
		t.Fatalf("BuildBootstrap: seal endorsed bootstrap: %v", err)
	}
	bootstrapPath := filepath.Join(dir, "bootstrap.json")
	if err := os.WriteFile(bootstrapPath, body, 0o644); err != nil {
		t.Fatalf("BuildBootstrap: write bootstrap.json: %v", err)
	}

	return BootstrapBundle{
		BootstrapPath: bootstrapPath,
		NetworkID:     ids.NetworkID,
	}
}

// _ ensures the fmt import is used when this file is otherwise
// trivially refactored; remove if unused after subsequent edits.
var _ = fmt.Sprintf
