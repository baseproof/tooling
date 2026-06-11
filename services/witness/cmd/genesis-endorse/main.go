/*
FILE PATH: cmd/genesis-endorse/main.go

The per-witness half of the MULTI-HOST genesis ceremony (PR-5).

A clean network bootstrap does NOT let one tool hold every witness key and
self-endorse N-of-N. Each witness generates its OWN key on its OWN host and
endorses the constitution independently; the coordinator (init-network) only
assembles the collected endorsements. This tool is that independent step:

	genesis-endorse -bootstrap unendorsed.json -key witness.pem -out endorsement.json

It loads the witness's secp256k1 key, derives its did:key, REFUSES to endorse a
constitution that does not name it (a witness never endorses a network it does
not belong to), runs the SDK ceremony primitive (network.EndorseGenesis) over
the NetworkID the document derives, and writes the single endorsement as JSON
for out-of-band collection. The witness key never leaves the host; nothing is
served; there is no coupling to a coordinator endpoint.

The input is the UNENDORSED constitution: it is pre-ceremony, so it is decoded
plainly (it cannot yet pass LoadVerifiedBootstrap — that is what this ceremony
produces). EndorseGenesis validates the document (doc.IDs()) before signing, so
a malformed constitution is refused here, before any signature exists.
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

func main() {
	bootstrap := flag.String("bootstrap", "", "path to the UNENDORSED constitution (network-bootstrap doc) to endorse (REQUIRED)")
	key := flag.String("key", os.Getenv("WITNESS_KEY_FILE"), "path to this witness's secp256k1 key PEM (witkey) (REQUIRED; default $WITNESS_KEY_FILE)")
	out := flag.String("out", "", "path to write the endorsement JSON (default: stdout)")
	flag.Parse()

	if *bootstrap == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: genesis-endorse -bootstrap <unendorsed.json> -key <witness.pem> [-out <endorsement.json>]")
		os.Exit(2)
	}

	end, did, err := endorse(*key, *bootstrap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis-endorse: %v\n", err)
		os.Exit(1)
	}
	body, err := json.MarshalIndent(end, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis-endorse: marshal endorsement: %v\n", err)
		os.Exit(1)
	}
	if *out == "" {
		fmt.Println(string(body))
	} else if err := os.WriteFile(*out, body, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "genesis-endorse: write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "genesis-endorse: witness %s endorsed network %s\n", did, networkShort(*bootstrap))
}

// endorse loads the witness key + the unendorsed constitution, REFUSES if the
// witness is not named in the genesis set, and returns its genesis endorsement
// plus the witness's did:key. Factored out of main so the multi-host round-trip
// is testable without a process boundary.
func endorse(keyPath, bootstrapPath string) (network.GenesisEndorsement, string, error) {
	priv, err := witkey.LoadPEM(keyPath)
	if err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("load witness key %s: %w", keyPath, err)
	}
	did, err := witkey.DID(priv)
	if err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("derive witness did:key: %w", err)
	}

	raw, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("read constitution %s: %w", bootstrapPath, err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("decode constitution %s: %w", bootstrapPath, err)
	}

	// Fail-closed: a witness endorses ONLY a constitution that names it. This is
	// the membership check that makes the ceremony trustworthy — a witness can't
	// be tricked into endorsing a network it is not part of.
	if !namedInSet(did, doc.GenesisWitnessSet) {
		return network.GenesisEndorsement{}, did, fmt.Errorf(
			"this witness (%s) is not in the constitution's genesis_witness_set — refusing to endorse", did)
	}

	end, err := network.EndorseGenesis(doc, priv)
	if err != nil {
		return network.GenesisEndorsement{}, did, fmt.Errorf("endorse genesis: %w", err)
	}
	if end.SignerDID != did {
		return network.GenesisEndorsement{}, did, fmt.Errorf(
			"endorsement signer %s != this witness %s (SDK invariant broken)", end.SignerDID, did)
	}
	return end, did, nil
}

func namedInSet(did string, set []string) bool {
	for _, d := range set {
		if d == did {
			return true
		}
	}
	return false
}

// networkShort renders a short NetworkID for the operator log, best-effort.
func networkShort(bootstrapPath string) string {
	raw, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return "?"
	}
	var doc network.BootstrapDocument
	if json.Unmarshal(raw, &doc) != nil {
		return "?"
	}
	ids, err := doc.IDs()
	if err != nil {
		return "?"
	}
	return fmt.Sprintf("%x…", ids.NetworkID[:6])
}
