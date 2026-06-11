/*
FILE PATH: cmd/genesis-endorse/main.go

The per-witness half of the MULTI-HOST genesis ceremony (PR-5).

A clean network bootstrap does NOT let one tool hold every witness key and
self-endorse N-of-N. Each witness generates its OWN key on its OWN host and
endorses the constitution independently; the coordinator (genesis-ceremony) only
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
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

func main() {
	bootstrap := flag.String("bootstrap", "", "path to the UNENDORSED constitution (network-bootstrap doc) to endorse (REQUIRED)")
	key := flag.String("key", os.Getenv("WITNESS_KEY_FILE"), "path to this endorser's secp256k1 key PEM (witkey) (REQUIRED; default $WITNESS_KEY_FILE)")
	kind := flag.String("kind", kindGenesisWitness,
		`what is being endorsed: "genesis-witness" (default — this host is a genesis `+
			`witness endorsing the constitution) or "genesis-auditor" (this host is a `+
			"declared genesis auditor; requires -auditor-did). The payload kind is part "+
			"of what is SIGNED, so an unknown kind refuses rather than guessing — new "+
			"consent kinds (e.g. rotation consent) are added here explicitly, never "+
			"smuggled through an old one.")
	auditorDID := flag.String("auditor-did", "",
		"the endorsing auditor's registered DID (genesis-auditor kind only — an "+
			"auditor DID is not derivable from its key, so it must be stated and is "+
			"checked against the constitution's genesis_auditors declaration)")
	out := flag.String("out", "", "path to write the endorsement JSON (default: stdout)")
	flag.Parse()

	if *bootstrap == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: genesis-endorse -bootstrap <unendorsed.json> -key <key.pem> [-kind genesis-witness|genesis-auditor] [-auditor-did did:…] [-out <endorsement.json>]")
		os.Exit(2)
	}

	end, did, err := endorse(*key, *bootstrap, *kind, *auditorDID)
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
	fmt.Fprintf(os.Stderr, "genesis-endorse: %s %s endorsed network %s\n", *kind, did, networkShort(*bootstrap))
}

// The endorsement kinds this one-shot can produce. The kind selects WHICH
// ceremony payload is signed (witness vs auditor endorsement are distinct
// signing purposes in the SDK); an unknown kind refuses loudly so a future
// consent kind (e.g. rotation consent) is an explicit addition here, never a
// silent fall-through into the wrong payload.
const (
	kindGenesisWitness = "genesis-witness"
	kindGenesisAuditor = "genesis-auditor"
)

// endorse loads the endorser's key + the unendorsed constitution, dispatches on
// kind, REFUSES if this identity is not declared for that role, and returns the
// endorsement plus the endorser's identity. Factored out of main so the
// multi-host round-trip is testable without a process boundary.
func endorse(keyPath, bootstrapPath, kind, auditorDID string) (network.GenesisEndorsement, string, error) {
	priv, err := witkey.LoadPEM(keyPath)
	if err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("load key %s: %w", keyPath, err)
	}

	raw, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("read constitution %s: %w", bootstrapPath, err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("decode constitution %s: %w", bootstrapPath, err)
	}

	switch kind {
	case kindGenesisWitness:
		return endorseAsWitness(doc, priv)
	case kindGenesisAuditor:
		return endorseAsAuditor(doc, priv, auditorDID)
	default:
		return network.GenesisEndorsement{}, "", fmt.Errorf(
			"unknown endorsement kind %q (known: %q, %q) — refusing to sign a payload this tool does not understand",
			kind, kindGenesisWitness, kindGenesisAuditor)
	}
}

// endorseAsWitness is the genesis-witness ceremony leg.
func endorseAsWitness(doc network.BootstrapDocument, priv *ecdsa.PrivateKey) (network.GenesisEndorsement, string, error) {
	did, err := witkey.DID(priv)
	if err != nil {
		return network.GenesisEndorsement{}, "", fmt.Errorf("derive witness did:key: %w", err)
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

// endorseAsAuditor is the genesis-auditor ceremony leg. An auditor's DID is not
// derivable from its key, so it is stated (-auditor-did) and verified against
// the constitution's declaration — INCLUDING that the declared public key is
// the public half of the key this host actually holds. An auditor can't be
// tricked into endorsing under someone else's declaration, and a coordinator
// can't smuggle a wrong key into the declaration unnoticed.
func endorseAsAuditor(doc network.BootstrapDocument, priv *ecdsa.PrivateKey, auditorDID string) (network.GenesisEndorsement, string, error) {
	if auditorDID == "" {
		return network.GenesisEndorsement{}, "", fmt.Errorf("-auditor-did is required for kind %q", kindGenesisAuditor)
	}
	compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		return network.GenesisEndorsement{}, auditorDID, fmt.Errorf("compress auditor pubkey: %w", err)
	}
	declared := false
	for _, a := range doc.GenesisAuditors {
		if a.AuditorDID != auditorDID {
			continue
		}
		declared = true
		if !strings.EqualFold(a.PublicKey, hex.EncodeToString(compressed)) {
			return network.GenesisEndorsement{}, auditorDID, fmt.Errorf(
				"the constitution declares auditor %s with a DIFFERENT public key — refusing to endorse under a declaration this key does not match", auditorDID)
		}
	}
	if !declared {
		return network.GenesisEndorsement{}, auditorDID, fmt.Errorf(
			"auditor %s is not in the constitution's genesis_auditors — refusing to endorse", auditorDID)
	}
	end, err := network.EndorseGenesisAuditor(doc, auditorDID, priv)
	if err != nil {
		return network.GenesisEndorsement{}, auditorDID, fmt.Errorf("endorse genesis (auditor): %w", err)
	}
	return end, auditorDID, nil
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
