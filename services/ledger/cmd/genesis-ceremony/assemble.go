/*
FILE PATH: cmd/genesis-ceremony/assemble.go

Production phase 3 — collect and seal.

Each witness produced its endorsement INDEPENDENTLY (genesis-endorse, on its
own host, with its own key); this mode attaches the collected endorsement files
to the unendorsed constitution and emits the SERVED form — after the same
first-contact round-trip every consumer runs (emitVerified →
network.LoadVerifiedBootstrap). The SDK's ceremony verification is N-of-N, so a
missing or invalid endorsement means NOTHING is emitted: a partial ceremony is
not a network.

The coordinator holds no keys here either: endorsements are signatures it can
verify but never produce.
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/baseproof/baseproof/network"
)

func runAssemble(args []string) {
	fs := flag.NewFlagSet("genesis-ceremony assemble", flag.ExitOnError)
	unendorsed := fs.String("unendorsed", "",
		"path to the UNENDORSED constitution emitted by `genesis-ceremony build` (REQUIRED)")
	endorsements := fs.String("endorsements", "",
		"comma-separated paths to the witnesses' endorsement JSON files "+
			"(genesis-endorse output) — one per genesis witness (REQUIRED when "+
			"the constitution's policy is require)")
	auditorEndorsements := fs.String("auditor-endorsements", "",
		"comma-separated paths to the genesis auditors' endorsement JSON files — "+
			"one per declared genesis auditor (REQUIRED when the constitution's "+
			"auditor policy is require)")
	out := fs.String("out", "bootstrap.json",
		"path to write the verified SERVED constitution")
	_ = fs.Parse(args)

	if *unendorsed == "" {
		log.Fatalf("genesis-ceremony assemble: -unendorsed is required")
	}

	raw, err := os.ReadFile(*unendorsed)
	if err != nil {
		log.Fatalf("genesis-ceremony assemble: read %s: %v", *unendorsed, err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		log.Fatalf("genesis-ceremony assemble: parse %s: %v", *unendorsed, err)
	}
	if _, err := doc.IDs(); err != nil {
		log.Fatalf("genesis-ceremony assemble: %s does not validate: %v", *unendorsed, err)
	}

	// Attach the ceremonies. Any endorsements already present in the input are
	// REPLACED, never merged — re-running assemble over a fresh collection is
	// idempotent, and a stale half-ceremony cannot survive by accident.
	doc.GenesisEndorsements, err = loadEndorsements(*endorsements)
	if err != nil {
		log.Fatalf("genesis-ceremony assemble: witness endorsements: %v", err)
	}
	doc.GenesisAuditorEndorsements, err = loadEndorsements(*auditorEndorsements)
	if err != nil {
		log.Fatalf("genesis-ceremony assemble: auditor endorsements: %v", err)
	}

	// emitVerified runs the full fail-closed seal: the SDK refuses to emit a
	// require constitution whose ceremony does not verify N-of-N, and the
	// emitted bytes must pass the first-contact gate before they are written.
	body, err := emitVerified(doc)
	if err != nil {
		log.Fatalf("genesis-ceremony assemble: %v (collect every witness's endorsement — the ceremony is N-of-N)", err)
	}
	if err := os.MkdirAll(dirOf(*out), 0o755); err != nil {
		log.Fatalf("genesis-ceremony assemble: mkdir: %v", err)
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		log.Fatalf("genesis-ceremony assemble: write %s: %v", *out, err)
	}

	ids, _ := doc.IDs()
	fmt.Printf("genesis-ceremony assemble: constitution = %s\n", *out)
	fmt.Printf("genesis-ceremony assemble: network_id   = %x\n", ids.NetworkID)
	fmt.Printf("genesis-ceremony assemble: endorsements = %d witness, %d auditor\n",
		len(doc.GenesisEndorsements), len(doc.GenesisAuditorEndorsements))
}

// loadEndorsements reads a comma-separated list of endorsement JSON files (the
// genesis-endorse output shape — one network.GenesisEndorsement per file).
// Empty input ⇒ nil (a no-ceremony constitution attaches nothing).
func loadEndorsements(csv string) ([]network.GenesisEndorsement, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	var ends []network.GenesisEndorsement
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		var e network.GenesisEndorsement
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		if e.SignerDID == "" || e.Signature == "" {
			return nil, fmt.Errorf("%s: not an endorsement (missing signer_did/signature)", p)
		}
		ends = append(ends, e)
	}
	return ends, nil
}
