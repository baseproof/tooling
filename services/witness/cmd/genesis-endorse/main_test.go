// FILE PATH: cmd/genesis-endorse/main_test.go
//
// The MULTI-HOST genesis ceremony round-trip (PR-5): three witnesses, three
// separate keys, three independent endorsements — assembled into a constitution
// that passes first contact. No single holder of all keys; the clean bootstrap.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

// mkWitness writes a fresh witness key to dir and returns (keyPath, did).
func mkWitness(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	priv, err := witkey.Generate()
	if err != nil {
		t.Fatalf("witkey.Generate: %v", err)
	}
	did, err := witkey.DID(priv)
	if err != nil {
		t.Fatalf("witkey.DID: %v", err)
	}
	path := filepath.Join(dir, name+".pem")
	if err := os.WriteFile(path, witkey.EncodePEM(priv), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path, did
}

// writeUnendorsed builds the UNENDORSED require constitution over the witness
// DIDs and writes it (the coordinator's build phase, minus the key custody).
func writeUnendorsed(t *testing.T, dir string, dids []string, k int) string {
	t.Helper()
	doc := network.BootstrapDocument{
		ProtocolVersion:          "v1",
		ExchangeDID:              "did:web:ceremony.example",
		NetworkName:              "multi-host-ceremony",
		GenesisWitnessSet:        dids,
		GenesisQuorumK:           k,
		GenesisTreeHead:          network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionPolicy:   network.GenesisAdmissionPolicy{GatingRequired: false, CostMode: "uncharged"},
		GenesisSignaturePolicy:   network.SignaturePolicy{AllowedEntrySigSchemes: []uint16{1}, AllowedCosignSchemeTags: []uint8{1}, MinSignaturesPerEntry: 1},
		GenesisEndorsementPolicy: network.GenesisEndorsementRequire,
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal unendorsed: %v", err)
	}
	path := filepath.Join(dir, "unendorsed.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write unendorsed: %v", err)
	}
	return path
}

// TestMultiHostCeremony_RoundTrip: the clean bootstrap end to end — each witness
// endorses its own copy with its own key, the coordinator assembles, and the
// result passes the SAME first-contact gate every consumer runs.
func TestMultiHostCeremony_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	k1, d1 := mkWitness(t, dir, "w1")
	k2, d2 := mkWitness(t, dir, "w2")
	k3, d3 := mkWitness(t, dir, "w3")
	dids := []string{d1, d2, d3}

	unendorsed := writeUnendorsed(t, dir, dids, 2) // N=3, K=2 (2K>N)

	// Phase 2: each witness endorses INDEPENDENTLY with its own key.
	var ends []network.GenesisEndorsement
	for _, kp := range []string{k1, k2, k3} {
		e, _, err := endorse(kp, unendorsed)
		if err != nil {
			t.Fatalf("endorse(%s): %v", kp, err)
		}
		ends = append(ends, e)
	}

	// Phase 3: the coordinator assembles. It holds only the collected
	// endorsements — never the keys.
	raw, _ := os.ReadFile(unendorsed)
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode unendorsed: %v", err)
	}
	doc.GenesisEndorsements = ends
	served, err := network.EndorsedBootstrapBytes(doc)
	if err != nil {
		t.Fatalf("assemble (EndorsedBootstrapBytes): %v", err)
	}

	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs: %v", err)
	}
	if _, err := network.LoadVerifiedBootstrap(served, [32]byte(ids.NetworkID)); err != nil {
		t.Fatalf("assembled constitution failed first contact: %v", err)
	}
}

// TestEndorse_RefusesNetworkItIsNotIn: a witness not named in the genesis set
// refuses to endorse — the membership guard that makes the ceremony trustworthy.
func TestEndorse_RefusesNetworkItIsNotIn(t *testing.T) {
	dir := t.TempDir()
	_, d1 := mkWitness(t, dir, "member1")
	_, d2 := mkWitness(t, dir, "member2")
	outsiderKey, _ := mkWitness(t, dir, "outsider")

	unendorsed := writeUnendorsed(t, dir, []string{d1, d2}, 2)

	if _, _, err := endorse(outsiderKey, unendorsed); err == nil {
		t.Fatal("an outsider witness endorsed a network it is not part of")
	} else if !strings.Contains(err.Error(), "not in the constitution's genesis_witness_set") {
		t.Fatalf("refusal came from the wrong place: %v", err)
	}
}

// TestMultiHostCeremony_IncompleteRefused: N-of-N — a constitution missing one
// witness's endorsement does NOT pass first contact (the ceremony is complete or
// it is nothing).
func TestMultiHostCeremony_IncompleteRefused(t *testing.T) {
	dir := t.TempDir()
	k1, d1 := mkWitness(t, dir, "w1")
	k2, d2 := mkWitness(t, dir, "w2")
	_, d3 := mkWitness(t, dir, "w3")
	unendorsed := writeUnendorsed(t, dir, []string{d1, d2, d3}, 2)

	// Only two of three witnesses endorse.
	e1, _, err := endorse(k1, unendorsed)
	if err != nil {
		t.Fatalf("endorse w1: %v", err)
	}
	e2, _, err := endorse(k2, unendorsed)
	if err != nil {
		t.Fatalf("endorse w2: %v", err)
	}

	raw, _ := os.ReadFile(unendorsed)
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	doc.GenesisEndorsements = []network.GenesisEndorsement{e1, e2} // missing w3
	ids, _ := doc.IDs()
	served, err := network.EndorsedBootstrapBytes(doc)
	if err == nil {
		if _, lvErr := network.LoadVerifiedBootstrap(served, [32]byte(ids.NetworkID)); lvErr == nil {
			t.Fatal("a constitution missing a witness's endorsement passed first contact (N-of-N broken)")
		}
	}
}
