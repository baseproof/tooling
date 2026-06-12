/*
FILE PATH: cmd/genesis-ceremony/ceremony_file_test.go

The multi-host ceremony at BINARY altitude — the same flow ceremony_test.go
pins at function altitude, but driven through the real flag parsers and real
files, exactly as operators run it:

	build (flags → unendorsed.json)
	  → 3× endorsement FILES (the genesis-endorse output shape, one
	    network.GenesisEndorsement JSON per file, minted with keys the
	    coordinator never sees)
	  → assemble (files → bootstrap.json, sealed through the first-contact gate)
	  → the emitted FILE passes network.LoadSelfVerifiedBootstrap — the same
	    self-pin door a consumer's `baseproof network add` first-contacts.

This is the layer where flag-parsing/sorting/IO regressions live and the
function-altitude tests cannot see: the Tier-1 targets flags round-trip
through the REAL CLI surface here (deliberately passed in REVERSED order — the
tool, not the operator, owns canonical element order).

The partial-ceremony negative stays at function altitude
(TestCeremony_PartialCeremony_RefusesToEmit): runAssemble exits the process on
a broken ceremony (log.Fatalf), which is the right behavior for the binary and
untestable in-process.
*/
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
)

func TestCeremony_MultiHost_FileAltitude(t *testing.T) {
	dir := t.TempDir()
	unendorsedPath := filepath.Join(dir, "unendorsed.json")
	sealedPath := filepath.Join(dir, "bootstrap.json")

	// Three witness hosts mint their own identities; the coordinator gets DIDs.
	keys := make([]*ecdsa.PrivateKey, 3)
	dids := make([]string, 3)
	for i := range keys {
		keys[i], dids[i] = mintWitnessIdentity(t)
	}
	t1 := strings.Repeat("1", 64)
	t2 := strings.Repeat("2", 64)

	// Phase 1 — build, through the real flag parser. Targets deliberately
	// REVERSED: canonical order is the tool's job, not the operator's.
	runBuild([]string{
		"-network-name", "file-altitude-net",
		"-log-did", "did:web:ceremony.example",
		"-witness-dids", strings.Join(dids, ","),
		"-quorum", "2",
		"-admission-authority", "0x0123456789abcdef0123456789abcdef01234567",
		"-anchoring-max-interval", "24h",
		"-anchoring-targets", t2 + "," + t1,
		"-anchoring-min-distinct", "1",
		"-out", unendorsedPath,
	})

	rawUnendorsed, err := os.ReadFile(unendorsedPath)
	if err != nil {
		t.Fatalf("build wrote no unendorsed constitution: %v", err)
	}
	var unendorsed network.BootstrapDocument
	if err := json.Unmarshal(rawUnendorsed, &unendorsed); err != nil {
		t.Fatalf("unendorsed.json does not parse: %v", err)
	}
	idsBuild, err := unendorsed.IDs()
	if err != nil {
		t.Fatalf("unendorsed constitution does not validate: %v", err)
	}
	a := unendorsed.GenesisAnchoring
	if a == nil || a.MaxIntervalSeconds != 86400 || a.MinDistinctTargets != 1 {
		t.Fatalf("anchoring flags did not survive the binary surface: %+v", a)
	}
	gotTargets := []string{a.Targets[0].NetworkID, a.Targets[1].NetworkID}
	if !sort.StringsAreSorted(gotTargets) {
		t.Fatalf("emitted targets not canonically sorted: %v (reversed flag order leaked into the constitution)", gotTargets)
	}

	// Phase 2 — each witness endorses on its own host and ships a FILE in the
	// genesis-endorse output shape (one GenesisEndorsement JSON per file).
	endorsementPaths := make([]string, len(keys))
	for i, k := range keys {
		e, err := network.EndorseGenesis(unendorsed, k)
		if err != nil {
			t.Fatalf("witness #%d EndorseGenesis: %v", i, err)
		}
		body, err := json.MarshalIndent(e, "", "  ")
		if err != nil {
			t.Fatalf("marshal endorsement #%d: %v", i, err)
		}
		endorsementPaths[i] = filepath.Join(dir, fmt.Sprintf("endorsement-%d.json", i))
		if err := os.WriteFile(endorsementPaths[i], body, 0o644); err != nil {
			t.Fatalf("write endorsement #%d: %v", i, err)
		}
	}

	// Phase 3 — assemble from files; seal through the first-contact gate.
	runAssemble([]string{
		"-unendorsed", unendorsedPath,
		"-endorsements", strings.Join(endorsementPaths, ","),
		"-out", sealedPath,
	})

	sealedBytes, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("assemble wrote no sealed constitution: %v", err)
	}
	// The consumer door: the SAME self-pin gate `baseproof network add` runs at
	// first contact (network.LoadSelfVerifiedBootstrap).
	sealed, err := network.LoadSelfVerifiedBootstrap(sealedBytes)
	if err != nil {
		t.Fatalf("sealed file failed the consumer first-contact door: %v", err)
	}
	idsSealed, err := sealed.IDs()
	if err != nil {
		t.Fatalf("sealed IDs: %v", err)
	}
	if idsSealed.NetworkID != idsBuild.NetworkID {
		t.Fatalf("NetworkID drifted across the file ceremony: build %x → sealed %x",
			idsBuild.NetworkID, idsSealed.NetworkID)
	}
	if len(sealed.GenesisEndorsements) != 3 {
		t.Fatalf("sealed constitution carries %d endorsements, want 3", len(sealed.GenesisEndorsements))
	}
	sa := sealed.GenesisAnchoring
	if sa == nil || len(sa.Targets) != 2 || sa.Targets[0].NetworkID != t1 || sa.Targets[1].NetworkID != t2 {
		t.Fatalf("the corroborator set did not survive the ceremony: %+v", sa)
	}
}
