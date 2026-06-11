/*
FILE PATH: cmd/genesis-ceremony/ceremony_test.go

The MULTI-HOST ceremony at coordinator altitude — the contract that supersedes
init-network. Three custody models, pinned:

  - build emits an UNENDORSED require constitution whose NetworkID is final
    (the ceremony signs the identity, so the identity must precede it);
  - each witness endorses independently (here: network.EndorseGenesis with
    keys the coordinator never sees — the same primitive genesis-endorse runs);
  - assemble attaches the collected endorsements and seals through the
    first-contact gate; a MISSING endorsement means NOTHING is emitted
    (N-of-N — a partial ceremony is not a network);
  - the genesis-auditor declaration (D5): auditors + a require auditor policy
    are canonical-bytes material, their ceremony (EndorseGenesisAuditor) is
    demanded at seal, and a constitution missing one auditor endorsement
    refuses to emit.

The dev (single-host) mode's contracts are pinned in main_test.go, ported from
init-network unchanged.
*/
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"
)

// mintWitnessIdentity simulates one witness host: a fresh secp256k1 key the
// coordinator never sees, plus its did:key.
func mintWitnessIdentity(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("witness keygen: %v", err)
	}
	did, err := secp256k1DIDKey(priv)
	if err != nil {
		t.Fatalf("witness DID: %v", err)
	}
	return priv, did
}

// coordinatorDoc builds the unendorsed constitution exactly as `build` does —
// external DIDs in, no key custody.
func coordinatorDoc(t *testing.T, dids []string, k int, auditors []network.GenesisAuditor, auditorPolicy string) network.BootstrapDocument {
	t.Helper()
	doc := buildBootstrapDoc("did:web:ceremony.example", "multi-host-net", "require", "require",
		dids, k, "0x0123456789abcdef0123456789abcdef01234567", 1, auditors, auditorPolicy)
	if _, err := doc.IDs(); err != nil {
		t.Fatalf("unendorsed constitution must validate: %v", err)
	}
	return doc
}

func TestCeremony_MultiHost_RoundTrip(t *testing.T) {
	// Three witness hosts mint their own identities.
	k1, d1 := mintWitnessIdentity(t)
	k2, d2 := mintWitnessIdentity(t)
	k3, d3 := mintWitnessIdentity(t)
	doc := coordinatorDoc(t, []string{d1, d2, d3}, 2, nil, "")

	// Phase 2: each witness endorses INDEPENDENTLY (the genesis-endorse
	// primitive); the coordinator collects signatures, never keys.
	for _, wk := range []*ecdsa.PrivateKey{k1, k2, k3} {
		e, err := network.EndorseGenesis(doc, wk)
		if err != nil {
			t.Fatalf("EndorseGenesis: %v", err)
		}
		doc.GenesisEndorsements = append(doc.GenesisEndorsements, e)
	}

	// Phase 3: seal through the first-contact gate.
	body, err := emitVerified(doc)
	if err != nil {
		t.Fatalf("a complete N-of-N ceremony must seal: %v", err)
	}
	// The emitted bytes are what every consumer first-contacts.
	if _, err := network.LoadSelfVerifiedBootstrap(body); err != nil {
		t.Fatalf("sealed constitution failed the self-pin door: %v", err)
	}
}

func TestCeremony_PartialCeremony_RefusesToEmit(t *testing.T) {
	k1, d1 := mintWitnessIdentity(t)
	_, d2 := mintWitnessIdentity(t)
	k3, d3 := mintWitnessIdentity(t)
	doc := coordinatorDoc(t, []string{d1, d2, d3}, 2, nil, "")

	// Only two of three witnesses endorse — w2 never signs.
	for _, wk := range []*ecdsa.PrivateKey{k1, k3} {
		e, err := network.EndorseGenesis(doc, wk)
		if err != nil {
			t.Fatalf("EndorseGenesis: %v", err)
		}
		doc.GenesisEndorsements = append(doc.GenesisEndorsements, e)
	}

	if _, err := emitVerified(doc); err == nil {
		t.Fatal("a constitution missing a witness's endorsement was emitted — N-of-N broken")
	}
}

// TestCeremony_GenesisAuditors_RequirePolicy pins D5: the constitution can
// declare founding auditors with a require endorsement policy; their ceremony
// is demanded at seal exactly like the witnesses'.
func TestCeremony_GenesisAuditors_RequirePolicy(t *testing.T) {
	wk, wd := mintWitnessIdentity(t)

	// The auditor identity: its registered key, DID, findings URL, and scope.
	aPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("auditor keygen: %v", err)
	}
	aPub, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&aPriv.PublicKey))
	if err != nil {
		t.Fatalf("compress auditor key: %v", err)
	}
	auditorDID := "did:web:auditor.example"
	auditors := []network.GenesisAuditor{{
		AuditorDID:  auditorDID,
		PublicKey:   hex.EncodeToString(aPub),
		SchemeTag:   1, // ECDSA
		FindingsURL: "https://auditor.example/findings",
		Scope:       1,
	}}

	doc := coordinatorDoc(t, []string{wd}, 1, auditors, "require")

	// Witness ceremony alone is NOT enough: the auditor policy is require.
	we, err := network.EndorseGenesis(doc, wk)
	if err != nil {
		t.Fatalf("witness EndorseGenesis: %v", err)
	}
	doc.GenesisEndorsements = []network.GenesisEndorsement{we}
	if _, err := emitVerified(doc); err == nil {
		t.Fatal("a require-auditor constitution sealed WITHOUT the auditor ceremony")
	}

	// With the auditor's endorsement, it seals.
	ae, err := network.EndorseGenesisAuditor(doc, auditorDID, aPriv)
	if err != nil {
		t.Fatalf("EndorseGenesisAuditor: %v", err)
	}
	doc.GenesisAuditorEndorsements = []network.GenesisEndorsement{ae}
	body, err := emitVerified(doc)
	if err != nil {
		t.Fatalf("complete witness+auditor ceremony must seal: %v", err)
	}
	verified, err := network.LoadSelfVerifiedBootstrap(body)
	if err != nil {
		t.Fatalf("sealed constitution failed the self-pin door: %v", err)
	}
	if len(verified.GenesisAuditors) != 1 || verified.GenesisAuditors[0].AuditorDID != auditorDID {
		t.Fatal("the verified constitution lost its genesis-auditor declaration")
	}
}

// TestCeremony_NetworkIDStableAcrossCeremony pins the ordering invariant the
// whole flow rests on: endorsements live OUTSIDE the canonical bytes, so the
// NetworkID derived at build time is byte-identical to the one consumers derive
// from the sealed constitution.
func TestCeremony_NetworkIDStableAcrossCeremony(t *testing.T) {
	wk, wd := mintWitnessIdentity(t)
	doc := coordinatorDoc(t, []string{wd}, 1, nil, "")

	before, err := doc.IDs()
	if err != nil {
		t.Fatalf("IDs before ceremony: %v", err)
	}
	e, err := network.EndorseGenesis(doc, wk)
	if err != nil {
		t.Fatalf("EndorseGenesis: %v", err)
	}
	doc.GenesisEndorsements = []network.GenesisEndorsement{e}
	body, err := emitVerified(doc)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sealed, err := network.LoadSelfVerifiedBootstrap(body)
	if err != nil {
		t.Fatalf("self-pin door: %v", err)
	}
	after, err := sealed.IDs()
	if err != nil {
		t.Fatalf("IDs after ceremony: %v", err)
	}
	if before.NetworkID != after.NetworkID {
		t.Fatalf("NetworkID drifted across the ceremony: %x → %x (endorsements leaked into the canonical bytes)",
			before.NetworkID, after.NetworkID)
	}
}
