package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkcryptosigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	sdkwitness "github.com/baseproof/baseproof/witness"
)

// TestWitnessKeys_Secp256k1_CosignResolvable is the regression for the
// P-256-witness mismatch: init-network must mint secp256k1 witnesses whose DIDs
// the ledger accepts at boot via witness.KeysFromDIDs (secp256k1-only) and whose
// PEM the tooling witness daemon can load (witkey block type). A P-256 DID
// (the old behaviour) is rejected by KeysFromDIDs.
func TestWitnessKeys_Secp256k1_CosignResolvable(t *testing.T) {
	dir := t.TempDir()
	var dids []string
	for i := 1; i <= 3; i++ {
		path := filepath.Join(dir, fmt.Sprintf("witness-%d.pem", i))
		priv, gen, err := loadOrGenerateWitnessKey(path)
		if err != nil {
			t.Fatalf("generate witness %d: %v", i, err)
		}
		if !gen {
			t.Errorf("witness %d: first call should report generated", i)
		}
		did, err := secp256k1DIDKey(priv)
		if err != nil {
			t.Fatalf("derive witness DID: %v", err)
		}
		if !strings.HasPrefix(did, "did:key:z") {
			t.Errorf("witness DID %q is not a did:key", did)
		}
		dids = append(dids, did)
	}

	// THE regression: the ledger resolves the genesis witness set through this
	// exact call at boot (quorum.LoadWitnessKeys → witness.KeysFromDIDs). P-256
	// DIDs fail here; secp256k1 DIDs pass.
	if _, err := sdkwitness.KeysFromDIDs(dids); err != nil {
		t.Fatalf("witness.KeysFromDIDs rejected init-network witness DIDs (P-256 regression?): %v", err)
	}

	// PEM is witkey-compatible (the witness daemon loads this exact block type).
	raw, err := os.ReadFile(filepath.Join(dir, "witness-1.pem"))
	if err != nil {
		t.Fatalf("read witness PEM: %v", err)
	}
	if !strings.Contains(string(raw), witnessPEMType) {
		t.Errorf("witness PEM block type is not %q:\n%s", witnessPEMType, raw)
	}
	// Idempotent reload.
	if _, gen, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witness-1.pem")); err != nil || gen {
		t.Errorf("reload should be idempotent (generated=%v err=%v)", gen, err)
	}
}

// TestLoadOrGenerateLedgerSignerKey_Idempotent: first call generates + writes a
// 32-byte hex scalar and returns a secp256k1 did:key; a second call loads the
// same file and re-derives the identical DID.
func TestLoadOrGenerateLedgerSignerKey_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger-signer.key")

	did1, gen1, err := loadOrGenerateLedgerSignerKey(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !gen1 {
		t.Error("first call must report generated=true")
	}
	if !strings.HasPrefix(did1, "did:key:z") {
		t.Errorf("did %q is not a did:key", did1)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if dec, derr := hex.DecodeString(strings.TrimSpace(string(raw))); derr != nil || len(dec) != 32 {
		t.Fatalf("key file is not a 32-byte hex scalar (len=%d err=%v)", len(dec), derr)
	}

	did2, gen2, err := loadOrGenerateLedgerSignerKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if gen2 {
		t.Error("second call must report generated=false (idempotent)")
	}
	if did2 != did1 {
		t.Errorf("reload did = %q, want %q", did2, did1)
	}
}

// TestLedgerSignerKey_MatchesLedgerLoader proves cross-tool consistency: the hex
// init-network writes is loadable by the LEDGER's exact loader primitive
// (signatures.PrivKeyFromBytes) and derives the SAME did:key the ledger computes
// (PubKeyBytes → CompressSecp256k1Pubkey → EncodeDIDKey/secp256k1). If these
// drift, the ledger would advertise a different originator than init-network
// printed and gossip verification would break.
func TestLedgerSignerKey_MatchesLedgerLoader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger-signer.key")
	genDID, _, err := loadOrGenerateLedgerSignerKey(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	scalar, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}

	// Exactly what cmd/ledger loadOrGenerateLedgerSigner + didKeyFromSecp256k1Priv do.
	priv, err := sdkcryptosigs.PrivKeyFromBytes(scalar)
	if err != nil {
		t.Fatalf("PrivKeyFromBytes (ledger loader primitive): %v", err)
	}
	uncompressed := sdkcryptosigs.PubKeyBytes(&priv.PublicKey)
	compressed, err := sdkcryptosigs.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		t.Fatalf("CompressSecp256k1Pubkey: %v", err)
	}
	ledgerDID := sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)

	if ledgerDID != genDID {
		t.Fatalf("ledger-derived did %q != init-network did %q — generator/loader drift", ledgerDID, genDID)
	}
}

// TestBuildBootstrapDoc_PassesGenesisValidation is the regression for the
// init-network bug shipped in v1.52.0: the doc omitted GenesisSignaturePolicy,
// which the SDK requires since v1.31 (it is hashed into the NetworkID, and
// validate() rejects the empty zero value as an "admit-nothing" policy). The
// tool wrote its keys fine, then exited non-zero on doc.IDs() — so it could not
// bootstrap a network at all (in any gating mode). This builds the same document
// main() builds and asserts it passes the SDK's validation.
func TestBuildBootstrapDoc_PassesGenesisValidation(t *testing.T) {
	dir := t.TempDir()
	priv, _, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witness-1.pem"))
	if err != nil {
		t.Fatalf("witness key: %v", err)
	}
	did, err := secp256k1DIDKey(priv)
	if err != nil {
		t.Fatalf("witness DID: %v", err)
	}
	addr, _, err := loadOrGenerateAdmissionAuthority(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatalf("admission authority: %v", err)
	}

	for _, gating := range []string{"off", "require"} {
		doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", gating, "require", []string{did}, 1, addr, 1)
		// doc.IDs() runs the SDK's validate() — exactly init-network's gate. A
		// missing genesis_signature_policy fails here, which is the regression.
		if _, err := doc.IDs(); err != nil {
			t.Fatalf("gating=%s: bootstrap failed SDK validation "+
				"(regression: genesis_signature_policy must be set): %v", gating, err)
		}
		if len(doc.GenesisSignaturePolicy.AllowedEntrySigSchemes) == 0 ||
			len(doc.GenesisSignaturePolicy.AllowedCosignSchemeTags) == 0 {
			t.Fatalf("gating=%s: genesis_signature_policy not populated", gating)
		}
	}
}

// TestBuildBootstrapDoc_MinSignaturesConfigurable pins the -min-signatures
// surface: a configured floor threads into GenesisSignaturePolicy and survives
// the SDK's NetworkID-deriving validation, while a 0 floor is rejected by
// doc.IDs() (network.validateGenesisSignaturePolicy). The CLI's own [1, 64]
// guard is the first line; this asserts the SDK floor binds even if that guard
// were bypassed — the "always > 0" guarantee is locked into the NetworkID.
func TestBuildBootstrapDoc_MinSignaturesConfigurable(t *testing.T) {
	dir := t.TempDir()
	priv, _, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witnesses", "witness-1.pem"))
	if err != nil {
		t.Fatalf("witness key: %v", err)
	}
	did, err := secp256k1DIDKey(priv)
	if err != nil {
		t.Fatalf("witness DID: %v", err)
	}
	addr, _, err := loadOrGenerateAdmissionAuthority(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatalf("admission authority: %v", err)
	}

	// A configured non-default floor threads through and validates.
	doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "require", []string{did}, 1, addr, 3)
	if got := doc.GenesisSignaturePolicy.MinSignaturesPerEntry; got != 3 {
		t.Fatalf("MinSignaturesPerEntry = %d, want 3 (flag did not thread)", got)
	}
	if _, err := doc.IDs(); err != nil {
		t.Fatalf("min-signatures=3 must pass SDK validation: %v", err)
	}

	// A 0 floor is rejected by the SDK at NetworkID derivation, regardless of
	// the CLI guard — this is the genesis half of the "always > 0" invariant.
	zero := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "require", []string{did}, 1, addr, 0)
	if _, err := zero.IDs(); err == nil {
		t.Fatal("min-signatures=0 must be rejected by doc.IDs() (admit-unsigned floor)")
	}
}

// TestInitNetwork_EmitsConstitutionalK pins the -quorum resolution: the auto
// default (0) is a simple majority that satisfies 2K>N for representative N,
// and the resolved K, fed through buildBootstrapDoc, round-trips doc.IDs().
func TestInitNetwork_EmitsConstitutionalK(t *testing.T) {
	// Auto-majority resolution per N: 2K>N must hold for every row.
	for _, tc := range []struct{ n, wantK int }{
		{1, 1}, {2, 2}, {3, 2}, {4, 3}, {5, 3}, {7, 4},
	} {
		k, err := resolveGenesisQuorumK(0, tc.n)
		if err != nil {
			t.Fatalf("auto K for N=%d: %v", tc.n, err)
		}
		if k != tc.wantK {
			t.Errorf("auto K for N=%d = %d, want %d", tc.n, k, tc.wantK)
		}
		if 2*k <= tc.n {
			t.Errorf("auto K=%d for N=%d violates 2K>N", k, tc.n)
		}
	}

	// For -witnesses 3 the emitted doc carries K=2 and round-trips doc.IDs().
	dir := t.TempDir()
	var dids []string
	for i := 1; i <= 3; i++ {
		priv, _, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witnesses", fmt.Sprintf("witness-%d.pem", i)))
		if err != nil {
			t.Fatalf("witness %d: %v", i, err)
		}
		did, err := secp256k1DIDKey(priv)
		if err != nil {
			t.Fatalf("witness DID %d: %v", i, err)
		}
		dids = append(dids, did)
	}
	addr, _, err := loadOrGenerateAdmissionAuthority(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatalf("admission authority: %v", err)
	}
	k, err := resolveGenesisQuorumK(0, len(dids))
	if err != nil {
		t.Fatalf("resolve K: %v", err)
	}
	doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "require", dids, k, addr, 1)
	if doc.GenesisQuorumK != 2 {
		t.Fatalf("emitted GenesisQuorumK = %d, want 2 for N=3", doc.GenesisQuorumK)
	}
	if _, err := doc.IDs(); err != nil {
		t.Fatalf("emitted constitutional doc must round-trip doc.IDs(): %v", err)
	}
}

// mintWitnessFixture generates n witness keys + the admission authority — the
// shared setup for the minting/ceremony tests. Keys come from the SAME
// generator main uses (loadOrGenerateWitnessKey), so the fixture is the
// tool's own material, not a stand-in.
func mintWitnessFixture(t *testing.T, n int) (dids []string, privs []*ecdsa.PrivateKey, addr string) {
	t.Helper()
	dir := t.TempDir()
	for i := 1; i <= n; i++ {
		priv, _, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witnesses", fmt.Sprintf("witness-%d.pem", i)))
		if err != nil {
			t.Fatalf("witness %d: %v", i, err)
		}
		did, err := secp256k1DIDKey(priv)
		if err != nil {
			t.Fatalf("witness DID %d: %v", i, err)
		}
		dids = append(dids, did)
		privs = append(privs, priv)
	}
	addr, _, err := loadOrGenerateAdmissionAuthority(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatalf("admission authority: %v", err)
	}
	return dids, privs, addr
}

// TestMintServedBootstrap_RequireSelfEndorses is the #77 fail-closed-minting
// pin, by evidence: with -endorsement-policy=require the served bytes (the
// EXACT bytes main writes) pass network.LoadVerifiedBootstrap — the single
// first-contact gate every consumer runs — against the doc's own NetworkID;
// the ceremony is N-of-N (endorsement count == N, every endorser a generated
// witness); and stripping ONE endorsement fails first contact (genesis has no
// quorum slack). No auditor policy is set, so witness endorsements alone must
// satisfy the gate.
func TestMintServedBootstrap_RequireSelfEndorses(t *testing.T) {
	const n = 3
	dids, privs, addr := mintWitnessFixture(t, n)
	doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "require", dids, 2, addr, 1)
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}

	body, minted, err := mintServedBootstrap(doc, privs)
	if err != nil {
		t.Fatalf("require-mode mint must succeed: %v", err)
	}
	if got := len(minted.GenesisEndorsements); got != n {
		t.Fatalf("endorsement count = %d, want %d (EVERY generated key must endorse)", got, n)
	}

	// First contact on the written bytes, pinned to the doc's own NetworkID.
	loaded, err := network.LoadVerifiedBootstrap(body, [32]byte(ids.NetworkID))
	if err != nil {
		t.Fatalf("served bytes failed LoadVerifiedBootstrap: %v", err)
	}
	if got := len(loaded.GenesisEndorsements); got != n {
		t.Fatalf("written form carries %d endorsements, want %d (the served shape includes the ceremony)", got, n)
	}
	if !loaded.RequiresEndorsement() {
		t.Fatal("written form must carry genesis_endorsement_policy=require")
	}

	// The fail-closed pin: drop ONE endorsement. The NetworkID is unchanged
	// (endorsements live outside the canonical bytes), so only the N-of-N
	// ceremony check can — and must — reject.
	var stripped network.BootstrapDocument
	if err := json.Unmarshal(body, &stripped); err != nil {
		t.Fatalf("unmarshal served bytes: %v", err)
	}
	stripped.GenesisEndorsements = stripped.GenesisEndorsements[:n-1]
	rawStripped, err := json.Marshal(stripped)
	if err != nil {
		t.Fatalf("marshal stripped doc: %v", err)
	}
	if _, err := network.LoadVerifiedBootstrap(rawStripped, [32]byte(ids.NetworkID)); !errors.Is(err, network.ErrGenesisEndorsement) {
		t.Fatalf("stripping one endorsement must fail the ceremony (N-of-N, no quorum slack), got err=%v", err)
	}
}

// TestMintServedBootstrap_OffPolicy pins the legacy/dev escape hatch: with
// -endorsement-policy=off the doc carries no policy key and no endorsements,
// and the served bytes still pass LoadVerifiedBootstrap (a no-policy doc
// demands no ceremony) — the pre-write round-trip gate applies in BOTH modes.
func TestMintServedBootstrap_OffPolicy(t *testing.T) {
	dids, privs, addr := mintWitnessFixture(t, 3)
	doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "off", dids, 2, addr, 1)
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}

	body, minted, err := mintServedBootstrap(doc, privs)
	if err != nil {
		t.Fatalf("off-mode mint must succeed: %v", err)
	}
	if len(minted.GenesisEndorsements) != 0 {
		t.Fatalf("off mode must not endorse, got %d endorsements", len(minted.GenesisEndorsements))
	}

	loaded, err := network.LoadVerifiedBootstrap(body, [32]byte(ids.NetworkID))
	if err != nil {
		t.Fatalf("off-mode served bytes failed LoadVerifiedBootstrap: %v", err)
	}
	if loaded.RequiresEndorsement() || len(loaded.GenesisEndorsements) != 0 {
		t.Fatalf("off-mode form must carry no policy and no endorsements (policy=%q count=%d)",
			loaded.GenesisEndorsementPolicy, len(loaded.GenesisEndorsements))
	}
}

// TestEndorsementPolicy_BoundIntoNetworkID: the policy lives INSIDE the
// canonical bytes, so identical inputs with require vs off mint DIFFERENT
// NetworkIDs. This is what makes the policy fail-closed — "require" cannot be
// stripped post-mint without becoming a different network and breaking every
// consumer's TOFU pin.
func TestEndorsementPolicy_BoundIntoNetworkID(t *testing.T) {
	dids, _, addr := mintWitnessFixture(t, 3)
	reqDoc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "require", dids, 2, addr, 1)
	offDoc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "off", dids, 2, addr, 1)

	reqIDs, err := reqDoc.IDs()
	if err != nil {
		t.Fatalf("require IDs: %v", err)
	}
	offIDs, err := offDoc.IDs()
	if err != nil {
		t.Fatalf("off IDs: %v", err)
	}
	if [32]byte(reqIDs.NetworkID) == [32]byte(offIDs.NetworkID) {
		t.Fatal("policy require vs off must derive different NetworkIDs (the policy is canonical-bytes material)")
	}
}

// TestInitNetwork_RefusesDilutingK: asking the tool for a diluting or
// out-of-range K fails at mint (resolveGenesisQuorumK), not at first boot.
func TestInitNetwork_RefusesDilutingK(t *testing.T) {
	for _, tc := range []struct {
		name string
		k, n int
	}{
		{"diluting 1-of-3", 1, 3},
		{"diluting 2-of-4", 2, 4},
		{"diluting 2-of-5", 2, 5},
		{"K exceeds N", 4, 3},
	} {
		if _, err := resolveGenesisQuorumK(tc.k, tc.n); err == nil {
			t.Errorf("%s: resolveGenesisQuorumK(%d,%d) must fail at mint", tc.name, tc.k, tc.n)
		}
	}
	// The conformant contrast still resolves.
	if _, err := resolveGenesisQuorumK(2, 3); err != nil {
		t.Errorf("2-of-3 is conformant (2K>N) and must resolve: %v", err)
	}
}

// TestBuildBootstrapDoc_GenesisQuorumK is the producer-side regression for the
// rc4 invariant: GenesisQuorumK is REQUIRED and bound into the NetworkID, and
// validate() (inside doc.IDs()) enforces both 1<=K<=N and the
// quorum-intersection invariant 2K>N. init-network must mint only docs that
// clear that gate, so the field threads through buildBootstrapDoc and a
// diluting K (2K<=N) is rejected at NetworkID derivation — the same gate the
// ledger applies at boot, here at the source.
func TestBuildBootstrapDoc_GenesisQuorumK(t *testing.T) {
	dir := t.TempDir()
	var dids []string
	for i := 1; i <= 3; i++ { // N=3
		priv, _, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witnesses", fmt.Sprintf("witness-%d.pem", i)))
		if err != nil {
			t.Fatalf("witness %d: %v", i, err)
		}
		did, err := secp256k1DIDKey(priv)
		if err != nil {
			t.Fatalf("witness DID %d: %v", i, err)
		}
		dids = append(dids, did)
	}
	addr, _, err := loadOrGenerateAdmissionAuthority(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatalf("admission authority: %v", err)
	}
	build := func(k int) (network.BootstrapDocument, error) {
		doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", "require", dids, k, addr, 1)
		_, idErr := doc.IDs()
		return doc, idErr
	}

	// K=2, N=3: 2*2=4 > 3 — conformant. Threads through and binds into the ID.
	if doc, err := build(2); err != nil {
		t.Fatalf("K=2 N=3 must pass SDK validation (2K>N): %v", err)
	} else if doc.GenesisQuorumK != 2 {
		t.Fatalf("GenesisQuorumK = %d, want 2 (flag did not thread into the doc)", doc.GenesisQuorumK)
	}

	// K=1, N=3: 2*1=2 <= 3 — two disjoint 1-quorums could fork. validate() must
	// reject before a NetworkID can be derived.
	if _, err := build(1); err == nil {
		t.Fatal("K=1 N=3 must be rejected by doc.IDs() (2K<=N — quorum-intersection violated)")
	}

	// K=0 (unset) and K>N are both out of range and rejected.
	if _, err := build(0); err == nil {
		t.Fatal("K=0 must be rejected by doc.IDs() (out of range / admit-no-quorum)")
	}
	if _, err := build(4); err == nil {
		t.Fatal("K=4 N=3 must be rejected by doc.IDs() (K>N)")
	}
}
