/*
FILE PATH: libs/crosslog/network_records_test.go

T2 unit tests — BuildAuditorRegistryFromConfig, BuildKnownWitnessKeys,
BuildLogWitnessSets.

Covers the three configuration-row → SDK-record helpers that bridge
operator deployment config to the resolver's inputs. Each helper
has its own validation contract; tests pin each.
*/
package crosslog

import (
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// generateDIDKeyForTest mints a syntactically-valid did:key:secp256k1.
// Required for tests that exercise downstream code paths AFTER
// BuildLogWitnessSets's key resolution — using a synthetic
// did:key:zNNN... string fails ParseDIDKey on unsupported multicodec
// 0x105f and short-circuits the test before reaching the path under
// test.
func generateDIDKeyForTest(t *testing.T) string {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	return kp.DID
}

// validAuditorSpec returns a syntactically-valid AuditorSpec ready
// for BuildAuditorRegistryFromConfig. Tests can mutate fields to
// exercise per-field validation paths.
func validAuditorSpec() AuditorSpec {
	pub := make([]byte, 33)
	pub[0] = 0x02
	return AuditorSpec{
		EffectiveSeq: 0,
		AuditorDID:   "did:web:auditor.example.org",
		PublicKey:    pub,
		SchemeTag:    1, // ECDSA
		FindingsURL:  "https://auditor.example.org/v1/findings",
		Scope:        network.ScopeEquivocation,
	}
}

// ─────────────────────────────────────────────────────────────
// BuildAuditorRegistryFromConfig
// ─────────────────────────────────────────────────────────────

func TestBuildAuditorRegistryFromConfig_Empty(t *testing.T) {
	got, err := BuildAuditorRegistryFromConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty input must yield empty slice; got len=%d", len(got))
	}
	if got == nil {
		t.Error("must return non-nil empty slice (caller may sort/range over it)")
	}
}

func TestBuildAuditorRegistryFromConfig_SingleValid(t *testing.T) {
	specs := []AuditorSpec{validAuditorSpec()}
	got, err := BuildAuditorRegistryFromConfig(specs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got len=%d, want 1", len(got))
	}
	if got[0].Payload.AuditorDID != "did:web:auditor.example.org" {
		t.Errorf("AuditorDID: got %q", got[0].Payload.AuditorDID)
	}
	if got[0].EffectivePos.Sequence != 0 {
		t.Errorf("EffectivePos.Sequence: got %d, want 0", got[0].EffectivePos.Sequence)
	}
}

func TestBuildAuditorRegistryFromConfig_MultipleEffectiveSeq(t *testing.T) {
	// Operator-defined EffectiveSeq per spec must flow through verbatim.
	specs := []AuditorSpec{
		func() AuditorSpec { s := validAuditorSpec(); s.EffectiveSeq = 100; return s }(),
		func() AuditorSpec {
			s := validAuditorSpec()
			s.EffectiveSeq = 200
			s.AuditorDID = "did:web:auditor-2.example.org"
			return s
		}(),
	}
	got, err := BuildAuditorRegistryFromConfig(specs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].EffectivePos.Sequence != 100 {
		t.Errorf("Sequence[0]: got %d, want 100", got[0].EffectivePos.Sequence)
	}
	if got[1].EffectivePos.Sequence != 200 {
		t.Errorf("Sequence[1]: got %d, want 200", got[1].EffectivePos.Sequence)
	}
}

func TestBuildAuditorRegistryFromConfig_InvalidSpec(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(s *AuditorSpec)
		wantError string
	}{
		{
			name:      "empty-did",
			mutate:    func(s *AuditorSpec) { s.AuditorDID = "" },
			wantError: "auditor_did",
		},
		{
			name:      "zero-scope",
			mutate:    func(s *AuditorSpec) { s.Scope = network.ScopeNone },
			wantError: "scope",
		},
		{
			name:      "http-not-https",
			mutate:    func(s *AuditorSpec) { s.FindingsURL = "http://auditor.example.org/v1/findings" },
			wantError: "https",
		},
		{
			name:      "zero-scheme-tag",
			mutate:    func(s *AuditorSpec) { s.SchemeTag = 0 },
			wantError: "scheme_tag",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validAuditorSpec()
			tc.mutate(&s)
			_, err := BuildAuditorRegistryFromConfig([]AuditorSpec{s})
			if err == nil {
				t.Fatalf("expected error mentioning %q; got nil", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("error %q must contain %q", err.Error(), tc.wantError)
			}
			// Error MUST include the row index for operator triage.
			if !strings.Contains(err.Error(), "[0]") {
				t.Errorf("error must include row index '[0]'; got %v", err)
			}
		})
	}
}

func TestBuildAuditorRegistryFromConfig_DefensiveCopyOfBytes(t *testing.T) {
	spec := validAuditorSpec()
	originalKey := spec.PublicKey
	got, err := BuildAuditorRegistryFromConfig([]AuditorSpec{spec})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// Mutate the caller's slice; record MUST NOT see the change.
	originalKey[0] = 0xFF
	if got[0].Payload.PublicKey[0] == 0xFF {
		t.Error("PublicKey not defensively copied (record sees caller's mutation)")
	}
}

// ─────────────────────────────────────────────────────────────
// BuildKnownWitnessKeys
// ─────────────────────────────────────────────────────────────

func TestBuildKnownWitnessKeys_EmptyGenesisErrors(t *testing.T) {
	_, err := BuildKnownWitnessKeys(nil, nil)
	if err == nil {
		t.Fatal("empty genesis must error")
	}
	if !strings.Contains(err.Error(), "genesis") {
		t.Errorf("error must mention 'genesis'; got %v", err)
	}
}

func TestBuildKnownWitnessKeys_GenesisOnly(t *testing.T) {
	genesis := []types.WitnessPublicKey{
		{ID: [32]byte{0x01}, SchemeTag: signatures.SchemeECDSA},
		{ID: [32]byte{0x02}, SchemeTag: signatures.SchemeECDSA},
		{ID: [32]byte{0x03}, SchemeTag: signatures.SchemeECDSA},
	}
	got, err := BuildKnownWitnessKeys(genesis, nil)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 keys; got %d", len(got))
	}
	for i, k := range genesis {
		if _, ok := got[k.ID]; !ok {
			t.Errorf("genesis key %d not in set", i)
		}
	}
}

func TestBuildKnownWitnessKeys_GenesisPlusRotations(t *testing.T) {
	// Two genesis keys + two rotation batches (one adds a key, one
	// repeats a genesis key — union semantics).
	genesis := []types.WitnessPublicKey{
		{ID: [32]byte{0x01}, SchemeTag: signatures.SchemeECDSA},
		{ID: [32]byte{0x02}, SchemeTag: signatures.SchemeECDSA},
	}
	rotations := [][]types.WitnessPublicKey{
		{
			{ID: [32]byte{0x03}, SchemeTag: signatures.SchemeECDSA}, // new
		},
		{
			{ID: [32]byte{0x01}, SchemeTag: signatures.SchemeECDSA}, // duplicate of genesis — union semantics
		},
	}
	got, err := BuildKnownWitnessKeys(genesis, rotations)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected union to dedupe to 3 distinct keys; got %d", len(got))
	}
	for _, want := range [][32]byte{{0x01}, {0x02}, {0x03}} {
		if _, ok := got[want]; !ok {
			t.Errorf("key %x not in union", want[:4])
		}
	}
}

// ─────────────────────────────────────────────────────────────
// BuildLogWitnessSets
// ─────────────────────────────────────────────────────────────

func TestBuildLogWitnessSets_Empty(t *testing.T) {
	got, err := BuildLogWitnessSets(nil)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got == nil {
		t.Error("must return non-nil empty map")
	}
	if len(got) != 0 {
		t.Errorf("expected empty map; got %d entries", len(got))
	}
}

func TestBuildLogWitnessSets_EmptyLogDID(t *testing.T) {
	specs := []WitnessSetSpec{{LogDID: "", QuorumK: 1}}
	_, err := BuildLogWitnessSets(specs)
	if err == nil {
		t.Fatal("empty LogDID must error")
	}
	if !strings.Contains(err.Error(), "log_did") {
		t.Errorf("error must mention 'log_did'; got %v", err)
	}
}

func TestBuildLogWitnessSets_DuplicateLogDID(t *testing.T) {
	witnessDID := generateDIDKeyForTest(t)
	specs := []WitnessSetSpec{
		{
			LogDID:      "did:test:log-A",
			WitnessDIDs: []string{witnessDID},
			QuorumK:     1,
		},
		{
			LogDID:      "did:test:log-A", // duplicate
			WitnessDIDs: []string{witnessDID},
			QuorumK:     1,
		},
	}
	_, err := BuildLogWitnessSets(specs)
	if err == nil {
		t.Fatal("duplicate LogDID must error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error must mention 'duplicate'; got %v", err)
	}
}
