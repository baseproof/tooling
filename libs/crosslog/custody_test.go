package crosslog

import (
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"
)

func custodyEntry(t *testing.T, seq uint64, payload []byte, encErr error) EntryAtPosition {
	t.Helper()
	if encErr != nil {
		t.Fatalf("encode payload: %v", encErr)
	}
	return EntryAtPosition{
		Position: types.LogPosition{LogDID: govLogDID, Sequence: seq},
		Entry:    &envelope.Entry{DomainPayload: payload},
	}
}

func TestMaterializeCustody_GroupsByContentDigestAndStampsPos(t *testing.T) {
	cdA := storage.Compute([]byte("artifact-A"))
	cdB := storage.Compute([]byte("artifact-B"))

	gA, err := storage.EncodeArtifactGenesisPayload(storage.ArtifactGenesis{
		ArtifactCID: cdA, ContentDigest: cdA, Owner: "did:exchange:a",
	})
	tA1, err1 := storage.EncodeArtifactCustodyTransferPayload(storage.ArtifactCustodyTransfer{
		ContentDigest: cdA, FromOwner: "did:exchange:a", ToOwner: "did:exchange:b", ToCustodian: "did:cust:b",
	})
	tA2, err2 := storage.EncodeArtifactCustodyTransferPayload(storage.ArtifactCustodyTransfer{
		ContentDigest: cdA, FromOwner: "did:exchange:b", ToOwner: "did:exchange:c", ToCustodian: "did:cust:c",
	})
	dA, err3 := storage.EncodeArtifactDestructionPayload(storage.ArtifactDestruction{
		ContentDigest: cdA, AuthorizingPrincipal: "did:exchange:c",
	})
	gB, err4 := storage.EncodeArtifactGenesisPayload(storage.ArtifactGenesis{
		ArtifactCID: cdB, ContentDigest: cdB, Owner: "did:exchange:z",
	})

	entries := []EntryAtPosition{
		custodyEntry(t, 1, gA, err),
		custodyEntry(t, 5, tA1, err1),
		custodyEntry(t, 9, tA2, err2),
		custodyEntry(t, 12, dA, err3),
		custodyEntry(t, 3, gB, err4),
	}

	mat := MaterializeCustody(entries, govSilent())
	if len(mat.Chains) != 2 {
		t.Fatalf("want 2 chains (cdA, cdB), got %d", len(mat.Chains))
	}
	chA := mat.Chains[cdA.String()]
	if chA == nil {
		t.Fatal("no chain for cdA")
	}
	if chA.Genesis.Owner != "did:exchange:a" {
		t.Errorf("cdA genesis owner = %q, want did:exchange:a", chA.Genesis.Owner)
	}
	if len(chA.Transfers) != 2 {
		t.Fatalf("cdA transfers = %d, want 2", len(chA.Transfers))
	}
	// EffectivePos stamped from the on-log Position, not the (absent) wire field.
	if chA.Transfers[0].EffectivePos.Sequence != 5 || chA.Transfers[1].EffectivePos.Sequence != 9 {
		t.Errorf("transfer EffectivePos not stamped from position: %d,%d",
			chA.Transfers[0].EffectivePos.Sequence, chA.Transfers[1].EffectivePos.Sequence)
	}
	if chA.Destruction == nil || chA.Destruction.EffectivePos.Sequence != 12 {
		t.Errorf("cdA destruction not stamped at seq 12: %+v", chA.Destruction)
	}
	if chB := mat.Chains[cdB.String()]; chB == nil || chB.Genesis.Owner != "did:exchange:z" {
		t.Errorf("cdB chain missing or wrong owner: %+v", chB)
	}

	// The projected chain walks cleanly via the SDK (genesis → b → c).
	owner, custodian, walkErr := storage.ArtifactCustodyAt(chA.Genesis, chA.Transfers, types.LogPosition{LogDID: govLogDID, Sequence: 100})
	if walkErr != nil {
		t.Fatalf("projected chain must walk cleanly: %v", walkErr)
	}
	if owner != "did:exchange:c" || custodian != "did:cust:c" {
		t.Errorf("resolved (%s,%s), want (did:exchange:c, did:cust:c)", owner, custodian)
	}
}

func TestMaterializeCustody_EarliestDestructionWins(t *testing.T) {
	cdA := storage.Compute([]byte("artifact-A"))
	d1, e1 := storage.EncodeArtifactDestructionPayload(storage.ArtifactDestruction{ContentDigest: cdA, AuthorizingPrincipal: "did:exchange:a"})
	d2, e2 := storage.EncodeArtifactDestructionPayload(storage.ArtifactDestruction{ContentDigest: cdA, AuthorizingPrincipal: "did:exchange:a"})
	mat := MaterializeCustody([]EntryAtPosition{
		custodyEntry(t, 20, d2, e2), // later
		custodyEntry(t, 10, d1, e1), // earlier
	}, govSilent())
	ch := mat.Chains[cdA.String()]
	if ch == nil || ch.Destruction == nil {
		t.Fatal("no destruction recorded")
	}
	if ch.Destruction.EffectivePos.Sequence != 10 {
		t.Errorf("earliest destruction must win: got seq %d, want 10", ch.Destruction.EffectivePos.Sequence)
	}
}

func TestMaterializeCustody_SkipsUnknownAndMalformed(t *testing.T) {
	cdA := storage.Compute([]byte("artifact-A"))
	gA, err := storage.EncodeArtifactGenesisPayload(storage.ArtifactGenesis{ArtifactCID: cdA, ContentDigest: cdA, Owner: "did:exchange:a"})
	entries := []EntryAtPosition{
		custodyEntry(t, 1, gA, err),
		{Position: types.LogPosition{Sequence: 2}, Entry: &envelope.Entry{DomainPayload: []byte(`{"kind":"BP-ENTRY-SOMETHING-ELSE"}`)}}, // unknown → skip
		{Position: types.LogPosition{Sequence: 3}, Entry: &envelope.Entry{DomainPayload: []byte(`{not json`)}},                          // malformed → skip
		{Position: types.LogPosition{Sequence: 4}, Entry: nil},                                                                          // nil → skip
	}
	mat := MaterializeCustody(entries, govSilent())
	if len(mat.Chains) != 1 {
		t.Fatalf("only the genesis chain must materialize, got %d", len(mat.Chains))
	}
}

// A payload whose "kind" matches a custody kind but whose body fails the SDK
// decoder is warned + skipped (one reject path per kind).
func TestMaterializeCustody_RejectsKindMatchedButInvalid(t *testing.T) {
	entries := []EntryAtPosition{
		{Position: types.LogPosition{Sequence: 1}, Entry: &envelope.Entry{DomainPayload: []byte(`{"kind":"BP-ENTRY-ARTIFACT-GENESIS-V1"}`)}},
		{Position: types.LogPosition{Sequence: 2}, Entry: &envelope.Entry{DomainPayload: []byte(`{"kind":"BP-ENTRY-ARTIFACT-CUSTODY-TRANSFER-V1"}`)}},
		{Position: types.LogPosition{Sequence: 3}, Entry: &envelope.Entry{DomainPayload: []byte(`{"kind":"BP-ENTRY-ARTIFACT-DESTRUCTION-V1"}`)}},
	}
	mat := MaterializeCustody(entries, govSilent())
	if len(mat.Chains) != 0 {
		t.Fatalf("all kind-matched-but-invalid payloads must be skipped, got %d chains", len(mat.Chains))
	}
}

func TestMaterializeCustody_NilLogger(t *testing.T) {
	cdA := storage.Compute([]byte("artifact-A"))
	gA, err := storage.EncodeArtifactGenesisPayload(storage.ArtifactGenesis{ArtifactCID: cdA, ContentDigest: cdA, Owner: "did:exchange:a"})
	mat := MaterializeCustody([]EntryAtPosition{custodyEntry(t, 1, gA, err)}, nil)
	if len(mat.Chains) != 1 {
		t.Fatalf("nil logger must still materialize, got %d", len(mat.Chains))
	}
}
