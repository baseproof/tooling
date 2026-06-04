package crosslog

import (
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"
)

// mkRef builds a valid, self-consistent commitment ref over `mutations` leaf
// mutations whose range starts at startSeq, plus the entry that carries it.
func mkRef(startSeq uint64, mutations int) (storage.SMTDerivationCommitmentRef, EntryAtPosition) {
	muts := make([]types.LeafMutation, mutations)
	for i := range muts {
		muts[i] = types.LeafMutation{LeafKey: [32]byte{byte(startSeq), byte(i)}}
	}
	blob, _ := storage.MarshalCommitmentMutations(muts)
	cid := storage.Compute(blob)
	ref := storage.SMTDerivationCommitmentRef{
		LogRangeStart: types.LogPosition{LogDID: govLogDID, Sequence: startSeq},
		LogRangeEnd:   types.LogPosition{LogDID: govLogDID, Sequence: startSeq + 9},
		MutationCount: uint32(mutations),
		MutationsCID:  cid,
		HashAlgo:      cid.Algorithm,
	}
	payload, _ := json.Marshal(ref)
	return ref, EntryAtPosition{
		Position: types.LogPosition{LogDID: govLogDID, Sequence: startSeq},
		Entry:    &envelope.Entry{DomainPayload: payload},
	}
}

func TestDiscoverCommitmentRefs_DetectsAndSorts(t *testing.T) {
	_, e30 := mkRef(30, 2)
	_, e10 := mkRef(10, 1)
	_, e20 := mkRef(20, 3)

	got := DiscoverCommitmentRefs([]EntryAtPosition{e30, e10, e20}, govSilent())
	if len(got) != 3 {
		t.Fatalf("want 3 refs discovered, got %d", len(got))
	}
	// Sorted ascending by LogRangeStart.
	if got[0].LogRangeStart.Sequence != 10 || got[1].LogRangeStart.Sequence != 20 || got[2].LogRangeStart.Sequence != 30 {
		t.Errorf("refs not sorted by range: %d,%d,%d",
			got[0].LogRangeStart.Sequence, got[1].LogRangeStart.Sequence, got[2].LogRangeStart.Sequence)
	}
}

func TestDiscoverCommitmentRefs_SkipsNonCommitmentPayloads(t *testing.T) {
	_, refEntry := mkRef(10, 1)
	entries := []EntryAtPosition{
		refEntry,
		// An anchor-shaped commentary payload: no mutations_cid → zero MutationsCID → skip.
		{Position: types.LogPosition{Sequence: 11}, Entry: &envelope.Entry{DomainPayload: []byte(`{"root_hash":"abc","tree_size":5}`)}},
		{Position: types.LogPosition{Sequence: 12}, Entry: &envelope.Entry{DomainPayload: []byte(`{not json`)}}, // malformed → skip
		{Position: types.LogPosition{Sequence: 13}, Entry: nil},                                                 // nil → skip
		{Position: types.LogPosition{Sequence: 14}, Entry: &envelope.Entry{DomainPayload: nil}},                 // empty → skip
	}
	got := DiscoverCommitmentRefs(entries, govSilent())
	if len(got) != 1 {
		t.Fatalf("only the real commitment ref must be discovered, got %d", len(got))
	}
}

func TestDiscoverCommitmentRefs_NilLogger(t *testing.T) {
	_, e := mkRef(10, 1)
	if got := DiscoverCommitmentRefs([]EntryAtPosition{e}, nil); len(got) != 1 {
		t.Fatalf("nil logger must still discover, got %d", len(got))
	}
}

// A ref whose HashAlgo does not restate its MutationsCID algorithm fails the
// self-consistency signature and is skipped (defends against coincidental
// unmarshals of unrelated payloads).
func TestDiscoverCommitmentRefs_RejectsInconsistentHashAlgo(t *testing.T) {
	ref, _ := mkRef(10, 1)
	ref.HashAlgo = ref.MutationsCID.Algorithm + 1 // deliberately inconsistent
	payload, _ := json.Marshal(ref)
	got := DiscoverCommitmentRefs([]EntryAtPosition{
		{Position: types.LogPosition{Sequence: 10}, Entry: &envelope.Entry{DomainPayload: payload}},
	}, govSilent())
	if len(got) != 0 {
		t.Fatalf("ref with inconsistent HashAlgo must be skipped, got %d", len(got))
	}
}
