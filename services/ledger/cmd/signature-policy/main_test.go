package main

import (
	"strings"
	"testing"

	sdknetwork "github.com/baseproof/baseproof/network"
)

func TestMustEntrySchemes_SortDedupHex(t *testing.T) {
	// Out-of-order + duplicate + 0x-optional → strictly-ascending, deduped.
	got := mustEntrySchemes("0x0002, 1 ,0x0002")
	if len(got) != 2 || got[0] != 0x0001 || got[1] != 0x0002 {
		t.Fatalf("got %v, want [1 2] (sorted, deduped)", got)
	}
}

func TestMustCosignTags_SortDedupHex(t *testing.T) {
	got := mustCosignTags("0x02,0x01,2")
	if len(got) != 2 || got[0] != 0x01 || got[1] != 0x02 {
		t.Fatalf("got %v, want [1 2] (sorted, deduped)", got)
	}
}

func TestMustSchemaPos(t *testing.T) {
	p := mustSchemaPos("did:web:state:tn:davidson@7", "fallback")
	if p.LogDID != "did:web:state:tn:davidson" || p.Sequence != 7 {
		t.Fatalf("got %+v", p)
	}
	p2 := mustSchemaPos("@9", "fallback-did")
	if p2.LogDID != "fallback-did" || p2.Sequence != 9 {
		t.Fatalf("got %+v", p2)
	}
}

func TestPolicyLabel(t *testing.T) {
	hybrid := int64(1893456000)
	p := sdknetwork.SignaturePolicy{
		AllowedEntrySigSchemes:  []uint16{0x0001},
		AllowedCosignSchemeTags: []uint8{0x01, 0x02},
		MinSignaturesPerEntry:   2,
		RequireHybridAfter:      &hybrid,
	}
	got := policyLabel(p)
	for _, want := range []string{"MinSignaturesPerEntry=2", "0x0001", "0x01", "0x02", "1893456000"} {
		if !strings.Contains(got, want) {
			t.Fatalf("policyLabel missing %q: %s", want, got)
		}
	}
	if modeLabel("") != "Mode B (PoW)" || modeLabel("tok") != "Mode A (credit)" {
		t.Fatal("modeLabel wrong")
	}
}
