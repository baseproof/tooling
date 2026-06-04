package monitoring

import (
	"testing"

	"github.com/baseproof/baseproof/types"
)

func th(size uint64, root byte) types.TreeHead {
	return types.TreeHead{TreeSize: size, RootHash: [32]byte{root}}
}

func TestTrustedHeadStore_Verdicts(t *testing.T) {
	s := NewTrustedHeadStore(nil)

	if v := s.RecordCosignedHead("did:log", th(100, 0xAA)); v != VerdictAdvanced {
		t.Fatalf("first head verdict = %v, want advanced", v)
	}
	if v := s.RecordCosignedHead("did:log", th(200, 0xBB)); v != VerdictAdvanced {
		t.Fatalf("larger size verdict = %v, want advanced", v)
	}
	if v := s.RecordCosignedHead("did:log", th(200, 0xBB)); v != VerdictStale {
		t.Fatalf("duplicate verdict = %v, want stale", v)
	}
	if v := s.RecordCosignedHead("did:log", th(150, 0xCC)); v != VerdictRegressed {
		t.Fatalf("smaller size verdict = %v, want regressed", v)
	}
	if v := s.RecordCosignedHead("did:log", th(200, 0xDD)); v != VerdictForkSuspected {
		t.Fatalf("same size diff root verdict = %v, want fork_suspected", v)
	}

	// The trusted head must remain the highest CLEAN advance (200/0xBB) — a
	// fork or regression never overwrites it.
	h, ok := s.TrustedHead("did:log")
	if !ok || h.TreeSize != 200 || h.RootHash != [32]byte{0xBB} {
		t.Fatalf("trusted head = %+v ok=%v, want size 200 root 0xBB", h, ok)
	}
	if _, ok := s.TrustedHead("did:unknown"); ok {
		t.Fatal("unknown log should miss")
	}
}
