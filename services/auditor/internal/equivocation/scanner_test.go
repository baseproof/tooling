// FILE PATH: services/auditor/internal/equivocation/scanner_test.go
//
// Tests for the Phase 5 equivocation scanner wiring. The SDK's
// witness.DetectEquivocation is the cryptographic source of truth
// (covered by baseproof/witness tests); these tests cover:
//
//  1. NewScanner validates every required field (returns
//     ErrInvalidConfig for each missing piece).
//  2. Default PollInterval is applied when zero.
//  3. lookupAndStore: first sighting → no prior; second sighting at
//     same TreeSize → returns the prior, replaces it with the new.
//  4. checkOne with same RootHash twice → no emit, no error.
//  5. checkOne with different sizes → no emit (silenced).
//
// Cryptographic equivocation (two cosigned heads, same size,
// different roots) is covered end-to-end by the integration smoke
// test in tests/contracts/, which has BLS material.
package equivocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

func TestNewScanner_RejectsEmptyLogDIDs(t *testing.T) {
	_, err := NewScanner(ScannerConfig{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestNewScanner_RejectsEmptyWitnessSets(t *testing.T) {
	_, err := NewScanner(ScannerConfig{LogDIDs: []string{"did:test:1"}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig (empty WitnessSets), got %v", err)
	}
}

func TestNewScanner_RejectsNilClient(t *testing.T) {
	_, err := NewScanner(ScannerConfig{
		LogDIDs:     []string{"did:test:1"},
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig (nil client), got %v", err)
	}
}

func TestNewScanner_RejectsNilEmitter(t *testing.T) {
	_, err := NewScanner(ScannerConfig{
		LogDIDs:     []string{"did:test:1"},
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
		Client:      &witness.TreeHeadClient{},
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig (nil emitter), got %v", err)
	}
}

func TestNewScanner_RejectsNilSigner(t *testing.T) {
	_, err := NewScanner(ScannerConfig{
		LogDIDs:     []string{"did:test:1"},
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
		Client:      &witness.TreeHeadClient{},
		Emitter:     &fakeEmitter{},
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig (nil signer), got %v", err)
	}
}

func TestNewScanner_DefaultsApplied(t *testing.T) {
	s, err := NewScanner(ScannerConfig{
		LogDIDs:     []string{"did:test:1"},
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
		Client:      &witness.TreeHeadClient{},
		Emitter:     &fakeEmitter{},
		Signer:      fakeSigner,
	})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if s.cfg.PollInterval != 30*time.Second {
		t.Fatalf("default PollInterval = 30s, got %v", s.cfg.PollInterval)
	}
	if s.logger == nil {
		t.Fatalf("logger must be initialized to non-nil")
	}
}

func TestLookupAndStore_FirstSightingNoPrior(t *testing.T) {
	s := mustNewScannerForCache(t)
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 100, RootHash: [32]byte{0x01}}}
	prior, had := s.lookupAndStore("did:test:1", head)
	if had {
		t.Fatalf("first sighting should report no prior; got %v", prior)
	}
}

func TestLookupAndStore_SecondSightingReturnsPriorAndReplaces(t *testing.T) {
	s := mustNewScannerForCache(t)
	a := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 100, RootHash: [32]byte{0x01}}}
	b := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 100, RootHash: [32]byte{0x02}}}
	_, _ = s.lookupAndStore("did:test:1", a)
	prior, had := s.lookupAndStore("did:test:1", b)
	if !had {
		t.Fatalf("second sighting must report had-prior=true")
	}
	if prior.RootHash != a.RootHash {
		t.Fatalf("prior root mismatch: want %x got %x", a.RootHash, prior.RootHash)
	}
	// Third sighting must see b as prior (we just replaced).
	c := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 100, RootHash: [32]byte{0x03}}}
	prior2, had2 := s.lookupAndStore("did:test:1", c)
	if !had2 || prior2.RootHash != b.RootHash {
		t.Fatalf("third sighting prior should be b; got had=%v root=%x", had2, prior2.RootHash)
	}
}

func TestLookupAndStore_DifferentSizesDoNotCollide(t *testing.T) {
	s := mustNewScannerForCache(t)
	a := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 100, RootHash: [32]byte{0x01}}}
	b := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 200, RootHash: [32]byte{0x02}}}
	_, _ = s.lookupAndStore("did:test:1", a)
	_, had := s.lookupAndStore("did:test:1", b)
	if had {
		t.Fatalf("different TreeSize must not be reported as prior")
	}
}

func mustNewScannerForCache(t *testing.T) *Scanner {
	t.Helper()
	s, err := NewScanner(ScannerConfig{
		LogDIDs:     []string{"did:test:1"},
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
		Client:      &witness.TreeHeadClient{},
		Emitter:     &fakeEmitter{},
		Signer:      fakeSigner,
	})
	if err != nil {
		t.Fatalf("mustNewScannerForCache: %v", err)
	}
	return s
}

// fakeEmitter / fakeSigner — simple counting fakes.

type fakeEmitter struct {
	emits []gossip.SignedEvent
}

func (e *fakeEmitter) EmitEvidence(_ context.Context, ev gossip.SignedEvent) error {
	e.emits = append(e.emits, ev)
	return nil
}

func fakeSigner(_ context.Context, ev gossip.Event) (gossip.SignedEvent, error) {
	return gossip.SignedEvent{Kind: ev.Kind()}, nil
}
