package store

import (
	"context"
	"errors"
	"testing"

	sdktypes "github.com/baseproof/baseproof/types"
)

// s3HeadSigned is a cosigned head WITH one witness signature, so GetBySize's
// sdk→apitypes→sdk round-trip is exercised on the signature leg the verifier needs.
func s3HeadSigned(n uint64) sdktypes.CosignedTreeHead {
	h := s3Head(n)
	h.Signatures = []sdktypes.WitnessSignature{{
		PubKeyID:  [32]byte{byte(n)},
		SchemeTag: 1,
		SigBytes:  []byte{byte(n), 0x01, 0x02},
	}}
	return h
}

// The PG-free resolver reproduces the receipt handler's covering-head queries over a
// history written through the real publisher (per-size archive + size index + horizon).
func TestS3ReceiptHeadResolver_OverPublishedHistory(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	pub := NewS3CheckpointPublisher(obj)
	horizon := NewS3HorizonReader(obj)
	resolver := NewS3ReceiptHeadResolver(NewS3CheckpointSizeIndex(obj), horizon)
	ctx := context.Background()

	for _, n := range []uint64{10, 25, 40} {
		if err := pub.PublishCosignedCheckpoint(ctx, s3HeadSigned(n)); err != nil {
			t.Fatalf("publish %d: %v", n, err)
		}
	}

	// CosignedSizeAtOrAbove: the first published checkpoint covering seq+1.
	for _, c := range []struct {
		min, want uint64
		ok        bool
	}{
		{1, 10, true}, {10, 10, true}, {11, 25, true}, {25, 25, true}, {26, 40, true},
		{41, 0, false}, // nothing published covers it yet
	} {
		got, ok, err := resolver.CosignedSizeAtOrAbove(ctx, c.min, 1)
		if err != nil {
			t.Fatalf("AtOrAbove(%d): %v", c.min, err)
		}
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("AtOrAbove(%d) = (%d,%v), want (%d,%v)", c.min, got, ok, c.want, c.ok)
		}
	}

	// CosignedSizeBelow: the previous published checkpoint (the delta-range start).
	for _, c := range []struct {
		size, want uint64
		ok         bool
	}{
		{10, 0, false}, {25, 10, true}, {40, 25, true},
	} {
		got, ok, err := resolver.CosignedSizeBelow(ctx, c.size, 1)
		if err != nil {
			t.Fatalf("Below(%d): %v", c.size, err)
		}
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("Below(%d) = (%d,%v), want (%d,%v)", c.size, got, ok, c.want, c.ok)
		}
	}

	// GetBySize round-trips the head + its signature into apitypes; HeadToSDK (the
	// receipt handler's re-encode path) reproduces the original.
	head, err := resolver.GetBySize(ctx, 25)
	if err != nil {
		t.Fatalf("GetBySize(25): %v", err)
	}
	if head == nil || head.TreeSize != 25 {
		t.Fatalf("GetBySize(25) head = %+v", head)
	}
	back := HeadToSDK(head)
	if back.TreeSize != 25 || len(back.Signatures) != 1 {
		t.Errorf("round-trip head = size %d, %d sigs; want 25, 1", back.TreeSize, len(back.Signatures))
	}
	if back.Signatures[0].PubKeyID != [32]byte{25} || back.Signatures[0].SchemeTag != 1 {
		t.Errorf("round-trip dropped signature fields: %+v", back.Signatures[0])
	}
}

// GetBySize on an unarchived size is a real inconsistency → error (never a fabricated head).
func TestS3ReceiptHeadResolver_GetBySizeMissingIsError(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	resolver := NewS3ReceiptHeadResolver(NewS3CheckpointSizeIndex(obj), NewS3HorizonReader(obj))
	if _, err := resolver.GetBySize(context.Background(), 999); err == nil {
		t.Error("GetBySize on an unarchived size must error")
	}
}

// Before anything is published (empty horizon), AtOrAbove is false — not an error.
func TestS3ReceiptHeadResolver_EmptyHorizon(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	resolver := NewS3ReceiptHeadResolver(NewS3CheckpointSizeIndex(obj), NewS3HorizonReader(obj))
	got, ok, err := resolver.CosignedSizeAtOrAbove(context.Background(), 1, 1)
	if err != nil {
		t.Fatalf("AtOrAbove on empty horizon: %v", err)
	}
	if ok {
		t.Errorf("AtOrAbove on empty horizon = (%d,true), want false", got)
	}
}

// A horizon read fault (distinct from a pre-genesis miss) surfaces — the at-or-above
// cap can't be resolved, so the query errors rather than fabricating a covering head.
func TestS3ReceiptHeadResolver_HorizonReadErrorPropagates(t *testing.T) {
	boom := errors.New("s3 down")
	resolver := NewS3ReceiptHeadResolver(
		NewS3CheckpointSizeIndex(&errObjStore{err: boom}),
		NewS3HorizonReader(&errObjStore{err: boom}),
	)
	if _, _, err := resolver.CosignedSizeAtOrAbove(context.Background(), 1, 1); !errors.Is(err, boom) {
		t.Errorf("AtOrAbove err = %v, want wrapped %v", err, boom)
	}
}

// sdkHeadToAPI is nil-safe (defensive: GetBySize never passes nil, ReadCheckpointAt
// returns a head or an error).
func TestSdkHeadToAPI_Nil(t *testing.T) {
	if sdkHeadToAPI(nil) != nil {
		t.Error("sdkHeadToAPI(nil) must be nil")
	}
}
