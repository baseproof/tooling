package store

import (
	"context"
	"errors"
	"testing"
)

func TestCheckpointIndex_EncodeDecodeRoundTrip(t *testing.T) {
	sizes := []uint64{1, 7, 65535, 65536, 1 << 40}
	got, err := decodeCheckpointIndex(encodeCheckpointIndex(sizes))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != len(sizes) {
		t.Fatalf("len = %d, want %d", len(got), len(sizes))
	}
	for i := range sizes {
		if got[i] != sizes[i] {
			t.Errorf("[%d] = %d, want %d", i, got[i], sizes[i])
		}
	}
}

func TestCheckpointIndex_DecodeRejectsCorruption(t *testing.T) {
	if _, err := decodeCheckpointIndex(nil); err == nil {
		t.Error("empty blob must error, never read as 'no sizes'")
	}
	if _, err := decodeCheckpointIndex([]byte{0xFF, 0, 0, 0, 0, 0, 0, 0, 1}); err == nil {
		t.Error("bad version must error")
	}
	if _, err := decodeCheckpointIndex([]byte{checkpointIndexVersion, 0, 0, 0}); err == nil {
		t.Error("body not a multiple of 8 must error")
	}
}

// Append is order-defensive (a bucket ends sorted regardless of call order) and
// idempotent (a re-published size is a no-op) — the crash-retry + restart contract.
func TestCheckpointIndex_AppendIdempotentAndSorted(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	idx := NewS3CheckpointSizeIndex(obj)
	ctx := context.Background()
	for _, s := range []uint64{30, 10, 20, 10, 30} {
		if err := idx.Append(ctx, s); err != nil {
			t.Fatalf("append %d: %v", s, err)
		}
	}
	got, err := idx.bucketSizes(ctx, 0)
	if err != nil {
		t.Fatalf("bucketSizes: %v", err)
	}
	want := []uint64{10, 20, 30}
	if len(got) != len(want) {
		t.Fatalf("sizes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sizes = %v, want %v", got, want)
		}
	}
}

// AtOrAbove / Below answer across bucket boundaries (the receipt handler's two queries).
func TestCheckpointIndex_AtOrAboveAndBelowAcrossBuckets(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	idx := NewS3CheckpointSizeIndex(obj)
	ctx := context.Background()
	B := uint64(1) << checkpointIndexShift
	sizes := []uint64{5, 100, B + 3, B + 9, 2*B + 1} // buckets 0,0,1,1,2
	for _, s := range sizes {
		if err := idx.Append(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	maxSize := sizes[len(sizes)-1]

	for _, c := range []struct {
		min, want uint64
		ok        bool
	}{
		{0, 5, true}, {5, 5, true}, {6, 100, true},
		{101, B + 3, true},     // crosses bucket 0→1
		{B + 4, B + 9, true},   // within bucket 1
		{B + 10, 2*B + 1, true}, // crosses bucket 1→2
		{2*B + 2, 0, false},    // past the last published → none
	} {
		got, ok, err := idx.AtOrAbove(ctx, c.min, maxSize)
		if err != nil {
			t.Fatalf("AtOrAbove(%d): %v", c.min, err)
		}
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("AtOrAbove(%d) = (%d,%v), want (%d,%v)", c.min, got, ok, c.want, c.ok)
		}
	}

	for _, c := range []struct {
		size, want uint64
		ok         bool
	}{
		{5, 0, false}, {6, 5, true},
		{B + 3, 100, true},     // crosses bucket 1→0
		{2*B + 1, B + 9, true}, // crosses bucket 2→1
		{3 * B, 2*B + 1, true},
	} {
		got, ok, err := idx.Below(ctx, c.size)
		if err != nil {
			t.Fatalf("Below(%d): %v", c.size, err)
		}
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("Below(%d) = (%d,%v), want (%d,%v)", c.size, got, ok, c.want, c.ok)
		}
	}
}

// The scan cap (latest published horizon) excludes an indexed size the head has not
// yet reached — even when it shares minSize's bucket.
func TestCheckpointIndex_AtOrAboveRespectsMaxCap(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	idx := NewS3CheckpointSizeIndex(obj)
	ctx := context.Background()
	for _, s := range []uint64{10, 20, 30} {
		if err := idx.Append(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, _ := idx.AtOrAbove(ctx, 25, 28); ok {
		t.Error("AtOrAbove(25, cap=28) must be false — 30 is past the cap")
	}
	if got, ok, _ := idx.AtOrAbove(ctx, 25, 30); !ok || got != 30 {
		t.Errorf("AtOrAbove(25, cap=30) = (%d,%v), want (30,true)", got, ok)
	}
}

// Edge guards: an inverted scan range and a zero "below" both answer false (not error).
func TestCheckpointIndex_EdgeGuards(t *testing.T) {
	idx := NewS3CheckpointSizeIndex(&fakeObjStore{m: map[string][]byte{}})
	ctx := context.Background()
	if _, ok, _ := idx.AtOrAbove(ctx, 10, 5); ok {
		t.Error("AtOrAbove(min>max) must be false")
	}
	if _, ok, _ := idx.Below(ctx, 0); ok {
		t.Error("Below(0) must be false (nothing is below size 0)")
	}
	// minSize above every indexed size but still <= the cap: the scan exhausts → false.
	if err := idx.Append(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := idx.AtOrAbove(ctx, 8, 12); ok {
		t.Error("AtOrAbove(8, cap=12) over sizes {5} must be false (scan exhausts)")
	}
}

// A backing-store read error surfaces (never silently treated as "no sizes").
func TestCheckpointIndex_ReadErrorPropagates(t *testing.T) {
	boom := errors.New("s3 down")
	idx := NewS3CheckpointSizeIndex(&errObjStore{err: boom})
	ctx := context.Background()
	if err := idx.Append(ctx, 5); !errors.Is(err, boom) {
		t.Errorf("Append err = %v, want wrapped %v", err, boom)
	}
	if _, _, err := idx.AtOrAbove(ctx, 1, 100); !errors.Is(err, boom) {
		t.Errorf("AtOrAbove err = %v, want wrapped %v", err, boom)
	}
	if _, _, err := idx.Below(ctx, 100); !errors.Is(err, boom) {
		t.Errorf("Below err = %v, want wrapped %v", err, boom)
	}
}

// errObjStore is an objectPutGetter whose Get/Put always fail (transient-fault tests).
type errObjStore struct{ err error }

func (e *errObjStore) PutObject(context.Context, string, []byte) error { return e.err }
func (e *errObjStore) GetObject(context.Context, string) ([]byte, error) {
	return nil, e.err
}
func (e *errObjStore) HeadObject(context.Context, string) (bool, error) { return false, e.err }
