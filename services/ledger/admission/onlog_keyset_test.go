package admission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/types"
)

func member(b byte) [20]byte {
	var a [20]byte
	a[0] = b
	return a
}

func recAt(seq uint64, members ...[20]byte) authz.EOAKeysetRecord {
	return authz.EOAKeysetRecord{
		EffectivePos: types.LogPosition{LogDID: "did:web:ctrl", Sequence: seq},
		Members:      members,
	}
}

func TestOnLogAdmissionKeyset_Current(t *testing.T) {
	ctx := context.Background()
	// Latest snapshot (highest position) wins, regardless of input order.
	src := func(context.Context) ([]authz.EOAKeysetRecord, error) {
		return []authz.EOAKeysetRecord{
			recAt(30, member(3)),
			recAt(10, member(1)),
			recAt(20, member(1), member(2)),
		}, nil
	}
	k := NewOnLogAdmissionKeyset(src, nil, 0) // no cache
	got, err := k.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != member(3) {
		t.Errorf("current = %x, want {3} (latest snapshot)", got)
	}

	// Empty source → nil (fail-closed at the gate).
	kEmpty := NewOnLogAdmissionKeyset(func(context.Context) ([]authz.EOAKeysetRecord, error) { return nil, nil }, nil, 0)
	if got, err := kEmpty.Current(ctx); err != nil || got != nil {
		t.Errorf("empty: %x / %v", got, err)
	}

	// Genesis fallback: no on-log snapshot → the genesis authority set.
	kGen := NewOnLogAdmissionKeyset(
		func(context.Context) ([]authz.EOAKeysetRecord, error) { return nil, nil },
		[][20]byte{member(9)}, 0)
	if got, _ := kGen.Current(ctx); len(got) != 1 || got[0] != member(9) {
		t.Errorf("genesis fallback = %x, want {9}", got)
	}

	// Source error propagates.
	boom := errors.New("query failed")
	kErr := NewOnLogAdmissionKeyset(func(context.Context) ([]authz.EOAKeysetRecord, error) { return nil, boom }, nil, 0)
	if _, err := kErr.Current(ctx); !errors.Is(err, boom) {
		t.Errorf("source error: %v", err)
	}
}

func TestOnLogAdmissionKeyset_Cache(t *testing.T) {
	ctx := context.Background()
	calls := 0
	src := func(context.Context) ([]authz.EOAKeysetRecord, error) {
		calls++
		return []authz.EOAKeysetRecord{recAt(1, member(7))}, nil
	}
	// Long TTL → second call served from cache.
	k := NewOnLogAdmissionKeyset(src, nil, time.Hour)
	if _, err := k.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("cache: source called %d times, want 1", calls)
	}

	// ttl<=0 → re-sourced every call.
	calls = 0
	kNoCache := NewOnLogAdmissionKeyset(src, nil, 0)
	_, _ = kNoCache.Current(ctx)
	_, _ = kNoCache.Current(ctx)
	if calls != 2 {
		t.Errorf("no-cache: source called %d times, want 2", calls)
	}
}
