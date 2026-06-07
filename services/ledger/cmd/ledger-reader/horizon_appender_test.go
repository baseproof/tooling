package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/tessera"
)

// stubHorizon is a minimal api.HorizonReader for the appender-backend tests.
type stubHorizon struct {
	head *types.CosignedTreeHead
	err  error
}

func (s stubHorizon) ReadHorizon(context.Context) (*types.CosignedTreeHead, []byte, error) {
	return s.head, nil, s.err
}

func TestHorizonAppenderBackend_HeadAndIntegratedSize(t *testing.T) {
	want := types.TreeHead{TreeSize: 4242, RootHash: [32]byte{0xaa}, SMTRoot: [32]byte{0xbb}}
	b := newHorizonAppenderBackend(stubHorizon{head: &types.CosignedTreeHead{TreeHead: want}})

	got, err := b.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got != want {
		t.Fatalf("Head = %+v, want %+v", got, want)
	}

	size, err := b.IntegratedSize(context.Background())
	if err != nil {
		t.Fatalf("IntegratedSize: %v", err)
	}
	if size != want.TreeSize {
		t.Fatalf("IntegratedSize = %d, want %d", size, want.TreeSize)
	}
}

func TestHorizonAppenderBackend_PropagatesHorizonError(t *testing.T) {
	// Before the first checkpoint the horizon reader returns a wrapped
	// os.ErrNotExist; the backend must surface it (callers distinguish
	// "no checkpoint yet" from a real fault), matching ReadOnlyAppender.Head.
	sentinel := os.ErrNotExist
	b := newHorizonAppenderBackend(stubHorizon{err: sentinel})

	if _, err := b.Head(); !errors.Is(err, sentinel) {
		t.Fatalf("Head err = %v, want wrapping %v", err, sentinel)
	}
	if _, err := b.IntegratedSize(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("IntegratedSize err = %v, want wrapping %v", err, sentinel)
	}
}

func TestHorizonAppenderBackend_RejectsWrites(t *testing.T) {
	b := newHorizonAppenderBackend(stubHorizon{})
	if _, err := b.AppendLeaf(context.Background(), make([]byte, 32)); !errors.Is(err, tessera.ErrReadOnly) {
		t.Fatalf("AppendLeaf err = %v, want tessera.ErrReadOnly", err)
	}
	if err := b.PublishCosignedCheckpoint(context.Background(), types.CosignedTreeHead{}); !errors.Is(err, tessera.ErrReadOnly) {
		t.Fatalf("PublishCosignedCheckpoint err = %v, want tessera.ErrReadOnly", err)
	}
}
