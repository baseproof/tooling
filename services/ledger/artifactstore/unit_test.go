package artifactstore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/artifactstore"
)

// Phase 3 — sharded round-trip through the module's Store, including multi-chunk.
func TestStore_Sharded(t *testing.T) {
	ctx := context.Background()
	s := artifactstore.NewStore(artifactstore.NewMemoryBackend())

	// Whole-blob default path.
	data := bytes.Repeat([]byte("judicial-pdf-bytes "), 1000) // ~19 KB, one chunk at 8 MiB
	mcid, err := s.PushSharded(ctx, data)
	if err != nil {
		t.Fatalf("PushSharded: %v", err)
	}
	got, err := s.FetchSharded(ctx, mcid)
	if err != nil {
		t.Fatalf("FetchSharded: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("sharded round-trip mismatch")
	}

	// Multi-chunk: drive the SDK helper through the Store with a small chunk size.
	big := bytes.Repeat([]byte("X"), 5000)
	mcid2, err := storage.PushSharded(ctx, s, big, 256, storage.AlgoSHA256)
	if err != nil {
		t.Fatalf("PushSharded(256): %v", err)
	}
	got2, err := storage.FetchSharded(ctx, s, mcid2)
	if err != nil || !bytes.Equal(got2, big) {
		t.Fatalf("multi-chunk round-trip: err=%v eq=%v", err, bytes.Equal(got2, big))
	}
}

// Phase 4 — token sign/verify error paths (the happy path is in serve_test).
func TestUploadToken_VerifyErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tok := artifactstore.UploadToken{NetworkID: "n", ArtifactCID: "sha256:00", MaxSize: 1, ExpiresAt: time.Now().UnixMicro()}

	bearer, err := artifactstore.SignUploadToken(tok, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := artifactstore.ParseAndVerifyUploadToken(bearer, pub); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if _, err := artifactstore.ParseAndVerifyUploadToken(bearer, otherPub); !errors.Is(err, artifactstore.ErrTokenInvalid) {
		t.Fatalf("wrong key: want ErrTokenInvalid, got %v", err)
	}
	if _, err := artifactstore.ParseAndVerifyUploadToken("no-dot", pub); err == nil {
		t.Fatal("malformed (no dot) should error")
	}
	if _, err := artifactstore.ParseAndVerifyUploadToken("!!!.@@@", pub); err == nil {
		t.Fatal("bad base64 should error")
	}
	// Tampered payload (flip a char in the payload half).
	tampered := "A" + bearer[1:]
	if _, err := artifactstore.ParseAndVerifyUploadToken(tampered, pub); err == nil {
		t.Fatal("tampered payload should fail verification")
	}
}

// NOTE: content-type / MIME validation moved OUT of artifactstore (the store is
// content-agnostic) to the ledger FINISH gate, governed by the on-log
// content-type policy. The validator mechanism is the SDK's
// crypto/artifact.{ContentValidator,ValidatorRegistry,BuildRegistry}, tested in
// the SDK; the FINISH-gate wiring is tested in reservation + admission.
