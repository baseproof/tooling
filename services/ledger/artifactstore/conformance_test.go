package artifactstore_test

import (
	"testing"

	"github.com/baseproof/baseproof/storage/storagetest"

	"github.com/baseproof/tooling/services/ledger/artifactstore"
)

// Every backend the module ships must pass the SDK's frozen ContentStore
// conformance suite (round-trip, not-found, verify-on-read 1-bit-flip,
// pin/delete optionality, UploadPresigner-if-supported).

func TestMemoryStore_Conformance(t *testing.T) {
	storagetest.ContentStoreConformance(t, artifactstore.NewStore(artifactstore.NewMemoryBackend()))
}

func TestPosixStore_Conformance(t *testing.T) {
	b, err := artifactstore.NewPosixBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixBackend: %v", err)
	}
	storagetest.ContentStoreConformance(t, artifactstore.NewStore(b))
}
