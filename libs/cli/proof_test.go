package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
)

// TestProof_GenerateAndWriteV2 exercises the generate → encode → file path (the
// testable core) with a fake gather, asserting a faithful v2 round-trip: the file
// `proof --out` writes decodes back as the same v2 proof. The live gather wiring
// (bootstrap fetch, ledger reader, NewBundleGather) is exercised by the platform
// e2e against a real ledger.
func TestProof_GenerateAndWriteV2(t *testing.T) {
	ctx := context.Background()
	doc := mustBootstrapDoc(t)

	proof, err := generateProof(ctx, &fakeStandaloneGather{doc: doc, quorumK: 1}, 1)
	if err != nil {
		t.Fatalf("generateProof: %v", err)
	}
	if proof.Format != sdkbundle.FormatV2 {
		t.Fatalf("format = %q, want v2", proof.Format)
	}

	path := filepath.Join(t.TempDir(), "out.proof")
	if err := writeProofFile(proof, path); err != nil {
		t.Fatalf("writeProofFile: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written proof: %v", err)
	}
	dec, err := sdkbundle.DecodeStandalone(raw)
	if err != nil {
		t.Fatalf("decode written proof: %v", err)
	}
	if dec.Format != sdkbundle.FormatV2 || dec.NetworkID != proof.NetworkID {
		t.Errorf("written proof is not a faithful v2 round-trip: format=%q nid=%x", dec.Format, dec.NetworkID)
	}
}
