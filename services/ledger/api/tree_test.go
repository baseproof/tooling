package api_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkgossip "github.com/baseproof/baseproof/gossip"
	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/apitypes"
)

// stubTreeHeadFetcher returns a fixed head from both read paths.
type stubTreeHeadFetcher struct{ head *apitypes.CosignedTreeHead }

func (s stubTreeHeadFetcher) Latest(context.Context) (*apitypes.CosignedTreeHead, error) {
	return s.head, nil
}

func (s stubTreeHeadFetcher) GetBySize(context.Context, uint64) (*apitypes.CosignedTreeHead, error) {
	return s.head, nil
}

// TestTreeHeadHandler_ServesReceiptRoot is the direct regression guard
// for the /v1/tree/head receipt_root truncation. The witness-cosigned
// canonical message is RootHash ‖ SMTRoot ‖ ReceiptRoot ‖ TreeSize;
// dropping receipt_root makes the 104-byte payload unreconstructable, so
// every cosignature check fails for any batch carrying Web3 receipts.
// Previously this was only guarded transitively through the anchor
// publisher's fake-server test; this hits the handler directly.
//
// A NON-ZERO ReceiptRoot is load-bearing: a zero value would pass even
// with the field dropped (the zero hash equals the absent-field default).
func TestTreeHeadHandler_ServesReceiptRoot(t *testing.T) {
	rootHash := [32]byte{0x11, 0x22}
	smtRoot := [32]byte{0x33, 0x44}
	receiptRoot := [32]byte{0x55, 0x66, 0x77}

	// The store persists each cosignature as a JSON-marshaled
	// types.WitnessSignature in the signature column; the handler
	// decodes it back into the wire trio. Mirror that here.
	ws := sdktypes.WitnessSignature{SchemeTag: 1, SigBytes: []byte{0xAB, 0xCD}}
	ws.PubKeyID[0] = 0x42
	wsJSON, err := json.Marshal(ws)
	if err != nil {
		t.Fatalf("marshal witness sig: %v", err)
	}

	head := &apitypes.CosignedTreeHead{
		TreeSize:    424242,
		RootHash:    rootHash,
		SMTRoot:     smtRoot,
		ReceiptRoot: receiptRoot,
		HashAlgo:    1,
		Signatures: []apitypes.TreeHeadSignature{
			{Signer: "witness:test", SigAlgo: 1, Signature: wsJSON},
		},
	}

	h := api.NewTreeHeadHandler(&api.TreeDeps{
		TreeHeadStore: stubTreeHeadFetcher{head: head},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/tree/head", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Decode into the canonical gossip wire shape — the contract the
	// anchor + any light client consume.
	var got sdkgossip.WireCosignedTreeHead
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response into WireCosignedTreeHead: %v; body=%s",
			err, rec.Body.String())
	}

	if want := hex.EncodeToString(receiptRoot[:]); got.ReceiptRoot != want {
		t.Errorf("receipt_root = %q, want %q — /v1/tree/head dropped receipt_root (the regression)",
			got.ReceiptRoot, want)
	}
	if want := hex.EncodeToString(rootHash[:]); got.RootHash != want {
		t.Errorf("root_hash = %q, want %q", got.RootHash, want)
	}
	if want := hex.EncodeToString(smtRoot[:]); got.SMTRoot != want {
		t.Errorf("smt_root = %q, want %q", got.SMTRoot, want)
	}
	if got.TreeSize != 424242 {
		t.Errorf("tree_size = %d, want 424242", got.TreeSize)
	}

	// The cosignature must round-trip into the SDK-native wire trio
	// {pub_key_id, scheme_tag, sig_bytes} so a consumer can verify the
	// quorum — not the old hex(json(...)) blob.
	if len(got.Signatures) != 1 {
		t.Fatalf("signatures = %d, want 1", len(got.Signatures))
	}
	sig := got.Signatures[0]
	if sig.SchemeTag != 1 {
		t.Errorf("scheme_tag = %d, want 1", sig.SchemeTag)
	}
	if want := hex.EncodeToString(ws.SigBytes); sig.SigBytes != want {
		t.Errorf("sig_bytes = %q, want %q", sig.SigBytes, want)
	}
	if want := hex.EncodeToString(ws.PubKeyID[:]); sig.PubKeyID != want {
		t.Errorf("pub_key_id = %q, want %q", sig.PubKeyID, want)
	}
}
