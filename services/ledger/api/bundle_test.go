/*
FILE PATH: api/bundle_test.go

Tests for the Part II.1 /v1/bundle/{seq} handler.

Coverage:
  - Missing/malformed smt_key → 400.
  - Malformed seq → 400.
  - Nil deps → 503.
  - Empty bootstrap → 404.
  - Happy path → 200 + JCS-canonical bundle bytes that the SDK's
    Decode reproduces field-for-field.
*/
package api

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// fakeBundleEntries implements BundleEntryFetcher returning a
// fixed envelope-canonical byte sequence + log time.
type fakeBundleEntries struct {
	wire    []byte
	logTime time.Time
	err     error
}

func (f *fakeBundleEntries) FetchEntryBytes(_ context.Context, seq uint64) ([]byte, time.Time, error) {
	return f.wire, f.logTime, f.err
}

type fakeBundleHeads struct{ head types.CosignedTreeHead }

func (f *fakeBundleHeads) FetchCosignedHead(_ context.Context, _ uint64) (types.CosignedTreeHead, error) {
	return f.head, nil
}

type fakeBundleInclusion struct{ proof *types.MerkleProof }

func (f *fakeBundleInclusion) FetchInclusionProof(_ context.Context, _, _ uint64) (*types.MerkleProof, error) {
	return f.proof, nil
}

type fakeBundleSMT struct{ proof types.SMTProof }

func (f *fakeBundleSMT) FetchSMTProof(_ context.Context, _, _ [32]byte) (types.SMTProof, error) {
	return f.proof, nil
}

type fakeBundleWitnessHash struct{ hash [32]byte }

func (f *fakeBundleWitnessHash) FetchWitnessSetHash(_ context.Context, _ types.CosignedTreeHead) ([32]byte, error) {
	return f.hash, nil
}

func bundleFixtureDeps(t *testing.T) (*BundleDeps, []byte) {
	t.Helper()
	// Construct a minimal envelope so OnLogEntryLeafHash produces a
	// deterministic on-log leaf hash the SDK BuildBundle will bind. The
	// ledger feeds Tessera the 32-byte EntryIdentity as leaf data, so the
	// committed leaf is H(0x00 || SHA-256(canonical)) = OnLogEntryLeafHash,
	// NOT EntryLeafHashBytes(canonical) = H(0x00 || canonical).
	hdr := envelope.ControlHeader{
		SignerDID:   "did:web:signer.example",
		Destination: "did:web:dest.example",
		EventTime:   1700000000,
	}
	entry, err := envelope.NewUnsignedEntry(hdr, []byte("payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: "did:web:signer.example",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     []byte{0x01, 0x02, 0x03},
	}}
	wire, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	leafHash := envelope.OnLogEntryLeafHash(wire)

	doc := validBootstrap(t)

	var smtKey [32]byte
	for i := range smtKey {
		smtKey[i] = byte(i)
	}

	var smtRoot [32]byte
	for i := range smtRoot {
		smtRoot[i] = byte(0xAA)
	}

	// SMT proof with a non-nil TerminalLeaf so VerifyBundle's
	// "no terminal" preflight check would pass downstream.
	leafPos := types.LogPosition{LogDID: "did:web:signer.example", Sequence: 0}
	smtLeaf := &types.SMTLeaf{Key: smtKey, OriginTip: leafPos, AuthorityTip: leafPos}

	deps := &BundleDeps{
		Bootstrap: doc,
		Entries:   &fakeBundleEntries{wire: wire, logTime: time.Unix(1700000000, 0)},
		Heads: &fakeBundleHeads{head: types.CosignedTreeHead{
			TreeHead: types.TreeHead{
				TreeSize: 1,
				RootHash: [32]byte{0xBB},
				SMTRoot:  smtRoot,
			},
			Signatures: []types.WitnessSignature{{
				PubKeyID:  [32]byte{0xCC},
				SchemeTag: 0x01,
				SigBytes:  []byte{0xDD},
			}},
		}},
		Inclusion: &fakeBundleInclusion{proof: &types.MerkleProof{
			LeafPosition: 0,
			LeafHash:     leafHash,
			TreeSize:     1,
			Siblings:     nil,
		}},
		SMT: &fakeBundleSMT{proof: types.SMTProof{
			Key:          smtKey,
			TerminalKind: types.SMTTerminalLeaf,
			TerminalLeaf: smtLeaf,
		}},
		Witnesses: &fakeBundleWitnessHash{hash: [32]byte{0xEE}},
	}
	return deps, wire
}

// ─────────────────────────────────────────────────────────────────────
// Param validation
// ─────────────────────────────────────────────────────────────────────

func TestBundleHandler_MissingSmtKeyReturns400(t *testing.T) {
	deps, _ := bundleFixtureDeps(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle/{seq}", NewBundleHandler(deps))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/bundle/0", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing smt_key)", rec.Code)
	}
}

func TestBundleHandler_BadSmtKeyReturns400(t *testing.T) {
	deps, _ := bundleFixtureDeps(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle/{seq}", NewBundleHandler(deps))
	for _, bad := range []string{"too_short", "ZZ" + strings.Repeat("00", 31)} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/v1/bundle/0?smt_key="+bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("smt_key %q: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestBundleHandler_BadSeqReturns400(t *testing.T) {
	deps, _ := bundleFixtureDeps(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle/{seq}", NewBundleHandler(deps))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/bundle/notanumber?smt_key="+strings.Repeat("00", 32), nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestBundleHandler_NilDepsReturns503(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle/{seq}", NewBundleHandler(nil))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/bundle/0?smt_key="+strings.Repeat("00", 32), nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestBundleHandler_EmptyBootstrapReturns404(t *testing.T) {
	deps := &BundleDeps{} // zero bootstrap
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle/{seq}", NewBundleHandler(deps))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/bundle/0?smt_key="+strings.Repeat("00", 32), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Happy path
// ─────────────────────────────────────────────────────────────────────

func TestBundleHandler_HappyPath(t *testing.T) {
	deps, wire := bundleFixtureDeps(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle/{seq}", NewBundleHandler(deps))

	var smtKey [32]byte
	for i := range smtKey {
		smtKey[i] = byte(i)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/bundle/0?smt_key="+hex.EncodeToString(smtKey[:]), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", cc)
	}
	// Round-trip through the SDK Decode.
	got, err := sdkbundle.Decode(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("sdkbundle.Decode: %v", err)
	}
	if got.Format != sdkbundle.FormatV1 {
		t.Errorf("Format = %q, want %q", got.Format, sdkbundle.FormatV1)
	}
	if got.Entry.Sequence != 0 {
		t.Errorf("Entry.Sequence = %d, want 0", got.Entry.Sequence)
	}
	if string(got.Entry.WireBytes) != string(wire) {
		t.Errorf("Entry.WireBytes drift")
	}
	if got.NetworkID == ([32]byte{}) {
		t.Error("NetworkID = zero (BuildBundle should populate)")
	}
}

func TestBundleHandler_PropagatesFetchError(t *testing.T) {
	deps, _ := bundleFixtureDeps(t)
	boom := errors.New("storage offline")
	deps.Entries = &fakeBundleEntries{err: boom}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle/{seq}", NewBundleHandler(deps))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/bundle/0?smt_key="+strings.Repeat("00", 32), nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

var _ = network.SignaturePolicy{} // keep import stable
