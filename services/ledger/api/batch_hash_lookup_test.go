/*
FILE PATH: api/batch_hash_lookup_test.go

Tests for POST /v1/entries-hash/batch (Part II.3).

Scope: per-hash decision matrix, request validation (empty/oversized/
malformed-hex), response-shape stability. The single-hash variant
(NewHashLookupHandler) is exercised by queries_test.go; this file
covers the batch-specific wrappers (request parsing, cap enforcement,
result aggregation) and confirms each hash routes through the
SAME WAL→entry_index decision as the singular endpoint.
*/
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/tooling/services/ledger/wal"
)

// fakeBatchEntryStore is a minimal EntryStore satisfier with
// per-hash predetermined outcomes. Used by tests that exercise the
// sequenced-state fall-through (where the singular tests cannot
// reach without a real Postgres).
type fakeBatchEntryStore struct {
	seqByHash map[[32]byte]uint64
	notFound  map[[32]byte]bool
	hardErr   error
}

func (f *fakeBatchEntryStore) FetchByHash(_ context.Context, hash [32]byte) (uint64, bool, error) {
	if f.hardErr != nil {
		return 0, false, f.hardErr
	}
	if f.notFound[hash] {
		return 0, false, nil
	}
	if s, ok := f.seqByHash[hash]; ok {
		return s, true, nil
	}
	return 0, false, nil
}

func (f *fakeBatchEntryStore) FetchHashBySeq(_ context.Context, _ uint64) ([32]byte, time.Time, bool, bool, error) {
	return [32]byte{}, time.Time{}, false, false, errors.New("fakeBatchEntryStore.FetchHashBySeq not used")
}

func (f *fakeBatchEntryStore) FetchPrimarySeqByHash(_ context.Context, _ [32]byte) (uint64, bool, error) {
	return 0, false, errors.New("fakeBatchEntryStore.FetchPrimarySeqByHash not used")
}

// batchWAL is a multi-hash WAL fake — per-hash state injection.
type batchWAL struct {
	stateByHash map[[32]byte]wal.EntryState
	seqByHash   map[[32]byte]uint64
	notFound    map[[32]byte]bool
	hardErr     error
}

func (b *batchWAL) Read(_ context.Context, _ [32]byte) ([]byte, error) {
	return nil, errors.New("batchWAL.Read not used")
}

func (b *batchWAL) MetaState(_ context.Context, hash [32]byte) (wal.Meta, error) {
	if b.hardErr != nil {
		return wal.Meta{}, b.hardErr
	}
	if b.notFound[hash] {
		return wal.Meta{}, wal.ErrNotFound
	}
	if s, ok := b.stateByHash[hash]; ok {
		return wal.Meta{State: s, Sequence: b.seqByHash[hash]}, nil
	}
	return wal.Meta{}, wal.ErrNotFound
}

// postBatch helper — builds + executes a POST against the batch
// handler with the supplied JSON body.
func postBatch(t *testing.T, deps *QueryDeps, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/entries-hash/batch", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewBatchHashLookupHandler(deps)(rec, r)
	return rec
}

// hexOf converts a [32]byte to lowercase hex (the wire shape).
func hexOf(h [32]byte) string { return hex.EncodeToString(h[:]) }

// ─────────────────────────────────────────────────────────────────────
// Per-hash decision matrix
// ─────────────────────────────────────────────────────────────────────

// TestBatchHashLookup_HappyPath_MixedStates exercises every per-hash
// outcome in ONE request — pending, manual, sequenced, not_found —
// so the result array's ordering + state-classification invariants
// are pinned in a single shot.
func TestBatchHashLookup_HappyPath_MixedStates(t *testing.T) {
	pendingHash := sha256.Sum256([]byte("pending"))
	manualHash := sha256.Sum256([]byte("manual"))
	seqHash := sha256.Sum256([]byte("seq-42"))
	missHash := sha256.Sum256([]byte("never-admitted"))

	deps := &QueryDeps{
		Logger: discardLogger(),
		WAL: &batchWAL{
			stateByHash: map[[32]byte]wal.EntryState{
				pendingHash: wal.StatePending,
				manualHash:  wal.StateManual,
				seqHash:     wal.StateSequenced,
			},
			seqByHash: map[[32]byte]uint64{seqHash: 42},
			notFound:  map[[32]byte]bool{missHash: true},
		},
		EntryStore: &fakeBatchEntryStore{
			seqByHash: map[[32]byte]uint64{seqHash: 42},
			notFound:  map[[32]byte]bool{missHash: true},
		},
	}

	rec := postBatch(t, deps, map[string]any{
		"hashes": []string{hexOf(pendingHash), hexOf(manualHash), hexOf(seqHash), hexOf(missHash)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Results []hashBatchResult `json:"results"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Results) != 4 {
		t.Fatalf("results len = %d, want 4", len(resp.Results))
	}
	// Pin per-hash outcome AND ordering (results[i] corresponds
	// to hashes[i]).
	wantStates := []string{"pending", "manual", "sequenced", "not_found"}
	for i, want := range wantStates {
		if resp.Results[i].State != want {
			t.Errorf("results[%d].state = %q, want %q (hash=%s)",
				i, resp.Results[i].State, want, resp.Results[i].CanonicalHash)
		}
	}
	// Sequence field MUST be populated for sequenced, absent (zero)
	// for everything else.
	if resp.Results[2].Sequence != 42 {
		t.Errorf("sequenced result sequence = %d, want 42", resp.Results[2].Sequence)
	}
	for _, i := range []int{0, 1, 3} {
		if resp.Results[i].Sequence != 0 {
			t.Errorf("non-sequenced result[%d] has Sequence=%d (should be 0)",
				i, resp.Results[i].Sequence)
		}
	}
}

// TestBatchHashLookup_EmptyArrayRejected — an empty batch is a
// client bug, not a valid empty result.
func TestBatchHashLookup_EmptyArrayRejected(t *testing.T) {
	deps := &QueryDeps{Logger: discardLogger()}
	rec := postBatch(t, deps, map[string]any{"hashes": []string{}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (empty array)", rec.Code)
	}
}

// TestBatchHashLookup_CapEnforced — request body containing more
// than MaxBatchHashLookup hashes rejected as 413.
func TestBatchHashLookup_CapEnforced(t *testing.T) {
	deps := &QueryDeps{Logger: discardLogger()}
	tooMany := make([]string, MaxBatchHashLookup+1)
	dummy := sha256.Sum256([]byte("dummy"))
	for i := range tooMany {
		tooMany[i] = hexOf(dummy)
	}
	rec := postBatch(t, deps, map[string]any{"hashes": tooMany})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 (over cap)", rec.Code)
	}
}

// TestBatchHashLookup_AtCapAccepted — exactly MaxBatchHashLookup
// hashes is the boundary; MUST be accepted.
func TestBatchHashLookup_AtCapAccepted(t *testing.T) {
	hashes := make([]string, MaxBatchHashLookup)
	notFound := make(map[[32]byte]bool, MaxBatchHashLookup)
	for i := range hashes {
		h := sha256.Sum256([]byte{byte(i / 256), byte(i % 256)})
		hashes[i] = hexOf(h)
		notFound[h] = true
	}
	deps := &QueryDeps{
		Logger: discardLogger(),
		WAL: &batchWAL{
			stateByHash: map[[32]byte]wal.EntryState{}, // empty: every hash misses
			notFound:    notFound,
		},
		EntryStore: &fakeBatchEntryStore{notFound: notFound},
	}
	rec := postBatch(t, deps, map[string]any{"hashes": hashes})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d at cap (boundary), want 200", rec.Code)
	}
	var resp struct {
		Results []hashBatchResult `json:"results"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Results) != MaxBatchHashLookup {
		t.Errorf("results len = %d, want %d", len(resp.Results), MaxBatchHashLookup)
	}
}

// TestBatchHashLookup_MalformedHexFailsClosed — a single bad-hex
// hash fails the whole request with 400. Partial-success would let
// a client probe the ledger one-hash-at-a-time hidden inside a
// "good batch" — defensive.
func TestBatchHashLookup_MalformedHexFailsClosed(t *testing.T) {
	good := sha256.Sum256([]byte("good"))
	deps := &QueryDeps{Logger: discardLogger()}
	rec := postBatch(t, deps, map[string]any{
		"hashes": []string{hexOf(good), "not-hex"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (malformed hash)", rec.Code)
	}
}

// TestBatchHashLookup_WrongLengthHexFailsClosed — 64 hex chars is
// the mandatory length (32 bytes). Anything else is malformed.
func TestBatchHashLookup_WrongLengthHexFailsClosed(t *testing.T) {
	deps := &QueryDeps{Logger: discardLogger()}
	short := "deadbeef" // 8 hex chars = 4 bytes
	rec := postBatch(t, deps, map[string]any{"hashes": []string{short}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (short hash)", rec.Code)
	}
	long := strings.Repeat("ab", 33) // 66 hex chars = 33 bytes
	rec = postBatch(t, deps, map[string]any{"hashes": []string{long}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (long hash)", rec.Code)
	}
}

// TestBatchHashLookup_MalformedBodyRejected — non-JSON body, JSON
// with unknown fields, missing fields → 400.
func TestBatchHashLookup_MalformedBodyRejected(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"non-JSON", "{not json"},
		{"unknown-field", `{"hashes":["aa"],"extra":1}`},
		{"empty-body", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost,
				"/v1/entries-hash/batch",
				bytes.NewReader([]byte(c.body)))
			r.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			deps := &QueryDeps{Logger: discardLogger()}
			NewBatchHashLookupHandler(deps)(rec, r)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %q: status = %d, want 400", c.name, rec.Code)
			}
		})
	}
}

// TestBatchHashLookup_WALTransportError_DegradesToNotFound pins the
// observability contract: an infrastructure failure on ONE hash
// degrades to state=not_found for that hash (logged at Error). The
// batch endpoint cannot per-hash-surface a 500 without compromising
// the response array's all-or-nothing usefulness.
func TestBatchHashLookup_WALTransportError_DegradesToNotFound(t *testing.T) {
	hash := sha256.Sum256([]byte("transport-fail"))
	deps := &QueryDeps{
		Logger:     discardLogger(),
		WAL:        &batchWAL{hardErr: errors.New("badger: I/O error")},
		EntryStore: &fakeBatchEntryStore{notFound: map[[32]byte]bool{hash: true}},
	}
	rec := postBatch(t, deps, map[string]any{"hashes": []string{hexOf(hash)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degradation is per-hash, not request-level)", rec.Code)
	}
	var resp struct {
		Results []hashBatchResult `json:"results"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Results[0].State != "not_found" {
		t.Errorf("state = %q, want \"not_found\" (WAL infrastructure-error degradation)",
			resp.Results[0].State)
	}
}

// TestBatchHashLookup_NilWAL_FallsThroughToEntryIndex — read-only
// ledger has no WAL; the batch handler skips the probe and goes
// straight to entry_index for every hash.
func TestBatchHashLookup_NilWAL_FallsThroughToEntryIndex(t *testing.T) {
	seqHash := sha256.Sum256([]byte("seq-100"))
	deps := &QueryDeps{
		Logger:     discardLogger(),
		WAL:        nil,
		EntryStore: &fakeBatchEntryStore{seqByHash: map[[32]byte]uint64{seqHash: 100}},
	}
	rec := postBatch(t, deps, map[string]any{"hashes": []string{hexOf(seqHash)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Results []hashBatchResult `json:"results"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Results[0].State != "sequenced" || resp.Results[0].Sequence != 100 {
		t.Errorf("got state=%q seq=%d; want sequenced/100",
			resp.Results[0].State, resp.Results[0].Sequence)
	}
}

// TestBatchHashLookup_PreservesOrderUnderRepeats pins that a batch
// with duplicate hashes returns the same outcome for each occurrence,
// at the matching positions in the result array. This guards
// against an over-cleverness that might dedupe at the API layer
// and corrupt the client's positional indexing.
func TestBatchHashLookup_PreservesOrderUnderRepeats(t *testing.T) {
	h := sha256.Sum256([]byte("dup"))
	deps := &QueryDeps{
		Logger: discardLogger(),
		WAL: &batchWAL{
			stateByHash: map[[32]byte]wal.EntryState{h: wal.StateSequenced},
			seqByHash:   map[[32]byte]uint64{h: 99},
		},
		EntryStore: &fakeBatchEntryStore{seqByHash: map[[32]byte]uint64{h: 99}},
	}
	rec := postBatch(t, deps, map[string]any{
		"hashes": []string{hexOf(h), hexOf(h), hexOf(h)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Results []hashBatchResult `json:"results"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Results) != 3 {
		t.Fatalf("results len = %d; want 3 (no dedup)", len(resp.Results))
	}
	for i, r := range resp.Results {
		if r.State != "sequenced" || r.Sequence != 99 {
			t.Errorf("dup[%d]: state=%q seq=%d; want sequenced/99",
				i, r.State, r.Sequence)
		}
	}
}
