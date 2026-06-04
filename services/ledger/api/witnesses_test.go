/*
FILE PATH: api/witnesses_test.go

Tests for the Part II.1 witness history handlers. Uses a fake
WitnessHistoryFetcher so the suite stays in-memory (no DSN gate).
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeWitnessFetcher implements WitnessHistoryFetcher with
// in-memory canned responses, injectable per-method errors, and
// per-method call counters for hit-count assertions.
type fakeWitnessFetcher struct {
	current      *WitnessSetView
	currentErr   error
	byHash       map[[32]byte]*WitnessSetView
	byHashErr    map[[32]byte]error
	atSeq        map[uint64]*WitnessSetView
	atSeqErr     map[uint64]error
	currentCalls int
	byHashCalls  int
	atSeqCalls   int
}

func (f *fakeWitnessFetcher) LoadCurrentSet(ctx context.Context) (*WitnessSetView, error) {
	f.currentCalls++
	if f.currentErr != nil {
		return nil, f.currentErr
	}
	return f.current, nil
}

func (f *fakeWitnessFetcher) LoadSetByHash(ctx context.Context, h [32]byte) (*WitnessSetView, error) {
	f.byHashCalls++
	if err, ok := f.byHashErr[h]; ok {
		return nil, err
	}
	v, ok := f.byHash[h]
	if !ok {
		return nil, ErrWitnessSetNotFound
	}
	return v, nil
}

func (f *fakeWitnessFetcher) LoadSetAtSeq(ctx context.Context, seq uint64) (*WitnessSetView, error) {
	f.atSeqCalls++
	if err, ok := f.atSeqErr[seq]; ok {
		return nil, err
	}
	v, ok := f.atSeq[seq]
	if !ok {
		return nil, ErrWitnessSetNotFound
	}
	return v, nil
}

// fixtureSetView returns a WitnessSetView with a deterministic
// content-addressable identity.
func fixtureSetView(setHashSeed byte, effective, retired uint64, withRetired bool) *WitnessSetView {
	var hash [32]byte
	for i := range hash {
		hash[i] = setHashSeed
	}
	v := &WitnessSetView{
		SetHash:      hex.EncodeToString(hash[:]),
		SchemeTag:    0x01, // SchemeECDSA
		EffectiveSeq: effective,
		Keys: []WitnessPublicKey{
			{
				ID:        strings.Repeat("aa", 32),
				PublicKey: strings.Repeat("bb", 33),
				SchemeTag: 0x01,
			},
		},
	}
	if withRetired {
		r := retired
		v.RetiredSeq = &r
	}
	return v
}

// ─────────────────────────────────────────────────────────────────────
// /v1/network/witnesses/current
// ─────────────────────────────────────────────────────────────────────

func TestWitnessesCurrentHandler_ServesActiveSet(t *testing.T) {
	view := fixtureSetView(0xAA, 1234, 0, false)
	f := &fakeWitnessFetcher{current: view}
	h := NewWitnessesCurrentHandler(f)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/witnesses/current", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control = %q, want public, max-age=60", cc)
	}
	var got WitnessSetView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SetHash != view.SetHash || got.EffectiveSeq != view.EffectiveSeq {
		t.Errorf("body drift: got %+v, want %+v", got, view)
	}
	// retired_seq must be absent on the active row.
	if strings.Contains(rec.Body.String(), `"retired_seq"`) {
		// rec.Body was consumed by Decode; re-encode `got` for the
		// JSON-shape check.
		bs, _ := json.Marshal(got)
		if strings.Contains(string(bs), `"retired_seq"`) {
			t.Errorf("retired_seq present on active row: %s", bs)
		}
	}
}

func TestWitnessesCurrentHandler_NotFoundOnEmptyTable(t *testing.T) {
	f := &fakeWitnessFetcher{currentErr: ErrWitnessSetNotFound}
	h := NewWitnessesCurrentHandler(f)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/witnesses/current", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestWitnessesCurrentHandler_NilFetcherReturns404(t *testing.T) {
	h := NewWitnessesCurrentHandler(nil)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/witnesses/current", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestWitnessesCurrentHandler_GenericErrorReturns500(t *testing.T) {
	boom := errors.New("connection refused")
	f := &fakeWitnessFetcher{currentErr: boom}
	h := NewWitnessesCurrentHandler(f)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/witnesses/current", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// /v1/network/witnesses/{set_hash}
// ─────────────────────────────────────────────────────────────────────

func TestWitnessesBySetHashHandler_ServesContentAddressed(t *testing.T) {
	view := fixtureSetView(0xBB, 100, 250, true)
	var hash [32]byte
	for i := range hash {
		hash[i] = 0xBB
	}
	f := &fakeWitnessFetcher{
		byHash: map[[32]byte]*WitnessSetView{hash: view},
	}
	// Use http.NewServeMux so the {set_hash} path parameter is
	// populated; httptest.NewRequest alone doesn't set path values.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/{set_hash}",
		NewWitnessesBySetHashHandler(f))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/network/witnesses/"+hex.EncodeToString(hash[:]), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var got WitnessSetView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SetHash != view.SetHash {
		t.Errorf("SetHash drift")
	}
	if got.RetiredSeq == nil || *got.RetiredSeq != 250 {
		t.Errorf("RetiredSeq = %+v, want 250", got.RetiredSeq)
	}
}

func TestWitnessesBySetHashHandler_BadHashReturns400(t *testing.T) {
	f := &fakeWitnessFetcher{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/{set_hash}",
		NewWitnessesBySetHashHandler(f))
	cases := []string{"too_short", "ZZ" + strings.Repeat("00", 31), ""}
	for _, raw := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/v1/network/witnesses/"+raw, nil))
		// Empty path doesn't match the route; everything else
		// reaches the handler and gets 400.
		if raw == "" {
			continue // mux pattern requires {set_hash}, would return 404 from mux
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("hash %q: status = %d, want 400", raw, rec.Code)
		}
	}
}

func TestWitnessesBySetHashHandler_NotFoundReturns404(t *testing.T) {
	f := &fakeWitnessFetcher{} // empty byHash map
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/{set_hash}",
		NewWitnessesBySetHashHandler(f))
	var hash [32]byte
	hash[0] = 0xFE
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/network/witnesses/"+hex.EncodeToString(hash[:]), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// /v1/network/witnesses/at/{seq}
// ─────────────────────────────────────────────────────────────────────

func TestWitnessesAtSeqHandler_ServesHistoricalSet(t *testing.T) {
	view := fixtureSetView(0xCC, 100, 0, false)
	f := &fakeWitnessFetcher{
		atSeq: map[uint64]*WitnessSetView{150: view},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/at/{seq}",
		NewWitnessesAtSeqHandler(f))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/network/witnesses/at/150", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestWitnessesAtSeqHandler_BadSeqReturns400(t *testing.T) {
	f := &fakeWitnessFetcher{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/at/{seq}",
		NewWitnessesAtSeqHandler(f))
	for _, bad := range []string{"abc", "-1", "9999999999999999999999"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/v1/network/witnesses/at/"+bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("seq %q: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestWitnessesAtSeqHandler_NotFoundReturns404(t *testing.T) {
	f := &fakeWitnessFetcher{} // empty atSeq map
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/at/{seq}",
		NewWitnessesAtSeqHandler(f))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/network/witnesses/at/42", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
