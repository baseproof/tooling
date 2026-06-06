/*
FILE PATH: api/entries_read_test.go

Evidence-based tests for the /v1/entries/{seq}/raw routing decision
matrix. The handler's correctness is encoded entirely in the
"which source serves the bytes?" decision, so tests focus on that:

	WAL state PublicURLer Outcome
	────────────────────────  ──────────────  ─────────────────────────
	StateSequenced (any)           200 OK + WAL bytes inline
	StateManual (any)           200 OK + WAL bytes inline
	StatePending (any)           200 OK + WAL bytes inline (defensive)
	StateShipped configured 302 + public URL
	StateShipped nil 500 (loud misconfig)
	wal.ErrNotFound configured 302 + public URL (post-GC path)
	wal.ErrNotFound nil 500
	Postgres "no row at seq"  —               404
	Invalid seq in path —               400

Tests bypass HTTP middleware by constructing http.Request directly
against the handler closure. Postgres is faked; WAL is faked; the
public-URL composer is faked.
*/
package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/tooling/services/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

type fakeSeqHashLookup struct {
	hashesBySeq   map[uint64][32]byte
	logTimeBySeq  map[uint64]time.Time
	ghostBySeq    map[uint64]bool     // optional; absent ⇒ not a ghost
	primaryByHash map[[32]byte]uint64 // optional; populated for ghost lookups
	err           error
}

func (f *fakeSeqHashLookup) FetchHashBySeq(_ context.Context, seq uint64) ([32]byte, time.Time, bool, bool, error) {
	if f.err != nil {
		return [32]byte{}, time.Time{}, false, false, f.err
	}
	h, ok := f.hashesBySeq[seq]
	if !ok {
		return [32]byte{}, time.Time{}, false, false, nil
	}
	return h, f.logTimeBySeq[seq], f.ghostBySeq[seq], true, nil
}

func (f *fakeSeqHashLookup) FetchPrimarySeqByHash(_ context.Context, hash [32]byte) (uint64, bool, error) {
	if f.err != nil {
		return 0, false, f.err
	}
	primary, ok := f.primaryByHash[hash]
	if !ok {
		return 0, false, nil
	}
	return primary, true, nil
}

type fakeWAL struct {
	mu         sync.Mutex
	wires      map[[32]byte][]byte
	metas      map[[32]byte]wal.Meta
	notFound   map[[32]byte]bool // hashes for which MetaState returns wal.ErrNotFound
	hardErr    error
	readHardEr error
}

func newFakeWAL() *fakeWAL {
	return &fakeWAL{
		wires:    map[[32]byte][]byte{},
		metas:    map[[32]byte]wal.Meta{},
		notFound: map[[32]byte]bool{},
	}
}

func (f *fakeWAL) Read(_ context.Context, hash [32]byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readHardEr != nil {
		return nil, f.readHardEr
	}
	w, ok := f.wires[hash]
	if !ok {
		return nil, fmt.Errorf("fakeWAL: no wire: %w", wal.ErrNotFound)
	}
	cp := make([]byte, len(w))
	copy(cp, w)
	return cp, nil
}

func (f *fakeWAL) MetaState(_ context.Context, hash [32]byte) (wal.Meta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hardErr != nil {
		return wal.Meta{}, f.hardErr
	}
	if f.notFound[hash] {
		return wal.Meta{}, fmt.Errorf("fakeWAL: meta missing: %w", wal.ErrNotFound)
	}
	m, ok := f.metas[hash]
	if !ok {
		return wal.Meta{}, fmt.Errorf("fakeWAL: no meta: %w", wal.ErrNotFound)
	}
	return m, nil
}

type fakePublicURLer struct {
	urlByPair map[uint64]string
	err       error
}

func (f *fakePublicURLer) PublicURL(seq uint64, _ [32]byte) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if u, ok := f.urlByPair[seq]; ok {
		return u, nil
	}
	return fmt.Sprintf("https://test.example/entries/%d/data", seq), nil
}

// discardLogger silences the handler's slog noise during tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError + 1,
	}))
}

func hashFor(name string) [32]byte { return sha256.Sum256([]byte(name)) }

// makeRequest builds a *http.Request with the seq embedded in a way
// the handler can parse. The handler reads r.URL.Path and strips
// the /v1/entries/ prefix + /raw suffix; tests build URLs that
// match that shape.
func makeRequest(seq uint64) *http.Request {
	url := fmt.Sprintf("/v1/entries/%d/raw", seq)
	return httptest.NewRequest(http.MethodGet, url, nil)
}

func newDeps(t *testing.T) (*EntryReadDeps, *fakeSeqHashLookup, *fakeWAL, *fakePublicURLer) {
	t.Helper()
	store := &fakeSeqHashLookup{
		hashesBySeq:   map[uint64][32]byte{},
		logTimeBySeq:  map[uint64]time.Time{},
		ghostBySeq:    map[uint64]bool{},
		primaryByHash: map[[32]byte]uint64{},
	}
	w := newFakeWAL()
	p := &fakePublicURLer{urlByPair: map[uint64]string{}}
	deps := &EntryReadDeps{
		EntryStore:  store,
		WAL:         w,
		PublicURLer: p,
		Logger:      discardLogger(),
	}
	return deps, store, w, p
}

// ─────────────────────────────────────────────────────────────────────
// 1) StateSequenced → 200 OK + inline WAL bytes
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_Sequenced_InlineFromWAL(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("entry-sequenced")
	wire := []byte("the durable wire bytes")
	store.hashesBySeq[42] = hash
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != string(wire) {
		t.Fatalf("body: got %q, want %q", got, wire)
	}
	if rec.Header().Get("X-Source") != "wal" {
		t.Errorf("X-Source: got %q, want wal", rec.Header().Get("X-Source"))
	}
}

func TestRawEntry_Manual_InlineFromWAL(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("entry-manual")
	wire := []byte("retry-exhausted-bytes")
	store.hashesBySeq[7] = hash
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateManual, Sequence: 7}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(7))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if rec.Body.String() != string(wire) {
		t.Fatal("body mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2) StateShipped + PublicURLer → 302 redirect
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_Shipped_RedirectVia302(t *testing.T) {
	deps, store, w, p := newDeps(t)

	hash := hashFor("entry-shipped")
	store.hashesBySeq[100] = hash
	w.metas[hash] = wal.Meta{State: wal.StateShipped, Sequence: 100}
	p.urlByPair[100] = "https://gcs.example/entries/0000000000000064/abcd"

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(100))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://gcs.example/entries/0000000000000064/abcd" {
		t.Fatalf("Location: got %q", got)
	}
	if rec.Header().Get("X-Source") != "bytestore" {
		t.Errorf("X-Source: got %q, want bytestore", rec.Header().Get("X-Source"))
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3) StateShipped + nil PublicURLer → 500 (loud misconfig)
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_Shipped_NoPublicURLer_Returns500(t *testing.T) {
	deps, store, w, _ := newDeps(t)
	deps.PublicURLer = nil

	hash := hashFor("entry-shipped-no-public")
	store.hashesBySeq[1] = hash
	w.metas[hash] = wal.Meta{State: wal.StateShipped, Sequence: 1}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500 (loud misconfig)", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4) wal.ErrNotFound → fall through to bytestore (post-GC path)
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_PostGC_RedirectViaPublicURLer(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("entry-post-gc")
	store.hashesBySeq[500] = hash
	w.notFound[hash] = true // WAL has GC'd this entry

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(500))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if rec.Header().Get("X-Source") != "bytestore" {
		t.Errorf("X-Source mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5) Read-only ledger (WAL=nil) → always redirects
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_NilWAL_AlwaysRedirects(t *testing.T) {
	deps, store, _, _ := newDeps(t)
	deps.WAL = nil // read-only ledger

	hash := hashFor("entry-readonly")
	store.hashesBySeq[42] = hash

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if rec.Header().Get("X-Source") != "bytestore" {
		t.Errorf("X-Source: got %q", rec.Header().Get("X-Source"))
	}
}

// ─────────────────────────────────────────────────────────────────────
// 6) Postgres "no row at seq" → 404
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_NoSeqInIndex_404(t *testing.T) {
	deps, _, _, _ := newDeps(t)

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(99999))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 7) Invalid sequence number in path → 400
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_InvalidSeq_400(t *testing.T) {
	deps, _, _, _ := newDeps(t)

	r := httptest.NewRequest(http.MethodGet, "/v1/entries/not-a-number/raw", nil)
	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8) Postgres transport error → 500
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_PostgresError_500(t *testing.T) {
	deps, store, _, _ := newDeps(t)
	store.err = errors.New("pg: connection refused")

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8b) PG-off read front (1.3d): FetchHashBySeq errors, but SeqHashFallback
//     resolves seq→hash from the entry tile → 302 bytestore redirect.
//     Without a fallback (TestRawEntry_PostgresError_500 above) the same
//     error is a 500 — together they are the +/- guard for the slice.
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_PostgresError_TileFallback_Redirects(t *testing.T) {
	deps, store, _, p := newDeps(t)
	deps.WAL = nil                                   // the read-only ledger runs WAL==nil (redirect-only)
	store.err = errors.New("pg: connection refused") // entry_index unreachable

	const seq = 7
	hash := hashFor("pg-off-entry")
	p.urlByPair[seq] = "https://cdn.example/entries/7/data"
	deps.SeqHashFallback = func(_ context.Context, s uint64) ([32]byte, bool, error) {
		if s == seq {
			return hash, true, nil
		}
		return [32]byte{}, false, nil
	}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(seq))

	if rec.Code != http.StatusFound {
		t.Fatalf("PG-off raw: got %d, want 302 (tile fallback → bytestore redirect)", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://cdn.example/entries/7/data" {
		t.Fatalf("Location: got %q, want the public URL", got)
	}
	if rec.Header().Get("X-Source") != "bytestore" {
		t.Errorf("X-Source: got %q, want bytestore", rec.Header().Get("X-Source"))
	}
}

func TestRawEntry_PostgresError_TileFallback_BeyondHorizon_404(t *testing.T) {
	deps, store, _, _ := newDeps(t)
	deps.WAL = nil
	store.err = errors.New("pg: connection refused")
	// Fallback reports the seq is beyond the cosigned horizon → genuine 404.
	deps.SeqHashFallback = func(_ context.Context, _ uint64) ([32]byte, bool, error) {
		return [32]byte{}, false, nil
	}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(999))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("PG-off raw beyond horizon: got %d, want 404", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 9) WAL transport error (non-NotFound) → 500
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_WALMetaTransportError_500(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("walfail")
	store.hashesBySeq[1] = hash
	w.hardErr = errors.New("badger: I/O error")

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 10) Concurrent-GC race between probe and read → graceful fallback
// ─────────────────────────────────────────────────────────────────────

// MetaState returns StateSequenced (so we go down the inline path),
// but Read returns wal.ErrNotFound (the entry was GC'd between
// probe and read). Handler must fall through to PublicURLer instead
// of 500ing.
func TestRawEntry_ConcurrentGC_FallsThroughToPublicURLer(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("concurrent-gc")
	store.hashesBySeq[42] = hash
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}
	// Note: NO wires[hash] entry — Read returns wal.ErrNotFound.

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302 (fallback after concurrent GC)", rec.Code)
	}
}

// Same scenario but no PublicURLer configured → 500 (no fallback path).
func TestRawEntry_ConcurrentGC_NoPublicURLer_Returns500(t *testing.T) {
	deps, store, w, _ := newDeps(t)
	deps.PublicURLer = nil

	hash := hashFor("concurrent-gc-no-public")
	store.hashesBySeq[42] = hash
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// X-Log-Time + X-Sequence header pin (Tier-2 alignment)
// ─────────────────────────────────────────────────────────────────────
//
// SDK's log.HTTPEntryFetcher reads X-Sequence and X-Log-Time from
// /raw responses (both 200-inline and post-302). Tests pin both
// values so a future refactor that drops X-Log-Time fails here
// rather than silently making the SDK fetcher round-trip to the
// JSON metadata endpoint for LogTime.

func TestRawEntry_Inline_StampsXSequenceAndXLogTime(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("inline-headers")
	wire := []byte("inline bytes")
	logTime := time.Date(2026, 4, 29, 21, 30, 0, 0, time.UTC)
	store.hashesBySeq[42] = hash
	store.logTimeBySeq[42] = logTime
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Sequence"); got != "42" {
		t.Errorf("X-Sequence: got %q, want %q", got, "42")
	}
	wantLT := logTime.Format(time.RFC3339Nano)
	if got := rec.Header().Get("X-Log-Time"); got != wantLT {
		t.Errorf("X-Log-Time: got %q, want %q", got, wantLT)
	}
}

func TestRawEntry_Redirect_StampsXSequenceAndXLogTime(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("redirect-headers")
	logTime := time.Date(2026, 4, 29, 22, 0, 0, 0, time.UTC)
	store.hashesBySeq[7] = hash
	store.logTimeBySeq[7] = logTime
	w.metas[hash] = wal.Meta{State: wal.StateShipped, Sequence: 7}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(7))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("X-Sequence"); got != "7" {
		t.Errorf("X-Sequence: got %q, want %q", got, "7")
	}
	wantLT := logTime.Format(time.RFC3339Nano)
	if got := rec.Header().Get("X-Log-Time"); got != wantLT {
		t.Errorf("X-Log-Time: got %q, want %q", got, wantLT)
	}
}

// X-Log-Time is omitted (not stamped as zero-valued string) when
// the ledger does not have a log_time on file. The SDK fetcher
// tolerates absence with a zero LogTime; the worst possible
// regression would be stamping "0001-01-01T00:00:00Z" which the
// fetcher would parse as a valid (but bogus) timestamp.
func TestRawEntry_OmitsXLogTime_WhenNotPersisted(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("no-log-time")
	wire := []byte("legacy")
	store.hashesBySeq[1] = hash
	// Deliberately leave logTimeBySeq[1] unset → zero time.
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 1}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Sequence"); got != "1" {
		t.Errorf("X-Sequence: got %q, want %q", got, "1")
	}
	if got := rec.Header().Get("X-Log-Time"); got != "" {
		t.Errorf("X-Log-Time should be absent for zero log_time, got %q", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Part II.5 — X-Content-SHA256 + X-Storage-Tier{,-Hint}
// ─────────────────────────────────────────────────────────────────────

// TestRawEntry_Inline_StampsContentSHA256 pins the tamper-evidence
// header on the 200-inline path. The lowercase-hex of the canonical
// hash MUST appear in X-Content-SHA256 so a downloading client can
// hash the bytes it receives and compare on a single round trip.
func TestRawEntry_Inline_StampsContentSHA256(t *testing.T) {
	deps, store, w, _ := newDeps(t)
	hash := hashFor("inline-content-sha256")
	wire := []byte("inline bytes")
	store.hashesBySeq[42] = hash
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	got := rec.Header().Get("X-Content-SHA256")
	want := fmt.Sprintf("%x", hash)
	if got != want {
		t.Errorf("X-Content-SHA256: got %q, want %q", got, want)
	}
	if got := rec.Header().Get("X-Storage-Tier"); got != "hot" {
		t.Errorf("X-Storage-Tier (WAL-served): got %q, want %q", got, "hot")
	}
}

// TestRawEntry_Redirect_StampsContentSHA256 pins the same header on
// the 302 path. The redirect target may be a third-party bucket
// the consumer cannot trust to stamp tamper-evidence headers; the
// ledger stamps the canonical hash on its OWN 302 response so the
// chain of custody is preserved at the ledger boundary.
func TestRawEntry_Redirect_StampsContentSHA256(t *testing.T) {
	deps, store, w, _ := newDeps(t)
	hash := hashFor("redirect-content-sha256")
	store.hashesBySeq[7] = hash
	w.metas[hash] = wal.Meta{State: wal.StateShipped, Sequence: 7}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(7))
	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	got := rec.Header().Get("X-Content-SHA256")
	want := fmt.Sprintf("%x", hash)
	if got != want {
		t.Errorf("X-Content-SHA256: got %q, want %q", got, want)
	}
	if got := rec.Header().Get("X-Storage-Tier"); got != "warm" {
		t.Errorf("X-Storage-Tier (bytestore-redirect): got %q, want %q", got, "warm")
	}
}

// TestRawEntry_StorageTierHintAccepted_Logged confirms the request
// hint is read without affecting routing. Tier-tier hints are
// observational, not load-bearing — routing remains state-driven.
// The test asserts that supplying a hint does NOT change the
// response status or X-Storage-Tier (since the hint cannot
// override the WAL meta-state decision).
func TestRawEntry_StorageTierHintAccepted_DoesNotChangeRouting(t *testing.T) {
	hints := []string{"hot", "warm", "cold", "HOT", " warm ", ""}
	for _, hint := range hints {
		t.Run("hint="+hint, func(t *testing.T) {
			deps, store, w, _ := newDeps(t)
			hash := hashFor("hint-no-route-change-" + hint)
			wire := []byte("inline")
			store.hashesBySeq[42] = hash
			w.wires[hash] = wire
			w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

			req := makeRequest(42)
			if hint != "" {
				req.Header.Set("X-Storage-Tier-Hint", hint)
			}
			rec := httptest.NewRecorder()
			NewRawEntryHandler(deps)(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("hint %q: status got %d, want 200 (hint does NOT override WAL state)",
					hint, rec.Code)
			}
			if got := rec.Header().Get("X-Storage-Tier"); got != "hot" {
				t.Errorf("hint %q: X-Storage-Tier got %q, want \"hot\" (WAL is always hot)",
					hint, got)
			}
		})
	}
}

// TestRawEntry_StorageTierHint_GarbageIgnored verifies invalid
// hint values are silently ignored — they don't fail the request
// and don't influence routing. The handler logs them at Debug
// so an observability pipeline can detect mis-hinting clients.
func TestRawEntry_StorageTierHint_GarbageIgnored(t *testing.T) {
	deps, store, w, _ := newDeps(t)
	hash := hashFor("garbage-hint")
	wire := []byte("inline")
	store.hashesBySeq[1] = hash
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 1}

	req := makeRequest(1)
	req.Header.Set("X-Storage-Tier-Hint", "not-a-real-tier")
	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid hint should not break the request; got %d", rec.Code)
	}
}

// TestNormalizeStorageTierHint pins the parsing contract. The
// normalizer accepts hot/warm/cold (case-insensitive, trimmed) and
// rejects everything else as empty. Pinned because downstream
// observability + (future) routing might key on the canonical form.
func TestNormalizeStorageTierHint(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"hot", "hot"},
		{"warm", "warm"},
		{"cold", "cold"},
		{"HOT", "hot"},
		{"  WARM  ", "warm"},
		{"Cold", "cold"},
		{"", ""},
		{"frozen", ""},
		{"luke-warm", ""},
		{"hot,warm", ""},
	}
	for _, c := range cases {
		t.Run("in="+c.in, func(t *testing.T) {
			got := normalizeStorageTierHint(c.in)
			if got != c.want {
				t.Errorf("normalizeStorageTierHint(%q) = %q, want %q",
					c.in, got, c.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Ghost-leaf redirect path (status=2 row)
// ─────────────────────────────────────────────────────────────────────

// TestRawEntry_Ghost_RedirectsToPrimary verifies that a GET on a
// ghost-row seq returns a 302 to the primary seq's /raw path. This
// is the load-bearing property of the migration-0006 Ghost Leaf
// design: every Tessera-assigned seq must be routable to bytes.
// A 404 here would be cryptographically equivalent to the operator
// destroying evidence (Tessera says the leaf exists; the API says
// it doesn't).
func TestRawEntry_Ghost_RedirectsToPrimary(t *testing.T) {
	deps, store, _, _ := newDeps(t)

	hash := hashFor("dup-hash")
	// Primary entry lives at seq=8; the ghost duplicate Tessera leaf
	// is at seq=16. Both rows share the canonical_hash.
	const primarySeq = 8
	const ghostSeq = 16
	store.hashesBySeq[ghostSeq] = hash
	store.ghostBySeq[ghostSeq] = true
	store.primaryByHash[hash] = primarySeq

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(ghostSeq))

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status: got %d, want 308 (permanent redirect)", rec.Code)
	}
	wantLoc := fmt.Sprintf("/v1/entries/%d/raw", primarySeq)
	if got := rec.Header().Get("Location"); got != wantLoc {
		t.Errorf("Location: got %q, want %q", got, wantLoc)
	}
	if got := rec.Header().Get("X-Source"); got != "ghost-redirect" {
		t.Errorf("X-Source: got %q, want %q", got, "ghost-redirect")
	}
	if got := rec.Header().Get("X-Sequence"); got != fmt.Sprintf("%d", ghostSeq) {
		t.Errorf("X-Sequence: got %q, want %d (the GHOST seq, so clients can correlate with the Tessera tile leaf)",
			got, ghostSeq)
	}
	if got := rec.Header().Get("X-Primary-Sequence"); got != fmt.Sprintf("%d", primarySeq) {
		t.Errorf("X-Primary-Sequence: got %q, want %d", got, primarySeq)
	}
	// Cache-Control must be `public, max-age=31536000, immutable` so
	// CDNs cache the redirect for a year — the ledger is append-only
	// and the ghost→primary mapping is mathematically permanent.
	wantCC := "public, max-age=31536000, immutable"
	if got := rec.Header().Get("Cache-Control"); got != wantCC {
		t.Errorf("Cache-Control: got %q, want %q", got, wantCC)
	}
}

// TestRawEntry_GhostWithoutPrimary_Surfaces500 pins the
// integrity-invariant guard: a ghost row whose canonical_hash has
// no primary row in entry_index is structurally impossible
// (migration 0006's partial unique index requires a primary to
// exist before a ghost can be inserted). If it ever happens, the
// API must surface 500, not 404 or 200, so SRE notices.
func TestRawEntry_GhostWithoutPrimary_Surfaces500(t *testing.T) {
	deps, store, _, _ := newDeps(t)

	hash := hashFor("orphan-ghost")
	store.hashesBySeq[100] = hash
	store.ghostBySeq[100] = true
	// Deliberately leave primaryByHash empty — the ghost has no
	// primary row.

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(100))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500 (orphan ghost row is an integrity violation)",
			rec.Code)
	}
}
