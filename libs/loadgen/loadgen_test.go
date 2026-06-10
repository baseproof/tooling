package loadgen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestAmendWindow pins the bounded-ring contract the memory bound and the
// streaming oracle both rest on: FIFO eviction returns the oldest, drain returns
// the remainder oldest→newest, and the window never exceeds its capacity.
func TestAmendWindow(t *testing.T) {
	w := newAmendWindow(3)
	mk := func(i uint64) *root { return &root{index: i} }

	if got := w.push(mk(0)); got != nil {
		t.Fatalf("push into space evicted %v, want nil", got)
	}
	w.push(mk(1))
	w.push(mk(2))
	if w.len() != 3 {
		t.Fatalf("len=%d, want 3 (at capacity)", w.len())
	}
	// Full now: pushing 3 evicts 0, then 1, then 2 in FIFO order.
	for want := uint64(0); want < 3; want++ {
		ev := w.push(mk(want + 3))
		if ev == nil || ev.index != want {
			t.Fatalf("push evicted %v, want index %d (FIFO)", ev, want)
		}
		if w.len() != 3 {
			t.Fatalf("len=%d after evicting push, want 3 (bounded)", w.len())
		}
	}
	// Remaining live roots are 3,4,5 (oldest→newest).
	rest := w.drain()
	if len(rest) != 3 || rest[0].index != 3 || rest[2].index != 5 {
		t.Fatalf("drain=%v, want indices [3 4 5]", indices(rest))
	}
	if w.len() != 0 {
		t.Fatalf("len=%d after drain, want 0", w.len())
	}
}

func indices(rs []*root) []uint64 {
	out := make([]uint64, len(rs))
	for i, r := range rs {
		out[i] = r.index
	}
	return out
}

// TestOracleWriter proves the oracle is a header line + one leaf per line (JSONL),
// round-trips, and counts correctly — i.e. it is written incrementally, never as
// one terminal whole-oracle marshal.
func TestOracleWriter(t *testing.T) {
	var buf bytes.Buffer
	ow, err := NewOracleWriter(nopWC{&buf}, OracleHeader{LogDID: "did:web:x", Seed: 1, N: 2, AmendRatio: 0.5})
	if err != nil {
		t.Fatalf("new oracle writer: %v", err)
	}
	want := []LeafRecord{
		{RootIndex: 0, Key: [32]byte{0xaa}, SignerDID: "did:key:zA", OriginTipSeq: 1, AuthorityTipSeq: 1},
		{RootIndex: 1, Key: [32]byte{0xbb}, SignerDID: "did:key:zB", OriginTipSeq: 9, AuthorityTipSeq: 4},
	}
	for _, r := range want {
		if err := ow.Leaf(r); err != nil {
			t.Fatalf("leaf: %v", err)
		}
	}
	if ow.Count() != 2 {
		t.Fatalf("count=%d, want 2", ow.Count())
	}
	if err := ow.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (header + 2 leaves)", len(lines))
	}
	var hdr OracleHeader
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil || hdr.Format != OracleFormat {
		t.Fatalf("header line %q: %v (format=%q)", lines[0], err, hdr.Format)
	}
	for i, ln := range lines[1:] {
		var l jsonlLeaf
		if err := json.Unmarshal([]byte(ln), &l); err != nil {
			t.Fatalf("leaf line %d %q: %v", i, ln, err)
		}
		if l.Key != hex.EncodeToString(want[i].Key[:]) || l.SignerDID != want[i].SignerDID {
			t.Errorf("leaf %d = %+v, want key/did from %+v", i, l, want[i])
		}
	}
}

type nopWC struct{ *bytes.Buffer }

func (nopWC) Close() error { return nil }

// fakeLedger is a minimal in-memory ledger: it accepts entries, assigns a
// monotonic sequence per accepted entry, and answers hash→sequence lookups. With
// one worker, sequence assignment == submission order == build order, so a seeded
// run is fully reproducible (keys included).
func fakeLedger() *httptest.Server {
	var (
		mu     sync.Mutex
		seq    uint64
		byHash = map[string]uint64{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/admission/difficulty", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]uint32{"difficulty": 0})
	})
	mux.HandleFunc("/v1/entries", func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		sum := sha256.Sum256(body)
		h := hex.EncodeToString(sum[:])
		mu.Lock()
		seq++
		byHash[h] = seq
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"canonical_hash": h})
	})
	mux.HandleFunc("/v1/entries-hash/", func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimPrefix(r.URL.Path, "/v1/entries-hash/")
		mu.Lock()
		s, ok := byHash[h]
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]string{"state": "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]uint64{"sequence_number": s})
	})
	return httptest.NewServer(mux)
}

func readAll(r *http.Request) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r.Body)
	return b.Bytes(), err
}

type captureSink struct{ recs []LeafRecord }

func (s *captureSink) Leaf(r LeafRecord) error { s.recs = append(s.recs, r); return nil }

// TestRun_StreamsReproducibleOracle drives the full engine against the fake
// ledger and asserts the three properties that make this the OOM cure and a clean
// client:
//
//   - bounded window forces STREAMING: with K ≪ roots, most records are emitted on
//     eviction mid-run, the rest flushed at end — yet EVERY root is accounted for;
//   - every entry is accounted (roots + amendments == N);
//   - the run is REPRODUCIBLE: same seed ⇒ identical oracle (key, DID, tips per
//     root), proving identities are derived (not random) and nothing is retained.
func TestRun_StreamsReproducibleOracle(t *testing.T) {
	cfg := Config{
		LogDID:        "did:web:baseproof:test",
		N:             300,
		AmendRatio:    0.5,
		DelegateRatio: 0.5, // ~half the entities are delegation-capable ⇒ both authorization styles
		EpochSize:     32,
		Seed:          1,
		Token:         "test-credit", // Mode A: no PoW in the test
		BatchSize:     1,
		Workers:       1, // serial ⇒ sequence assignment is deterministic ⇒ keys reproducible
		AmendWindow:   16,
	}

	// A FRESH ledger per run: each starts its sequence counter at 0, so a
	// reproducible run yields identical creation sequences (hence identical keys),
	// not the same run offset by a carried-over counter.
	run := func() (Stats, []LeafRecord) {
		srv := fakeLedger()
		defer srv.Close()
		c := cfg
		c.LedgerURL = srv.URL
		c.HTTPClient = srv.Client()
		s := &captureSink{}
		st, err := Run(context.Background(), c, s)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return st, s.recs
	}

	st1, recs1 := run()
	if st1.Submitted != cfg.N {
		t.Fatalf("submitted=%d, want %d", st1.Submitted, cfg.N)
	}
	if st1.Roots+st1.Delegations+st1.Amendments != cfg.N {
		t.Fatalf("roots(%d)+delegations(%d)+amendments(%d) != N(%d) — entries unaccounted",
			st1.Roots, st1.Delegations, st1.Amendments, cfg.N)
	}
	// One oracle leaf per root AND per delegation (amendments mutate, don't create).
	if len(recs1) != st1.Roots+st1.Delegations {
		t.Fatalf("oracle emitted %d records, want one per leaf (roots %d + delegations %d)", len(recs1), st1.Roots, st1.Delegations)
	}
	if st1.Roots <= cfg.AmendWindow {
		t.Fatalf("test too weak: roots(%d) must exceed window(%d) so eviction/streaming is exercised", st1.Roots, cfg.AmendWindow)
	}
	// BOTH authorization styles must actually be exercised by this run.
	if st1.DelegatedAmendments == 0 {
		t.Errorf("delegated authority not exercised: delegated amendments=0 (delegations=%d)", st1.Delegations)
	}
	if st1.Amendments-st1.DelegatedAmendments == 0 {
		t.Errorf("same-signer authority not exercised: all %d amendments were delegated", st1.Amendments)
	}

	_, recs2 := run()
	if msg := diffOracles(recs1, recs2); msg != "" {
		t.Fatalf("run not reproducible: %s", msg)
	}
}

// diffOracles compares two runs' oracle records keyed by RootIndex.
func diffOracles(a, b []LeafRecord) string {
	if len(a) != len(b) {
		return fmt.Sprintf("record count %d vs %d", len(a), len(b))
	}
	idx := func(recs []LeafRecord) map[uint64]LeafRecord {
		m := make(map[uint64]LeafRecord, len(recs))
		for _, r := range recs {
			m[r.RootIndex] = r
		}
		return m
	}
	ma, mb := idx(a), idx(b)
	for k, ra := range ma {
		rb, ok := mb[k]
		if !ok {
			return fmt.Sprintf("root %d missing from second run", k)
		}
		if ra.Key != rb.Key || ra.SignerDID != rb.SignerDID ||
			ra.OriginTipSeq != rb.OriginTipSeq || ra.AuthorityTipSeq != rb.AuthorityTipSeq {
			return fmt.Sprintf("root %d differs: %+v vs %+v", k, ra, rb)
		}
	}
	return ""
}
