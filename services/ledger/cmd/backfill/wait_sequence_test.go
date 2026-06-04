package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestWaitForSequence_PollsPastPending pins the manifest-integrity fix: the
// /v1/entries-hash/{hash} endpoint returns 200 with {"state":"pending"} and NO
// sequence_number while an entry is WAL-resident but not yet sequenced. The old
// parser decoded any 200 into `SequenceNumber uint64`, so an absent field read as
// 0 — and under high-throughput admission EVERY entity recorded seq 0, collapsing
// every manifest leaf key to DeriveKey(seq 0) and failing the membership audit
// wholesale. waitForSequence must keep polling until sequence_number is present.
func TestWaitForSequence_PollsPastPending(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// First two polls: the WAL-pending shape (200, no sequence_number).
		if atomic.AddInt32(&calls, 1) < 3 {
			_, _ = w.Write([]byte(`{"state":"pending","canonical_hash":"abc"}`))
			return
		}
		_, _ = w.Write([]byte(`{"sequence_number":4242,"canonical_hash":"abc"}`))
	}))
	defer ts.Close()
	hc = ts.Client()

	got, err := waitForSequence(ts.URL, "deadbeef", 10*time.Second)
	if err != nil {
		t.Fatalf("waitForSequence: %v", err)
	}
	if got != 4242 {
		t.Fatalf("waitForSequence = %d, want 4242 — must poll past 200+pending, never record 0", got)
	}
}

// TestWaitForSequence_PendingNeverReturnsZero proves an entry that never leaves
// the pending state TIMES OUT (loud failure) rather than being silently recorded
// as seq 0 — the precise mis-read that produced the all-DeriveKey(seq 0) manifest.
func TestWaitForSequence_PendingNeverReturnsZero(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"pending"}`))
	}))
	defer ts.Close()
	hc = ts.Client()

	if _, err := waitForSequence(ts.URL, "deadbeef", 1200*time.Millisecond); err == nil {
		t.Fatal("want a timeout error for an entry that never sequences; got nil (old code recorded seq 0)")
	}
}

// TestWaitForSequence_SequencedZeroIsValid keeps the genuine seq-0 case working: a
// SEQUENCED entry carries sequence_number=0 (present), which is the real seq of the
// first entry on a fresh log — distinct from an absent field. The pointer decode
// returns 0 here, and must NOT be conflated with pending.
func TestWaitForSequence_SequencedZeroIsValid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sequence_number":0,"canonical_hash":"abc"}`))
	}))
	defer ts.Close()
	hc = ts.Client()

	got, err := waitForSequence(ts.URL, "deadbeef", 5*time.Second)
	if err != nil {
		t.Fatalf("waitForSequence: %v", err)
	}
	if got != 0 {
		t.Fatalf("waitForSequence = %d, want 0 (a sequenced entry with sequence_number:0)", got)
	}
}
