/*
FILE PATH: store/anchor_source_embedded_test.go

Migration 0020's behavior test, in the 0019 discipline: not "the migration
applies" but "the index SERVES the query" — proven against a real Postgres
(embeddedpg; skips where one cannot be brought up, like the repo's other
embedded-PG tests).

Pins, in order:
 1. the projection column round-trips through BOTH insert paths (single-row
    Insert and the hot-path InsertBatch), with "" landing as SQL NULL;
 2. the by-source keyset page (the exact SQL store/indexes/anchor_source.go
    runs) returns only the requested child's anchors, ascending, cursor-able,
    and never sees NULL rows;
 3. EXPLAIN shows idx_anchor_source serving that query — the partial covering
    index is load-bearing, not decorative (the 0019 lesson: an index that
    doesn't do its documented job is worse than none).
*/
package store_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/store"
)

// distinct from dbintegration (54331) and node-index (54332).
const anchorSourcePGPort = 54333

// the exact keyset SQL from store/indexes/anchor_source.go, inlined so this
// test pins the SHAPE the index must serve (a drift in either place fails).
const anchorSourcePageSQL = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE source_log_did = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC LIMIT $3`

func TestAnchorSourceIndex_Embedded(t *testing.T) {
	pool := embeddedpg.Start(t, anchorSourcePGPort) // t.Skip if no real PG here
	ctx := context.Background()
	es := store.NewEntryStore(pool)

	hb := func(b byte, n uint64) [32]byte {
		var x [32]byte
		x[0], x[1] = b, byte(n)
		x[2] = byte(n >> 8)
		return x
	}
	insert := func(t *testing.T, seq uint64, src string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		row := store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hb(0xA1, seq),
			LogTime:        time.Unix(1_700_000_000+int64(seq), 0).UTC(),
			SignerDID:      "did:key:zChild",
			SourceLogDID:   src,
			Status:         store.StatusLive,
		}
		if err := es.Insert(ctx, tx, row); err != nil {
			t.Fatalf("insert seq=%d: %v", seq, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	childA := "did:baseproof:network:childa"
	childB := "did:baseproof:network:childb"

	// Interleave: A at 0,2,4; B at 1; plain (no source → NULL) at 3,5.
	insert(t, 0, childA)
	insert(t, 1, childB)
	insert(t, 2, childA)
	insert(t, 3, "")
	insert(t, 4, childA)
	insert(t, 5, "")

	// Batch path projects identically (the hot path must not drift from the
	// single-row path): A at 6, NULL at 7.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.InsertBatch(ctx, tx, []store.EntryRow{
		{SequenceNumber: 6, CanonicalHash: hb(0xB2, 6), LogTime: time.Unix(1_700_000_006, 0).UTC(), SignerDID: "did:key:zChild", SourceLogDID: childA, Status: store.StatusLive},
		{SequenceNumber: 7, CanonicalHash: hb(0xB2, 7), LogTime: time.Unix(1_700_000_007, 0).UTC(), SignerDID: "did:key:zChild", Status: store.StatusLive},
	}); err != nil {
		t.Fatalf("insert batch: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	page := func(t *testing.T, src string, startSeq uint64, limit int) []uint64 {
		t.Helper()
		rows, err := pool.Query(ctx, anchorSourcePageSQL, src, startSeq, limit)
		if err != nil {
			t.Fatalf("page query: %v", err)
		}
		defer rows.Close()
		var seqs []uint64
		for rows.Next() {
			var seq int64
			var lt time.Time
			var h []byte
			if err := rows.Scan(&seq, &lt, &h); err != nil {
				t.Fatalf("scan: %v", err)
			}
			seqs = append(seqs, uint64(seq))
		}
		return seqs
	}

	// 2a. Child A sees exactly its anchors, ascending, from both insert paths.
	if got := page(t, childA, 0, 100); fmt.Sprint(got) != "[0 2 4 6]" {
		t.Fatalf("childA full page = %v, want [0 2 4 6]", got)
	}
	// 2b. Keyset cursor: advance past 2 → [4 6]; LIMIT caps the page.
	if got := page(t, childA, 3, 100); fmt.Sprint(got) != "[4 6]" {
		t.Fatalf("childA cursored page = %v, want [4 6]", got)
	}
	if got := page(t, childA, 0, 2); fmt.Sprint(got) != "[0 2]" {
		t.Fatalf("childA limited page = %v, want [0 2]", got)
	}
	// 2c. Child B is isolated; an unknown child sees nothing (NULL rows are
	// invisible — they are not "" matches).
	if got := page(t, childB, 0, 100); fmt.Sprint(got) != "[1]" {
		t.Fatalf("childB page = %v, want [1]", got)
	}
	if got := page(t, "did:baseproof:network:nobody", 0, 100); len(got) != 0 {
		t.Fatalf("unknown child sees %v, want nothing", got)
	}

	// 3. The partial covering index SERVES the query. Disable seqscan so the
	// planner must use an index path if one exists; a missing/unusable
	// idx_anchor_source would fall back and this assertion names the drift.
	if _, err := pool.Exec(ctx, "SET enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, "EXPLAIN "+anchorSourcePageSQL, childA, 0, 100)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if !strings.Contains(plan.String(), "idx_anchor_source") {
		t.Fatalf("by-source page is not served by idx_anchor_source — plan:\n%s", plan.String())
	}
}
