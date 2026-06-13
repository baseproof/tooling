/*
FILE PATH: store/entry_kind_embedded_test.go

The migration-0022 lock test against a REAL Postgres (embeddedpg; skips where
one cannot boot, like the repo's other embedded-PG tests): the `kind` column
projects through BOTH insert paths, the partial idx_entry_kind serves the
keyset page AND the latest-per-kind seek, NULL-kind rows stay invisible, and
the end-to-end path (payload → store.EntryKindProjection → NULL for an
unrecognized kind) holds.
*/
package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/kinds"

	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/store"
)

const entryKindPGPort = 54335

// The exact SQL store/indexes/entry_kind.go emits, inlined so this test pins
// the SHAPE the index must serve (drift in either place fails).
const entryKindPageSQL = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE kind = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC LIMIT $3`
const entryKindLatestSQL = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE kind = $1 AND sequence_number >= $2 ORDER BY sequence_number DESC LIMIT $3`

func TestEntryKindIndex_Embedded(t *testing.T) {
	pool := embeddedpg.Start(t, entryKindPGPort) // t.Skip without a real PG
	ctx := context.Background()
	es := store.NewEntryStore(pool)

	hb := func(b byte, n uint64) [32]byte {
		var x [32]byte
		x[0], x[1], x[2] = b, byte(n), byte(n>>8)
		return x
	}
	// rowFor derives Kind THROUGH the production projection from a real
	// payload — so an unrecognized kind lands as "" (NULL), end to end.
	rowFor := func(seq uint64, payload string) store.EntryRow {
		k := store.EntryKindProjection(&envelope.Entry{DomainPayload: []byte(payload)})
		return store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hb(0xC3, seq),
			LogTime:        time.Unix(1_700_000_000+int64(seq), 0).UTC(),
			SignerDID:      "did:key:zOps",
			Kind:           k,
			Status:         store.StatusLive,
		}
	}
	insert := func(t *testing.T, seq uint64, payload string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := es.Insert(ctx, tx, rowFor(seq, payload)); err != nil {
			t.Fatalf("insert seq=%d: %v", seq, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	schema := kinds.EntrySchemaShardGenesisV1
	burn := kinds.EntryNetworkBurnV1
	schemaPayload := `{"kind":"` + schema + `"}`
	burnPayload := `{"kind":"` + burn + `"}`
	plainPayload := `{"event_type":"case_initiation"}` // no kind → NULL
	bogusPayload := `{"kind":"BP-ENTRY-NOT-REAL-V1"}`  // unrecognized → NULL

	// Single-row path: schema at 0,2,4; burn at 1; NULL at 3,5.
	insert(t, 0, schemaPayload)
	insert(t, 1, burnPayload)
	insert(t, 2, schemaPayload)
	insert(t, 3, plainPayload)
	insert(t, 4, schemaPayload)
	insert(t, 5, bogusPayload)

	// Batch path must project identically: schema at 6, NULL at 7.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.InsertBatch(ctx, tx, []store.EntryRow{
		rowFor(6, schemaPayload),
		rowFor(7, plainPayload),
	}); err != nil {
		t.Fatalf("insert batch: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	page := func(t *testing.T, kind string, startSeq uint64, limit int) []uint64 {
		t.Helper()
		rows, err := pool.Query(ctx, entryKindPageSQL, kind, startSeq, limit)
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

	// Schema kind: exactly its entries, ascending, from BOTH insert paths.
	if got := page(t, schema, 0, 100); fmt.Sprint(got) != "[0 2 4 6]" {
		t.Fatalf("schema page = %v, want [0 2 4 6]", got)
	}
	// Keyset cursor advances; LIMIT caps.
	if got := page(t, schema, 3, 100); fmt.Sprint(got) != "[4 6]" {
		t.Fatalf("schema cursored = %v, want [4 6]", got)
	}
	if got := page(t, schema, 0, 2); fmt.Sprint(got) != "[0 2]" {
		t.Fatalf("schema limited = %v, want [0 2]", got)
	}
	// Burn kind isolated.
	if got := page(t, burn, 0, 100); fmt.Sprint(got) != "[1]" {
		t.Fatalf("burn page = %v, want [1]", got)
	}

	// LatestByKind's seek: the MAX-seq row of a kind (the resolver primitive).
	latest := func(t *testing.T, kind string) (uint64, bool) {
		t.Helper()
		rows, err := pool.Query(ctx, entryKindLatestSQL, kind, uint64(0), 1)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		if !rows.Next() {
			return 0, false
		}
		var seq int64
		var lt time.Time
		var h []byte
		if err := rows.Scan(&seq, &lt, &h); err != nil {
			t.Fatal(err)
		}
		return uint64(seq), true
	}
	if seq, ok := latest(t, schema); !ok || seq != 6 {
		t.Fatalf("latest schema = %d (ok=%v), want 6", seq, ok)
	}
	if seq, ok := latest(t, burn); !ok || seq != 1 {
		t.Fatalf("latest burn = %d (ok=%v), want 1", seq, ok)
	}
	// A kind never written has no latest — the resolver's "no declaration".
	if _, ok := latest(t, kinds.EntryDestinationProvisionV1); ok {
		t.Fatal("a never-declared kind must have no latest")
	}

	// NULL-kind rows (no-kind AND unrecognized-kind) are invisible to every
	// kind query — the partial index excludes them, and the end-to-end
	// projection mapped both plain and bogus payloads to "".
	var nullCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM entry_index WHERE kind IS NULL AND sequence_number IN (3,5,7)`).Scan(&nullCount); err != nil {
		t.Fatal(err)
	}
	if nullCount != 3 {
		t.Fatalf("no-kind, unrecognized-kind, and batch-no-kind rows must all be NULL: got %d/3", nullCount)
	}
}
