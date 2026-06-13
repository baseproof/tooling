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

	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/store/indexes"
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

// TestEntryKindIndex_FamilyDiscrimination_Embedded pins #114 finding ②: the
// AuthoritativeResolver's five families are DISTINCT kinds and the index
// discriminates each on its own kind — the by-kind derivation model Phase B
// can actually use. The same test proves the ANTI-pattern: keying off the
// shared EntrySchemaShardGenesisV1 cannot tell the families apart (every
// family's schema shard is that one kind), so LatestByKind(SchemaShardGenesis)
// returns one shard regardless of how many families exist. This is the
// concrete reason Phase B must derive per family kind, not via the shard.
func TestEntryKindIndex_FamilyDiscrimination_Embedded(t *testing.T) {
	pool := embeddedpg.Start(t, entryKindPGPort+1) // distinct port from the sibling test
	ctx := context.Background()
	es := store.NewEntryStore(pool)

	families := []string{
		kinds.EntryWitnessEndpointV1,
		kinds.EntryWitnessLabelV1,
		kinds.EntryAuditorRegistrationV1,
		kinds.EntryAuditorScopeAmendmentV1,
		kinds.EntryAnchorTargetV1,
	}
	// One entry per family kind, plus TWO schema shards (the shared kind).
	insert := func(seq uint64, kind string) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var h [32]byte
		h[0], h[1] = 0xD4, byte(seq)
		if err := es.Insert(ctx, tx, store.EntryRow{
			SequenceNumber: seq, CanonicalHash: h,
			LogTime:   time.Unix(1_700_000_000+int64(seq), 0).UTC(),
			SignerDID: "did:key:zOps", Kind: kind, Status: store.StatusLive,
		}); err != nil {
			t.Fatalf("insert seq=%d: %v", seq, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i, fam := range families {
		insert(uint64(i), fam)
	}
	insert(100, kinds.EntrySchemaShardGenesisV1)
	insert(101, kinds.EntrySchemaShardGenesisV1)

	// Drive the REAL production readers (QueryByKind / LatestByKind), not
	// inlined SQL — so this test exercises the actual code Phase B imports,
	// closing the reader-SQL drift gap. The fake reader returns dummy bytes
	// per ref; the readers assemble metadata without deserializing, so seq
	// is the assertion axis.
	api := indexes.NewPostgresQueryAPI(ctx, pool, seqReader{}, "did:baseproof:log:test")

	// Each family is found by ITS OWN kind — exactly one, at its own seq —
	// through both readers. This is the by-kind derivation Phase B uses.
	for i, fam := range families {
		got, ok, err := api.LatestByKind(fam)
		if err != nil {
			t.Fatalf("family %s LatestByKind: %v", fam, err)
		}
		if !ok || got.Position.Sequence != uint64(i) {
			t.Fatalf("family %s: LatestByKind want seq %d, got ok=%v seq=%d", fam, i, ok, got.Position.Sequence)
		}
		page, err := api.QueryByKind(fam, 0, 100)
		if err != nil {
			t.Fatalf("family %s QueryByKind: %v", fam, err)
		}
		if len(page) != 1 || page[0].Position.Sequence != uint64(i) {
			t.Fatalf("family %s: QueryByKind want exactly [seq %d], got %d rows", fam, i, len(page))
		}
	}
	// The shared shard kind cannot discriminate families: LatestByKind
	// returns the latest shard (101) and QueryByKind returns BOTH — never a
	// per-family answer. This is the concrete reason Phase B must NOT key
	// derivation off SchemaShardGenesisV1.
	shardLatest, ok, err := api.LatestByKind(kinds.EntrySchemaShardGenesisV1)
	if err != nil || !ok || shardLatest.Position.Sequence != 101 {
		t.Fatalf("schema shard LatestByKind: want seq 101, got ok=%v seq=%d err=%v", ok, shardLatest.Position.Sequence, err)
	}
	shards, err := api.QueryByKind(kinds.EntrySchemaShardGenesisV1, 0, 100)
	if err != nil || len(shards) != 2 {
		t.Fatalf("schema shard kind is shared: QueryByKind want 2 rows, got %d err=%v", len(shards), err)
	}
}

// seqReader is a minimal bytestore.Reader for the index-reader tests: it
// returns dummy non-nil bytes per ref so QueryByKind/LatestByKind assemble
// successfully (they don't deserialize — the consumer does). Seq is the
// assertion axis.
type seqReader struct{}

func (seqReader) ReadEntry(_ context.Context, seq uint64, _ [32]byte) ([]byte, error) {
	return []byte{byte(seq)}, nil
}

func (seqReader) ReadEntryBatch(_ context.Context, refs []bytestore.EntryRef) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, r := range refs {
		out[i] = []byte{byte(r.Seq)}
	}
	return out, nil
}
