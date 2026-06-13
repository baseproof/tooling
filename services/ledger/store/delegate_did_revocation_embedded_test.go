/*
FILE PATH: store/delegate_did_revocation_embedded_test.go

PRE-13b #120 load-bearing confirm against a REAL Postgres (embeddedpg; skips
where one cannot boot): the delegate_did index SURFACES an explicit
revocation entry as the newest row for the DID, so the SDK resolver's
newest-grant-wins can exclude the withdrawn authority. The index does NOT
(and must not) filter revocation itself — that would be fail-open.
*/
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/store/indexes"
)

const delegateDIDRevocationPGPort = 54336

func TestDelegateDID_SurfacesRevocationNewestFirst_Embedded(t *testing.T) {
	pool := embeddedpg.Start(t, delegateDIDRevocationPGPort) // t.Skip without a real PG
	ctx := context.Background()
	es := store.NewEntryStore(pool)

	const delegate = "did:pkh:eip155:1:0xclerk"
	insert := func(seq uint64, b byte) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var h [32]byte
		h[0], h[1] = b, byte(seq)
		if err := es.Insert(ctx, tx, store.EntryRow{
			SequenceNumber: seq, CanonicalHash: h,
			LogTime:   time.Unix(1_700_000_000+int64(seq), 0).UTC(),
			SignerDID: "did:web:origin", DelegateDID: delegate, Status: store.StatusLive,
		}); err != nil {
			t.Fatalf("insert seq=%d: %v", seq, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	insert(10, 0xA1) // the grant
	insert(20, 0xA2) // the revocation (a later delegation entry for the SAME delegate)

	api := indexes.NewPostgresQueryAPI(ctx, pool, seqReader{}, "did:web:ledger.test")
	got, err := api.QueryByDelegateDID(delegate)
	if err != nil {
		t.Fatalf("QueryByDelegateDID: %v", err)
	}
	// Both surfaced; newest (the revocation, seq 20) FIRST — so the SDK
	// resolver's newest-grant-wins sees the revocation and withdraws authority.
	if len(got) != 2 {
		t.Fatalf("index must surface BOTH the grant and the revocation: got %d", len(got))
	}
	if got[0].Position.Sequence != 20 {
		t.Fatalf("the revocation (newest) must be returned FIRST so newest-wins excludes it: got seq %d", got[0].Position.Sequence)
	}
}
