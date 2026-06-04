/*
FILE PATH:

	internal/dbintegration/dbintegration_test.go

DESCRIPTION:

	End-to-end integration tests against a REAL Postgres (embedded-postgres, no
	Docker) — the complex, common flows that unit tests in isolation cannot
	prove: the reservation Store contract on the real engine, the full
	RESERVE -> UPLOAD -> FINISH lifecycle, the #190 commitment-ref persistence
	round-trip, and concurrent-FINISH compare-and-swap safety under real
	transactional contention. Skips (does not fail) when a real PG can't be
	started (e.g. running as root); run as a non-root user via
	scripts/run-db-integration.sh.
*/
package dbintegration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/apitypes"
	"github.com/baseproof/tooling/services/ledger/artifactstore"
	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/reservation"
	"github.com/baseproof/tooling/services/ledger/reservation/reservationtest"
	"github.com/baseproof/tooling/services/ledger/store"
)

func TestPostgresIntegration(t *testing.T) {
	pool := embeddedpg.Start(t, 54331) // t.Skip if no real PG here
	ctx := context.Background()
	truncate := func(table string) {
		if _, err := pool.Exec(ctx, "TRUNCATE "+table); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}

	// 1) The production PostgresStore must satisfy the SAME contract the
	//    in-memory fake passes — verified here against the real engine.
	t.Run("reservation store conformance on real PG", func(t *testing.T) {
		reservationtest.StoreConformance(t, func() reservation.Store {
			truncate("artifact_reservations")
			return reservation.NewPostgresStore(pool)
		})
	})

	// 2) Full RESERVE -> UPLOAD -> FINISH, plus REAP / no-commit-after-expire,
	//    against real PG with a fake clock.
	t.Run("RESERVE-UPLOAD-FINISH lifecycle on real PG", func(t *testing.T) {
		truncate("artifact_reservations")
		clk := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		content := storage.NewInMemoryContentStore()
		mgr := reservation.NewManager(reservation.Config{
			Store: reservation.NewPostgresStore(pool), Content: content,
			SignKey: priv, NetworkID: "netA", TTL: 10 * time.Minute,
			Now: func() time.Time { return clk },
		})

		// RESERVE -> a verifiable token + a PENDING row in PG (keyed by CID).
		data := []byte("exhibit C — forensic report")
		cid := storage.Compute(data)
		tok, err := mgr.Reserve(ctx, reservation.ReserveRequest{
			ContentDigest: cid.String(), ArtifactCID: cid.String(),
			MaxSize: 1 << 20, Owner: "did:court:5",
		})
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if _, err := artifactstore.ParseAndVerifyUploadToken(tok, pub); err != nil {
			t.Fatalf("token does not verify: %v", err)
		}

		// FINISH before upload -> incomplete; no commit.
		if _, err := mgr.Finish(ctx, cid.String()); err == nil {
			t.Fatal("finish before upload should be incomplete")
		}

		// UPLOAD then FINISH -> committed (row in PG is committed).
		if err := content.Push(ctx, cid, data); err != nil {
			t.Fatal(err)
		}
		if r, err := mgr.Finish(ctx, cid.String()); err != nil || r.Status != reservation.StatusCommitted {
			t.Fatalf("finish: status=%s err=%v", r.Status, err)
		}
		got, _ := reservation.NewPostgresStore(pool).Get(ctx, cid.String())
		if got.Status != reservation.StatusCommitted {
			t.Fatalf("PG row status=%s, want committed", got.Status)
		}

		// A second reservation, abandoned -> reaped to EXPIRED, no commit after.
		data2 := []byte("never uploaded")
		cid2 := storage.Compute(data2)
		_, _ = mgr.Reserve(ctx, reservation.ReserveRequest{
			ContentDigest: cid2.String(), ArtifactCID: cid2.String(), MaxSize: 1 << 20, Owner: "did:court:5",
		})
		clk = clk.Add(11 * time.Minute)
		if n, err := mgr.Reap(ctx, 100); err != nil || n != 1 {
			t.Fatalf("reap: n=%d err=%v", n, err)
		}
		_ = content.Push(ctx, cid2, data2) // bytes arrive late...
		if _, err := mgr.Finish(ctx, cid2.String()); err == nil {
			t.Fatal("no commit-after-expire: finish on an EXPIRED reservation must fail")
		}
		exp, _ := reservation.NewPostgresStore(pool).Get(ctx, cid2.String())
		if exp.Status != reservation.StatusExpired {
			t.Fatalf("PG row status=%s, want expired", exp.Status)
		}
	})

	// 3) The #190 fix end-to-end on real PG: the ref-shaped derivation_commitments
	//    row round-trips (validates migration 0015 + the store SQL).
	t.Run("commitment-ref persistence round-trip on real PG", func(t *testing.T) {
		truncate("derivation_commitments")
		cs := store.NewCommitmentStore(pool)
		want := apitypes.CommitmentRow{
			RangeStartSeq: 1, RangeEndSeq: 1000,
			PriorSMTRoot: [32]byte{0xaa}, PostSMTRoot: [32]byte{0xbb},
			MutationsCID:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			MutationCount: 873,
		}
		if err := cs.Insert(ctx, want); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := cs.QueryBySequence(ctx, 500) // 500 is within [1,1000]
		if err != nil || got == nil {
			t.Fatalf("query: err=%v got=%v", err, got)
		}
		if got.MutationsCID != want.MutationsCID || got.MutationCount != want.MutationCount {
			t.Fatalf("round-trip: got cid=%q count=%d, want cid=%q count=%d",
				got.MutationsCID, got.MutationCount, want.MutationsCID, want.MutationCount)
		}
		if got.PriorSMTRoot != want.PriorSMTRoot || got.PostSMTRoot != want.PostSMTRoot {
			t.Fatalf("roots mismatch")
		}
	})

	// 4) The hard, common case: many clients FINISH the same reservation at once.
	//    The UPDATE ... WHERE status=from CAS must let exactly one commit; every
	//    caller sees a consistent committed result, none errors, no double-write.
	t.Run("concurrent FINISH is CAS-safe on real PG", func(t *testing.T) {
		truncate("artifact_reservations")
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		content := storage.NewInMemoryContentStore()
		mgr := reservation.NewManager(reservation.Config{
			Store: reservation.NewPostgresStore(pool), Content: content,
			SignKey: priv, NetworkID: "netA", TTL: time.Hour,
		})
		data := []byte("contended artifact")
		cid := storage.Compute(data)
		if _, err := mgr.Reserve(ctx, reservation.ReserveRequest{
			ContentDigest: cid.String(), ArtifactCID: cid.String(), MaxSize: 1 << 20, Owner: "did:court:5",
		}); err != nil {
			t.Fatal(err)
		}
		if err := content.Push(ctx, cid, data); err != nil {
			t.Fatal(err)
		}

		const n = 16
		var wg sync.WaitGroup
		errs := make([]error, n)
		statuses := make([]reservation.Status, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				r, err := mgr.Finish(ctx, cid.String())
				errs[i], statuses[i] = err, r.Status
			}(i)
		}
		wg.Wait()
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("concurrent finisher %d errored: %v", i, errs[i])
			}
			if statuses[i] != reservation.StatusCommitted {
				t.Fatalf("concurrent finisher %d saw status %s, want committed", i, statuses[i])
			}
		}
		final, _ := reservation.NewPostgresStore(pool).Get(ctx, cid.String())
		if final.Status != reservation.StatusCommitted {
			t.Fatalf("final PG status=%s, want committed", final.Status)
		}
	})
}
