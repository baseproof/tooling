/*
FILE PATH: tests/witness_quorum_signal_test.go

Functional, embedded-Postgres coverage for the witness-quorum SRE signal
(builder.CheckpointLoop.OnWitnessQuorumFailure → gossipnet
baseproof_witness_quorum_failures_total), the Backpressure-Stall trigger.

It drives the REAL CheckpointLoop over a REAL embedded Postgres — real
SMTCommitCursor (smt_root_state), real PgTileFrontier (tile_frontier), real
BuildTilesEmitter (POSIX tiles) — to a committed, durable state, then fails the
witness cosign. Unlike builder's in-memory hook unit test, the loop must
actually reach the cosign step over durable PG state for the signal to fire, so
this pins the end-to-end behaviour:

  - the loop HOLDS — CheckpointOnce returns nil and nothing is published (the
    horizon freezes; ingestion is unaffected);
  - the injected hook fires exactly once;
  - the gossipnet counter, installed exactly as boot installs it, records one
    observation carrying the deployment's network_id label.

Skips (never fails) when the embedded engine can't start (no network for the
one-time binary download, or a root/sandboxed runner).
*/
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	baseprooflog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/types"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	opbuilder "github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/gossipnet"
	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	opstore "github.com/baseproof/tooling/services/ledger/store"
)

// quorumFailWitness models a witness outage: RequestCosignatures always errors,
// the "K-of-N quorum unavailable" condition that HOLDS the horizon.
type quorumFailWitness struct{}

func (quorumFailWitness) RequestCosignatures(context.Context, types.TreeHead) (types.CosignedTreeHead, error) {
	return types.CosignedTreeHead{}, errors.New("witness quorum unavailable: K-of-N unreachable")
}

// witnessQuorumCount returns the summed value of
// baseproof_witness_quorum_failures_total and the network_id label observed on
// it; (-1, "") when the metric is absent.
func witnessQuorumCount(t *testing.T, reader *sdkmetric.ManualReader) (int64, string) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "baseproof_witness_quorum_failures_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric data %T, want Sum[int64]", m.Data)
			}
			var total int64
			var label string
			for _, dp := range sum.DataPoints {
				total += dp.Value
				if v, ok := dp.Attributes.Value(attribute.Key("network_id")); ok {
					label = v.AsString()
				}
			}
			return total, label
		}
	}
	return -1, ""
}

func TestWitnessQuorumSignal_FiresOnHold_EmbeddedPG(t *testing.T) {
	pool := embeddedpg.Start(t, 54332) // t.Skip()s when embedded PG can't boot
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Genesis: drive the SMT tree from empty and reset the durable cursor +
	// frontier singletons (id=1) the loop reads.
	if _, err := pool.Exec(ctx, `UPDATE smt_root_state SET current_root=$1, committed_through_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset smt_root_state: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tile_frontier SET frontier_root=$1, frontier_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset tile_frontier: %v", err)
	}

	leafStore := smt.NewInMemoryLeafStore()
	nodeStore := opstore.NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(leafStore, nodeStore)
	tree.SetRoot(smt.EmptyHash)

	rootStore := opstore.NewSMTRootStateStore(pool)
	tileStore := opstore.NewPosixSMTTileStore(t.TempDir())

	// Commit a real batch so the log is non-empty (a genuinely empty log would
	// HOLD on the genesis gate, never reaching the cosign step). The Merkle gate
	// is satisfied by intgRooter (everything durable), so the loop proceeds to the
	// witness cosign — where the outage fires.
	const logDID = "did:web:witness-quorum.test"
	const n = uint64(5)
	leaves := make([]types.SMTLeaf, n)
	for i := uint64(0); i < n; i++ {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], i)
		key := sha256.Sum256(append([]byte(logDID), b[:]...))
		pos := types.LogPosition{LogDID: logDID, Sequence: i}
		leaves[i] = types.SMTLeaf{Key: key, OriginTip: pos, AuthorityTip: pos}
	}
	if err := tree.SetLeaves(ctx, leaves); err != nil {
		t.Fatalf("SetLeaves: %v", err)
	}
	committedRoot, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("tree.Root: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE smt_root_state SET current_root=$1, committed_through_seq=$2 WHERE id=1`,
		committedRoot[:], int64(n-1),
	); err != nil {
		t.Fatalf("set smt_root_state: %v", err)
	}

	// Install the REAL gossipnet counter on an in-memory reader, exactly as
	// installPrebuilderInstruments does at boot. No other test in this binary
	// installs it, so this install is authoritative.
	provider, reader := baseprooflog.NewInMemoryMeterProvider()
	gossipInstalled := gossipnet.InstallWitnessQuorumFailureCounter(provider.Meter("test"))
	const networkIDHex = "a1b2c3d4e5f60718"

	pub := &intgPublisher{}
	loop := opbuilder.NewCheckpointLoop(
		opstore.NewSMTCommitCursor(rootStore),
		opstore.NewPgTileFrontier(pool),
		opstore.NewBuildTilesEmitter(nodeStore, tileStore),
		intgRooter{}, pub, quorumFailWitness{}, nil, 0, logger,
	)
	// Bind the hook the same way the composition root does, plus a local counter
	// so the assertion holds regardless of the package-singleton's state.
	hookFired := 0
	loop.OnWitnessQuorumFailure(func(ctx context.Context) {
		hookFired++
		gossipnet.IncWitnessQuorumFailure(ctx, networkIDHex)
	})

	// One cycle: read cursor → durable gate → emit tiles → build head → request
	// cosignatures (FAILS) ⇒ HOLD + SRE signal.
	if err := loop.CheckpointOnce(ctx); err != nil {
		t.Fatalf("a witness-quorum hold must not be an error, got %v", err)
	}

	// Functional outcome: the horizon froze — nothing published.
	if len(pub.roots) != 0 {
		t.Fatalf("published %d horizon(s) despite a witness-quorum failure; the horizon must HOLD", len(pub.roots))
	}
	// The injected SRE hook fired exactly once over the real PG-driven loop.
	if hookFired != 1 {
		t.Fatalf("witness-quorum hook fired %d times, want exactly 1", hookFired)
	}
	// And the real gossipnet counter recorded one observation with the network_id
	// label (when this test owns the singleton — always true under -count=1).
	if gossipInstalled {
		got, label := witnessQuorumCount(t, reader)
		if got != 1 {
			t.Errorf("baseproof_witness_quorum_failures_total = %d, want 1", got)
		}
		if label != networkIDHex {
			t.Errorf("network_id label = %q, want %q", label, networkIDHex)
		}
	}
}
