/*
FILE PATH: cmd/ledger/boot/wire/genesis_record.go

#76 — boot-graph adapters for the seq-0 constitution producer (boot/genesis)
and the log-derived witness-set baseline re-root (witnessclient).

The producer RULE lives in boot/genesis (build → submit → await → assert,
SDK-only). These adapters bind it to the live boot graph: they pull the verified
constitution, the ledger signer, the WAL committer, the entry index, and the
composite byte reader off *deps.AppDeps and run the rule. A nil/zero
constitution (no bootstrap document — test/dev paths) is a no-op: those logs are
not in constitutional mode.

Part 2 (re-root): once the constitution is seated at sequence 0, the
witness_sets baseline is derived FROM THAT RECORD rather than from configuration
(witnessclient.RebuildGenesisBaselineFromLog), so the projection becomes a
rebuildable cache of the log. The active admission quorum (d.QuorumManager) is
still seeded from config in wireWitnessQuorum — that is in-memory operational
state needed before serving; only the persisted baseline ROW moves to the log.
*/
package wire

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"

	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/deps"
	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/genesis"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"

	"time"
)

// ensureGenesisRecordFromDeps constructs the producer inputs from the boot
// graph and runs genesis.EnsureRecord. Returns the on-log genesis record bytes
// (for the Part 2 baseline re-root) or nil when the log is not in constitutional
// mode (no bootstrap document). Called from startGoroutines after the sequencer
// goroutine launches and before the HTTP server opens.
func ensureGenesisRecordFromDeps(ctx context.Context, d *deps.AppDeps, cfg Config) ([]byte, error) {
	if cfg.GenesisBootstrapDocument.NetworkName == "" {
		return nil, nil
	}
	pin, err := genesisPin(cfg)
	if err != nil {
		return nil, err
	}
	fetcher := store.NewPostgresEntryFetcher(
		d.PgPool.DB,
		store.NewCompositeByteReader(d.WALCommitter, d.ByteStore, d.Logger),
		cfg.LogDID,
	)
	return genesis.EnsureRecord(ctx, d.WALCommitter, d.EntryStore, fetcher, genesis.Config{
		Doc:       cfg.GenesisBootstrapDocument,
		LogDID:    cfg.LogDID,
		SignerDID: d.LedgerDID,
		Priv:      d.LedgerSignerPriv,
		Pin:       pin,
		Poll:      25 * time.Millisecond,
		Timeout:   30 * time.Second,
		Logger:    d.Logger,
	})
}

// reRootWitnessBaselineFromDeps derives the witness_sets genesis baseline from
// the log's own seq-0 record (#76 Part 2). No-op when record is nil (no
// constitution) or there is no Postgres pool. The set_hash it writes is
// byte-identical to the config derivation it replaces (D4).
func reRootWitnessBaselineFromDeps(ctx context.Context, d *deps.AppDeps, cfg Config, record []byte) error {
	if len(record) == 0 || d.PgPool == nil {
		return nil
	}
	pin, err := genesisPin(cfg)
	if err != nil {
		return err
	}
	recorded, err := witnessclient.RebuildGenesisBaselineFromLog(ctx, d.PgPool.DB, record, pin)
	if err != nil {
		return err
	}
	if recorded {
		d.Logger.InfoContext(ctx, "witness history: genesis baseline re-rooted from log (seq 0)")
	}
	return nil
}

// genesisPin derives the network's TOFU NetworkID pin from the mounted
// constitution — the single derivation both adapters use.
func genesisPin(cfg Config) ([32]byte, error) {
	ids, err := cfg.GenesisBootstrapDocument.IDs()
	if err != nil {
		return [32]byte{}, fmt.Errorf("genesis: derive network identity: %w", err)
	}
	return [32]byte(cosign.NetworkID(ids.NetworkID)), nil
}
