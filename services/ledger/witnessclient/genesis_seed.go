/*
FILE PATH: witnessclient/genesis_seed.go

Genesis-baseline reconciliation for the witness_sets history table.

The witness-set HISTORY is log-driven: every rotation is a verified
on-log entry (rotation_handler.go appends it, then projects the row).
The GENESIS set has no rotation entry — its authority is the network
trust root itself: the bootstrap document whose JCS-canonical bytes
hash to the NetworkID. Migration 0014 reserved the row shape for it
(effective_seq = 0, rotation_event_id NULL, "the genesis baseline")
but nothing ever wrote that row. Consequences on a never-rotated
network: /v1/network/witnesses/{current,at} serve 404 while the
ledger cosigns heads with that very set; worse, the FIRST rotation's
"retire prior" UPDATE matches nothing on an empty table, so the
genesis era [0, first-rotation) stays uncovered forever.

SeedGenesisBaseline closes both. The row is DERIVED from the trust
root (bootstrap witness DIDs + NetworkID + quorum K) — never
operator-seeded, no off-log authority introduced — and reconciled
idempotently at boot:

  - empty table                      → insert genesis ACTIVE
    (retired_seq NULL);
  - rows exist, none cover seq 0     → insert genesis RETIRED at the
    earliest recorded
    effective_seq (backfills the
    genesis-era hole);
  - a row with effective_seq = 0     → no-op (already recorded).

set_hash is the row-identity hash — the WitnessKeySet's SetHash()
over the JCS-canonical {network_id, quorum_k, witnesses[]} — so the
seeded row is byte-identical to what every other consumer (gossip,
/v1/network/witnesses/*, the bundle witness_set_hint) computes.
*/
package witnessclient

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// GenesisCosignSchemeTag is the genesis cosign scheme: ECDSA (0x01). did:key
// witness resolution is secp256k1-only (quorum.LoadWitnessKeys), so the genesis
// roster never carries a BLS key — those join on-log via a verified rotation.
const GenesisCosignSchemeTag byte = 0x01

// SeedGenesisBaseline reconciles the genesis witness set into the
// witness_sets history table (see the file header for the three
// cases). genesis is the keyset constructed from the bootstrap's
// genesis witness DIDs under the network's NetworkID + quorum K;
// keys is the resolved roster it was built from; schemeTag is the
// genesis cosign scheme (ECDSA — did:key resolution is
// secp256k1-only, see quorum.LoadWitnessKeys).
//
// Returns true when a row was inserted, false when the table already
// carried a genesis-era record. Safe to call on every boot: the
// statement is a single idempotent INSERT guarded by NOT EXISTS and
// ON CONFLICT DO NOTHING (a rotation landing concurrently can at
// worst make this boot's insert a no-op).
func SeedGenesisBaseline(
	ctx context.Context,
	db *pgxpool.Pool,
	genesis *cosign.WitnessKeySet,
	keys []types.WitnessPublicKey,
	schemeTag byte,
) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("witness/genesis-baseline: nil db pool")
	}
	if genesis == nil || len(keys) == 0 {
		return false, fmt.Errorf("witness/genesis-baseline: nil/empty genesis set")
	}
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return false, fmt.Errorf("witness/genesis-baseline: marshal keys: %w", err)
	}
	setHash := genesis.SetHash()

	// One statement, three cases:
	//   empty table          → MIN(...) is NULL → retired_seq NULL (active);
	//   earliest row at E>0  → retired_seq = E (genesis era [0,E) backfilled);
	//   any effective_seq=0  → NOT EXISTS fails (no-op).
	// ON CONFLICT DO NOTHING covers the exotic rotate-back-to-genesis case
	// (same set_hash already present at effective_seq > 0) and concurrent
	// inserts — skipping is correct, corrupting history is not.
	tag, err := db.Exec(ctx, `
		INSERT INTO witness_sets
		    (set_hash, keys_json, scheme_tag, effective_seq, retired_seq, rotation_event_id)
		SELECT $1, $2, $3, 0,
		       (SELECT MIN(effective_seq) FROM witness_sets WHERE effective_seq > 0),
		       NULL
		WHERE NOT EXISTS (SELECT 1 FROM witness_sets WHERE effective_seq = 0)
		ON CONFLICT DO NOTHING`,
		setHash[:], keysJSON, int16(schemeTag),
	)
	if err != nil {
		return false, fmt.Errorf("witness/genesis-baseline: persist: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RebuildGenesisBaselineFromLog reconciles the genesis baseline row by deriving
// the witness set FROM THE LOG'S OWN seq-0 constitution record (#76 Part 2),
// not from configuration. This is the projection-as-cache-of-the-log re-root:
// verifier.GenesisSetFromRecord re-verifies the record against the TOFU pin
// (strict decode → canonical-subset hash → genesis ceremony, via the
// LoadVerifiedBootstrap chokepoint) and reads the constitutional quorum K from
// it, so the resulting row is rebuildable from the log alone — no off-log trust
// input, no caller-supplied K.
//
// One home: the ledger boot path (after the constitution is seated at sequence
// 0) and rebuild-projection (after the tile walk repopulates entry_index) both
// seed through here. The set_hash it produces is byte-identical to the
// config-derived baseline (genesis DIDs + NetworkID + quorum K hash to the same
// content-addressable identity); the parity test pins that they cannot diverge.
//
// record is the genesis entry's domain payload (the BP-ENTRY-NETWORK-GENESIS-V1
// JSON); pin is the network's TOFU NetworkID. Returns true when a row was
// inserted, false when the table already carried a genesis-era record.
func RebuildGenesisBaselineFromLog(
	ctx context.Context,
	db *pgxpool.Pool,
	record []byte,
	pin [32]byte,
) (bool, error) {
	genesisSet, err := verifier.GenesisSetFromRecord(record, pin, nil)
	if err != nil {
		return false, fmt.Errorf("witness/genesis-baseline: re-root from log: %w", err)
	}
	return SeedGenesisBaseline(ctx, db, genesisSet, genesisSet.Keys(), GenesisCosignSchemeTag)
}
