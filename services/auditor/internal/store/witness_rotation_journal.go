// FILE PATH: services/auditor/internal/store/witness_rotation_journal.go
//
// PostgresWitnessRotationJournal — AT-1: the durable, per-log witness-set
// rotation chain that powers historical witness-set reconstruction
// (ZT-SCN-02, the Year-15 scenario).
//
// # WHY THIS EXISTS
//
// The auditor's libs/auditing WitnessSetRegistry tracks only the LIVE
// (current) witness set per log — it applies each verified rotation in place
// and forgets the chain. That makes "what set was authoritative at position N
// in year 1?" unanswerable, which defeats ZT-SCN-02: a bundle sealed in year 1
// must verify in year 15 against the YEAR-1 quorum, never silently against the
// long-rotated modern set.
//
// This journal is the materialized projection of the on-log rotation entries
// (the LOG is the source of truth; the self-contained WitnessRotationFinding is
// the verifiable carrier the reconciler hands us). It persists each verified
// rotation as a position-bearing types.WitnessRotationRecord so the SDK's
// witness.WitnessSetAt can deterministically reconstruct the authoritative set
// at any historical asOf — even with the ledger, witnesses, and the
// auditor-of-the-day all gone (ZT-SCN-07).
//
// # SCHEMA
//
//	witness_rotation_records (
//	  log_did          TEXT        NOT NULL,
//	  effective_seq    BIGINT      NOT NULL,   -- EffectivePos.Sequence (PROVEN)
//	  rotation_payload BYTEA       NOT NULL,   -- witness.EncodeWitnessRotationPayload bytes
//	  recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
//	  PRIMARY KEY (log_did, effective_seq)
//	)
//
// A rotation's (log_did, effective_seq) IS its identity — re-receiving the same
// rotation (gossip is at-least-once) is an idempotent no-op (ON CONFLICT DO
// NOTHING). The wire payload is stored verbatim (the SDK codec round-trips it
// byte-exactly), not a re-encoded struct, so the 15-year record is stable
// across SDK refactors (ZT-SCN-12 spirit).
//
// # RETENTION — REBUILDABLE CACHE, NOT BEDROCK
//
// Unlike the heads journal (permanent, ZT-IMM-02/03), this table is a
// materialized PROJECTION of the on-log rotation entries — the LOG is the
// source of truth. The rows are SAFE TO DELETE (see PurgeFor): the chain is
// rebuilt by re-walking the log — re-ingesting the on-log
// BP-ENTRY-WITNESS-ROTATION-PAYLOAD-V1 entries (carried verbatim in their
// self-contained findings), re-verifying each, and re-recording via the
// idempotent RecordRotation. It is a CQRS read-model (ZT-CQRS-03), not
// permanent bedrock — losing it costs a rebuild, never evidence. (The chain is
// tiny anyway: rotations are rare relative to the 10B-entry log.)
//
// KEY DEPENDENCIES:
//   - libs/monitoring: RotationJournal (the reconciler seam this satisfies).
//   - baseproof/witness: EncodeWitnessRotationPayload / DecodeWitnessRotationPayload
//     (the canonical wire codec) and WitnessSetAt (the reconstruction primitive).
//   - baseproof/crypto/cosign: WitnessKeySet (the genesis seed + the result).
//   - baseproof/types: WitnessRotationRecord, LogPosition.
package store

import (
	"context"
	"fmt"

	"database/sql"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/tooling/libs/monitoring"
)

// PostgresWitnessRotationJournal persists the verified witness-set rotation
// chain per log. Construct via NewPostgresWitnessRotationJournal; call Migrate
// at boot. Mirrors PostgresHeadsJournal (idempotent Migrate, NEVER DELETE).
type PostgresWitnessRotationJournal struct {
	db *sql.DB
}

// Static conformance: this satisfies the reconciler's RotationJournal seam, so
// every verified rotation the reconciler processes is durably journaled.
var _ monitoring.RotationJournal = (*PostgresWitnessRotationJournal)(nil)

// NewPostgresWitnessRotationJournal wraps an open pool. The store does NOT take
// ownership — the caller (auditor boot wire) owns it and shares it with the
// gossip PostgresStore + heads journal.
func NewPostgresWitnessRotationJournal(db *sql.DB) (*PostgresWitnessRotationJournal, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: nil *sql.DB", ErrInvalidConfig)
	}
	return &PostgresWitnessRotationJournal{db: db}, nil
}

const schemaSQLWitnessRotationJournal = `
CREATE TABLE IF NOT EXISTS witness_rotation_records (
    log_did          TEXT        NOT NULL,
    effective_seq    BIGINT      NOT NULL,
    rotation_payload BYTEA       NOT NULL,
    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (log_did, effective_seq)
);
CREATE INDEX IF NOT EXISTS witness_rotation_records_log_seq
    ON witness_rotation_records (log_did, effective_seq ASC);`

// Migrate creates the witness_rotation_records table + index if absent.
// Idempotent; safe to call on every boot.
func (j *PostgresWitnessRotationJournal) Migrate(ctx context.Context) error {
	if _, err := j.db.ExecContext(ctx, schemaSQLWitnessRotationJournal); err != nil {
		return fmt.Errorf("witness_rotation_records: migrate: %w", err)
	}
	return nil
}

// RecordRotation implements monitoring.RotationJournal. Persists one verified
// rotation as a position-bearing record. Idempotent on (log_did,
// effective_seq) — a rotation's proven position is its identity, so an
// at-least-once gossip redelivery is a harmless no-op (ZT-SDK-14).
//
// Fail-closed on a null EffectivePos: historical reconstruction requires a
// concrete proven position per record (mirrors WitnessSetAt's own guard).
func (j *PostgresWitnessRotationJournal) RecordRotation(ctx context.Context, record types.WitnessRotationRecord) error {
	if record.EffectivePos.IsNull() {
		return fmt.Errorf("witness_rotation_records: refusing to journal record with null EffectivePos")
	}
	payload, err := witness.EncodeWitnessRotationPayload(record.Rotation)
	if err != nil {
		return fmt.Errorf("witness_rotation_records: encode rotation: %w", err)
	}
	if _, err := j.db.ExecContext(ctx,
		`INSERT INTO witness_rotation_records (log_did, effective_seq, rotation_payload)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (log_did, effective_seq) DO NOTHING`,
		record.EffectivePos.LogDID,
		int64(record.EffectivePos.Sequence),
		payload,
	); err != nil {
		return fmt.Errorf("witness_rotation_records: insert: %w", err)
	}
	return nil
}

// RecordsFor returns the full rotation chain for logDID, sorted ascending by
// EffectivePos.Sequence — exactly the sorted form witness.WitnessSetAt requires.
func (j *PostgresWitnessRotationJournal) RecordsFor(ctx context.Context, logDID string) ([]types.WitnessRotationRecord, error) {
	rows, err := j.db.QueryContext(ctx,
		`SELECT effective_seq, rotation_payload
		   FROM witness_rotation_records
		  WHERE log_did = $1
		  ORDER BY effective_seq ASC`,
		logDID)
	if err != nil {
		return nil, fmt.Errorf("witness_rotation_records: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []types.WitnessRotationRecord
	for rows.Next() {
		var seq int64
		var payload []byte
		if err := rows.Scan(&seq, &payload); err != nil {
			return nil, fmt.Errorf("witness_rotation_records: scan: %w", err)
		}
		rot, err := witness.DecodeWitnessRotationPayload(payload)
		if err != nil {
			return nil, fmt.Errorf("witness_rotation_records: decode seq=%d: %w", seq, err)
		}
		out = append(out, types.WitnessRotationRecord{
			Rotation:     rot,
			EffectivePos: types.LogPosition{LogDID: logDID, Sequence: uint64(seq)},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("witness_rotation_records: rows: %w", err)
	}
	return out, nil
}

// WitnessSetAt reconstructs the *cosign.WitnessKeySet that was authoritative on
// logDID at asOf, by replaying the journaled rotation chain from genesisSet via
// the SDK's witness.WitnessSetAt — the Year-15 reproducibility primitive
// (ZT-SCN-02). The walk re-verifies each rotation under the prior set, so the
// result is trustless given a trusted genesis.
//
//   - genesisSet: the year-1 set from the network bootstrap (FS-ACT-01's public
//     genesis witness list); the auditor holds these in app.WitnessSets.
//   - asOf: MANDATORY (ZT-IMM-01) — the SDK rejects a null LogPosition. Pass the
//     position the evidence was sealed at (e.g., the bundle entry's position),
//     never an implicit "latest".
//
// Returns the genesis set unchanged when asOf precedes the first rotation
// (the year-1 set IS the genesis set).
func (j *PostgresWitnessRotationJournal) WitnessSetAt(
	ctx context.Context,
	genesisSet *cosign.WitnessKeySet,
	logDID string,
	asOf types.LogPosition,
) (*cosign.WitnessKeySet, error) {
	records, err := j.RecordsFor(ctx, logDID)
	if err != nil {
		return nil, err
	}
	return witness.WitnessSetAt(genesisSet, records, asOf)
}

// PurgeFor deletes the journaled rotation chain for logDID. The journal is a
// rebuildable cache, not bedrock (see the RETENTION note): dropping it is safe
// because the chain is re-materialized by re-walking the log's on-log rotation
// entries through the idempotent RecordRotation. Used for ops cache-reset and
// by tests proving the delete -> rebuild cycle.
func (j *PostgresWitnessRotationJournal) PurgeFor(ctx context.Context, logDID string) error {
	if _, err := j.db.ExecContext(ctx,
		`DELETE FROM witness_rotation_records WHERE log_did = $1`, logDID); err != nil {
		return fmt.Errorf("witness_rotation_records: purge %q: %w", logDID, err)
	}
	return nil
}
