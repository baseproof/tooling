// FILE PATH: services/auditor/internal/store/rotation_scan_cursor.go
//
// PostgresRotationScanCursor — the durable per-log watermark for the
// witnessrotation.ScanReconciler: every position below the cursor has been
// scanned (exactly once across the cursor's lifetime) against a cosigned
// target. The cursor is what turns the year-15 reconciliation cost from
// O(history) per pass into O(new entries) per pass.
//
// Like the rotation journal, this is a rebuildable projection, not bedrock:
// resetting a cursor to 0 merely makes the next pass re-scan (and idempotently
// re-journal) the whole committed prefix.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/baseproof/tooling/libs/witnessrotation"
)

// PostgresRotationScanCursor persists scan watermarks. Construct via
// NewPostgresRotationScanCursor; call Migrate at boot.
type PostgresRotationScanCursor struct {
	db *sql.DB
}

// Static conformance: the scan reconciler's cursor seam.
var _ witnessrotation.CursorStore = (*PostgresRotationScanCursor)(nil)

// NewPostgresRotationScanCursor wraps an open pool (shared with the gossip
// store + journals; the caller owns it).
func NewPostgresRotationScanCursor(db *sql.DB) (*PostgresRotationScanCursor, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: nil *sql.DB", ErrInvalidConfig)
	}
	return &PostgresRotationScanCursor{db: db}, nil
}

const schemaSQLRotationScanCursor = `
CREATE TABLE IF NOT EXISTS witness_rotation_scan_cursor (
    log_did       TEXT        NOT NULL PRIMARY KEY,
    scanned_until BIGINT      NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// Migrate creates the cursor table if absent. Idempotent.
func (c *PostgresRotationScanCursor) Migrate(ctx context.Context) error {
	if _, err := c.db.ExecContext(ctx, schemaSQLRotationScanCursor); err != nil {
		return fmt.Errorf("witness_rotation_scan_cursor: migrate: %w", err)
	}
	return nil
}

// ScanCursor returns the watermark for logDID; 0 when never scanned.
func (c *PostgresRotationScanCursor) ScanCursor(ctx context.Context, logDID string) (uint64, error) {
	var until int64
	err := c.db.QueryRowContext(ctx,
		`SELECT scanned_until FROM witness_rotation_scan_cursor WHERE log_did = $1`,
		logDID).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("witness_rotation_scan_cursor: read %q: %w", logDID, err)
	}
	return uint64(until), nil
}

// SetScanCursor upserts the watermark. Monotonic by contract — the GREATEST
// guard makes a concurrent/replayed older pass a no-op rather than a coverage
// regression.
func (c *PostgresRotationScanCursor) SetScanCursor(ctx context.Context, logDID string, scannedUntil uint64) error {
	if _, err := c.db.ExecContext(ctx,
		`INSERT INTO witness_rotation_scan_cursor (log_did, scanned_until, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (log_did) DO UPDATE
		   SET scanned_until = GREATEST(witness_rotation_scan_cursor.scanned_until, EXCLUDED.scanned_until),
		       updated_at    = now()`,
		logDID, int64(scannedUntil)); err != nil {
		return fmt.Errorf("witness_rotation_scan_cursor: upsert %q: %w", logDID, err)
	}
	return nil
}
