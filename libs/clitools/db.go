package clitools

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// DB wraps a *sql.DB with tools-specific helpers.
// The Postgres driver must be imported in the binary (cmd/):
//
//	import _ "github.com/lib/pq"
type DB struct {
	Pool *sql.DB
}

// NewDB opens a connection pool. connStr is a Postgres connection string:
//
//	"postgres://localhost:5432/court_tools?sslmode=disable"
func NewDB(connStr string) (*DB, error) {
	pool, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	pool.SetMaxOpenConns(25)
	pool.SetMaxIdleConns(5)
	pool.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close shuts down the connection pool. Safe to call on a *DB
// whose Pool was never opened (test stubs construct *DB literals
// without a real pool); the nil guard returns nil cleanly.
func (db *DB) Close() error {
	if db == nil || db.Pool == nil {
		return nil
	}
	return db.Pool.Close()
}

// PingContext verifies the underlying connection pool is reachable.
// Delegates to *sql.DB.PingContext. Used by probe handlers
// (cmd/aggregator) for /readyz checks.
func (db *DB) PingContext(ctx context.Context) error {
	return db.Pool.PingContext(ctx)
}

// GetWatermark returns the last scanned position for a log.
func (db *DB) GetWatermark(logDID string) (uint64, error) {
	var pos uint64
	err := db.Pool.QueryRow(
		`SELECT last_position FROM scan_watermarks WHERE log_did = $1`,
		logDID,
	).Scan(&pos)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return pos, err
}

// UpdateWatermark sets the last scanned position for a log.
func (db *DB) UpdateWatermark(logDID string, pos uint64) error {
	_, err := db.Pool.Exec(`
		INSERT INTO scan_watermarks (log_did, last_position, last_scan_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (log_did) DO UPDATE
		SET last_position = $2, last_scan_at = NOW()
	`, logDID, pos)
	return err
}

// ExecContext is a pass-through for direct SQL execution.
func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.Pool.ExecContext(ctx, query, args...)
}

// QueryRowContext is a pass-through for single-row queries.
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return db.Pool.QueryRowContext(ctx, query, args...)
}

// QueryContext is a pass-through for multi-row queries.
func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return db.Pool.QueryContext(ctx, query, args...)
}
