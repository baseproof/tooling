package store

import (
	"context"
	"testing"
	"time"
)

// TestInitPool_LazyConnect_BootsWithoutPostgres is the +/- guard for 1.3c
// (PG-optional boot): with LazyConnect, InitPool returns a usable pool even when
// Postgres is unreachable — so the read front boots and serves its object-store
// surface during a PG outage. Without it, the eager Ping makes boot fatal (the
// pre-fix behavior the reader could not tolerate).
func TestInitPool_LazyConnect_BootsWithoutPostgres(t *testing.T) {
	// 127.0.0.1:1 refuses immediately (nothing listens) — a deterministic, fast
	// "unreachable Postgres" with no real PG required.
	const unreachable = "postgres://u:p@127.0.0.1:1/db?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// LazyConnect: boots (no eager connect); the pool is usable.
	pool, err := InitPool(ctx, PoolConfig{DSN: unreachable, MaxConns: 1, LazyConnect: true})
	if err != nil {
		t.Fatalf("LazyConnect InitPool against unreachable PG: err=%v; want a usable pool (boot must not abort)", err)
	}
	if pool == nil || pool.DB == nil {
		t.Fatal("LazyConnect InitPool returned a nil pool")
	}
	pool.Close()

	// Strict (default): the eager Ping makes boot fatal — the regression guard.
	if _, err := InitPool(ctx, PoolConfig{DSN: unreachable, MaxConns: 1}); err == nil {
		t.Fatal("strict InitPool against unreachable PG returned nil error; the eager-ping boot guard regressed")
	}
}

// TestInitPool_LazyConnect_MalformedDSN_StillErrors — LazyConnect tolerates an
// outage, NOT a config bug: a malformed DSN is still fatal (an invalid sslmode
// fails ParseConfig before any connection attempt).
func TestInitPool_LazyConnect_MalformedDSN_StillErrors(t *testing.T) {
	bad := PoolConfig{DSN: "postgres://u:p@127.0.0.1:5432/db?sslmode=totally-invalid", LazyConnect: true}
	if _, err := InitPool(context.Background(), bad); err == nil {
		t.Fatal("LazyConnect InitPool accepted a malformed DSN; want a parse error")
	}
}
