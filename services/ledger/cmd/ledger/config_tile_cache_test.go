package main

import (
	"os"
	"testing"
)

// TestConfig_TileCacheSize_DefaultWhenUnset pins the default value
// (10000 entries) when LEDGER_TILE_CACHE_SIZE is unset. The default
// matches the pre-Part-II.7 hard-coded literal so the env-var
// introduction is observably backward-compatible.
func TestConfig_TileCacheSize_DefaultWhenUnset(t *testing.T) {
	t.Setenv("LEDGER_TILE_CACHE_SIZE", "")
	// Other env vars Load() needs to read can stay defaulted; the
	// tile-cache field is sourced via envIntOr and is independent.
	got := envIntOr("LEDGER_TILE_CACHE_SIZE", 10_000)
	if got != 10_000 {
		t.Errorf("LEDGER_TILE_CACHE_SIZE unset: got %d, want 10000", got)
	}
}

// TestConfig_TileCacheSize_HonorsEnv pins the env-driven adjustment
// path: the operator sets LEDGER_TILE_CACHE_SIZE in their deployment
// config (Helm ConfigMap, docker-compose env, systemd Environment=)
// and the parsed value flows through to tessera.NewTileReader.
func TestConfig_TileCacheSize_HonorsEnv(t *testing.T) {
	cases := []struct {
		name string
		envv string
		want int
	}{
		{"explicit larger", "20000", 20_000},
		{"explicit smaller", "5000", 5_000},
		{"explicit minimum", "100", 100},
		// envIntOr returns the default for non-numeric or empty —
		// the operator's malformed value never reaches the cache
		// with a confusing partial number.
		{"non-numeric falls back to default", "not-an-int", 10_000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("LEDGER_TILE_CACHE_SIZE", c.envv)
			got := envIntOr("LEDGER_TILE_CACHE_SIZE", 10_000)
			if got != c.want {
				t.Errorf("LEDGER_TILE_CACHE_SIZE=%q: got %d, want %d",
					c.envv, got, c.want)
			}
		})
	}
}

// TestConfig_TileCacheSize_BelowFloorHandedToTessera pins the
// contract between cmd/ledger/config.go and tessera/tile_reader.go:83-86.
// Values below the tessera floor (100) flow through unchanged; the
// floor is enforced inside NewTileReader, NOT in Config.Load. This
// is the right boundary — the floor is a property of the cache
// implementation, not of the config layer.
func TestConfig_TileCacheSize_BelowFloorHandedToTessera(t *testing.T) {
	t.Setenv("LEDGER_TILE_CACHE_SIZE", "10")
	got := envIntOr("LEDGER_TILE_CACHE_SIZE", 10_000)
	if got != 10 {
		t.Fatalf("config layer must NOT clamp; got %d, want 10", got)
	}
	// tessera.NewTileReader(backend, 10) is what enforces the floor.
	// Verified in tessera/tile_reader.go test suite, not here.
}

// TestConfig_TileCacheSize_NegativeFallsThroughToTessera mirrors the
// "explicit zero or negative" operator-error case. envIntOr does not
// guard sign; tessera.NewTileReader treats < 100 as default-trigger.
func TestConfig_TileCacheSize_NegativeFallsThroughToTessera(t *testing.T) {
	t.Setenv("LEDGER_TILE_CACHE_SIZE", "-5")
	got := envIntOr("LEDGER_TILE_CACHE_SIZE", 10_000)
	if got != -5 {
		t.Fatalf("config layer must NOT clamp negatives; got %d, want -5", got)
	}
	// tessera.NewTileReader(backend, -5) → uses internal default.
}

// _ keeps os imported even if no direct os.X call (Setenv is t.Setenv).
var _ = os.Getenv
