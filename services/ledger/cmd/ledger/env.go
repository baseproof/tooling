// Environment-variable helpers.
//
// FILE PATH:
//
//	cmd/ledger/env.go
//
// DESCRIPTION:
//
//	Five small parsing helpers used by loadConfig + main:
//	  envOr            — string or default
//	  envIntOr         — int or default
//	  envDurationOr    — time.Duration or default
//	  parseCSV         — comma-separated → []string
//	  parseMigrateMode — LEDGER_DB_MIGRATE_MODE → store.MigrateMode
//
//	Extracted verbatim from cmd/ledger/main.go as part of the
//	lifecycle-phase decomposition (P3). Behaviour unchanged.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/baseproof/tooling/services/ledger/store"
)

// envOr returns the value of the env var, or fallback when unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envIntOr reads an env var as a base-10 integer; returns fallback
// if the var is unset or unparseable.
func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// envInt64Or reads an env var as a base-10 int64; returns fallback
// if the var is unset or unparseable. Used for byte-sized configuration
// values (LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES) where int32 would saturate.
func envInt64Or(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

// envDurationOr reads an env var as a Go time.Duration string
// (e.g. "1s", "500ms", "24h"); returns fallback on unset or parse
// failure.
func envDurationOr(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// envFloatOr reads an env var as a float64; returns fallback on unset or
// parse failure. Used for fractional tuning knobs (LEDGER_SHIPPER_AIMD_STEP).
func envFloatOr(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

// parseCSV splits a comma-separated env value into a slice of
// trimmed non-empty entries. Empty input → nil. Used for
// LEDGER_WITNESS_ENDPOINTS.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseMigrateMode resolves LEDGER_DB_MIGRATE_MODE to the typed
// store.MigrateMode value. Empty / "apply" → MigrateApply (default;
// preserves the legacy boot-time behaviour). "verify" → fail at boot
// if any migration is pending. "skip" → assume an out-of-band apply
// has already run; touch nothing.
func parseMigrateMode(raw string) (store.MigrateMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "apply":
		return store.MigrateApply, nil
	case "verify":
		return store.MigrateVerify, nil
	case "skip":
		return store.MigrateSkip, nil
	default:
		return 0, fmt.Errorf("LEDGER_DB_MIGRATE_MODE=%q (want apply|verify|skip)", raw)
	}
}
