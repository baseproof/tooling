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

// resolveFile implements the orchestrator-agnostic cert/key/bootstrap
// injection convention: an EXPLICITLY-configured path (the env var) always
// wins — and, being explicit, is honored verbatim so a downstream open fails
// loudly if it is missing. Otherwise the first existing file among the
// conventional candidate paths is used, in order:
//
//  1. the standard mount path (/etc/ledger/...) — a Secret/ConfigMap volume
//     (k8s) or bind mount (compose) dropped there is picked up with ZERO env;
//  2. the PaaS secret-file path (/etc/secrets/<flat-name>) — where Render-class
//     platforms place uploaded secret files (no subdirectories), so the same
//     image runs there with zero env too.
//
// No candidate ⇒ "" — the feature stays unconfigured, byte-identical to the
// pre-convention behavior (no env, no mount ⇒ off). The stats are boot-only.
func resolveFile(envKey string, candidates ...string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// listenAddr resolves the HTTP listen address: the service-specific env var
// wins; else the platform-injected PORT (the Render / Cloud Run / Heroku /
// Railway contract — the platform routes to the port it announces) yields
// ":$PORT"; else the baked default. PORT is consulted ONLY when the service
// var is unset, so docker-compose / k8s deployments that set LEDGER_ADDR are
// untouched, and a garbage PORT fails loudly at bind, never silently.
func listenAddr(envKey, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		return ":" + p
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

// envIntLookup reads an env var as a base-10 int, distinguishing "unset" from
// "set" and surfacing a parse error rather than silently falling back. Used by
// the constitutional-quorum cross-check, where the difference between absent
// (adopt the constitutional value) and present-but-wrong (fatal) is the whole
// point — envIntOr's fallback-on-error would mask a misconfiguration.
func envIntLookup(key string) (value int, set bool, err error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return 0, false, nil
	}
	n, perr := strconv.Atoi(strings.TrimSpace(v))
	if perr != nil {
		return 0, true, fmt.Errorf("%s=%q is not an integer: %w", key, v, perr)
	}
	return n, true, nil
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
// trimmed non-empty entries. Empty input → nil. Used for the gossip
// peer lists (LEDGER_GOSSIP_PEER_ENDPOINTS / LEDGER_GOSSIP_PEER_DIDS).
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
