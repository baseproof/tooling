/*
FILE PATH: cmd/ledger/config_anchoring_test.go

PR-4 producer/consumer cadence contract: the constitution's GenesisAnchoring
commitment is the SINGLE source of the anchor-publisher cadence (consumers
derive, never restate). reconcileAnchorCadence:

  - no commitment        → operational defaults untouched;
  - commitment           → self-interval = clamp(bound/3, 10s, 1h), never above
    the bound itself (the publisher must run comfortably INSIDE the promise);
  - LEDGER_PARENT_ANCHOR_INTERVAL (the one operator cadence knob) demotes to a
    cross-check: within the bound honored, LOOSER than the bound fatal — an
    off-log env cannot stretch a NetworkID-bound commitment.
*/
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/network"
)

func anchoredDoc(maxIntervalSeconds uint64) network.BootstrapDocument {
	var doc network.BootstrapDocument
	if maxIntervalSeconds > 0 {
		doc.GenesisAnchoring = &network.GenesisAnchoringPolicy{
			Mode:               network.GenesisEndorsementRequire,
			MaxIntervalSeconds: maxIntervalSeconds,
		}
	}
	return doc
}

func TestReconcileAnchorCadence_DerivationTable(t *testing.T) {
	cases := []struct {
		name         string
		boundSeconds uint64
		wantInterval time.Duration
	}{
		{"no-commitment-untouched", 0, time.Hour},
		{"day-bound-caps-at-default", 86400, time.Hour}, // 24h/3=8h → capped at 1h
		{"30min-bound-derives-third", 1800, 10 * time.Minute},
		{"90s-bound-derives-30s", 90, 30 * time.Second},
		{"tiny-bound-floor-then-bound", 5, 5 * time.Second}, // floor 10s would EXCEED the bound → bound wins
	}
	for _, c := range cases {
		cfg := &Config{AnchorInterval: time.Hour}
		if err := reconcileAnchorCadence(anchoredDoc(c.boundSeconds), cfg); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if cfg.AnchorInterval != c.wantInterval {
			t.Errorf("%s: AnchorInterval = %s, want %s", c.name, cfg.AnchorInterval, c.wantInterval)
		}
		if c.boundSeconds > 0 {
			bound := time.Duration(c.boundSeconds) * time.Second
			if cfg.AnchorInterval > bound {
				t.Errorf("%s: derived interval %s exceeds the constitutional bound %s — the promise would be breached by design", c.name, cfg.AnchorInterval, bound)
			}
		}
	}
}

func TestReconcileAnchorCadence_ParentEnvDemotion(t *testing.T) {
	// Within the bound: honored (an operator may anchor MORE often).
	cfg := &Config{AnchorInterval: time.Hour, ParentAnchorInterval: 5 * time.Minute}
	if err := reconcileAnchorCadence(anchoredDoc(1800), cfg); err != nil {
		t.Fatalf("tighter parent interval must be honored: %v", err)
	}
	if cfg.ParentAnchorInterval != 5*time.Minute {
		t.Errorf("parent interval rewritten to %s; the knob demotes to a cross-check, it is not derived", cfg.ParentAnchorInterval)
	}

	// Looser than the bound: fatal.
	cfg = &Config{AnchorInterval: time.Hour, ParentAnchorInterval: 2 * time.Hour}
	err := reconcileAnchorCadence(anchoredDoc(1800), cfg)
	if err == nil {
		t.Fatal("a parent interval LOOSER than the constitutional bound was accepted — an off-log env stretched a NetworkID-bound commitment")
	}
	if !strings.Contains(err.Error(), "LOOSER than the constitutional") {
		t.Fatalf("refusal came from the wrong place: %v", err)
	}
}
