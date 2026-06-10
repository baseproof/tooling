// FILE PATH: cmd/auditor/rotation_wiring_test.go
//
// Functional tests for the AT-2 wiring seams. The original gap was a wiring
// omission (the resolver existed, main never connected it), so the wiring is
// tested as behavior: a restart after a rotation must re-seed live trust with
// the reconstructed current set, and the scan job must translate per-log
// outcomes into the right alert severities without one log muting another.
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/witnessrotation"
	"github.com/baseproof/tooling/services/auditor/internal/store"
)

func mintSet(t *testing.T) *cosign.WitnessKeySet {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	keys := []types.WitnessPublicKey{{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}}
	var nid cosign.NetworkID
	nid[0] = 0x42
	set, err := cosign.NewWitnessKeySet(keys, nid, 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	return set
}

type fakeCurrentSetResolver struct {
	sets map[string]*cosign.WitnessKeySet
	errs map[string]error
}

func (f *fakeCurrentSetResolver) CurrentSet(_ context.Context, logDID string) (*cosign.WitnessKeySet, error) {
	if err := f.errs[logDID]; err != nil {
		return nil, err
	}
	return f.sets[logDID], nil
}

// TestReseedWitnessSets_RestartAfterRotation emulates the restart-after-
// rotation boot: the journal chain reconstructs S1 for a rotated log, so the
// live trust map (keyed by the gossip originator) must carry S1 — while a log
// whose chain cannot be read fail-statics to its genesis seed.
func TestReseedWitnessSets_RestartAfterRotation(t *testing.T) {
	genA, curA := mintSet(t), mintSet(t) // log A rotated: genesis ≠ current
	genB := mintSet(t)                   // log B: chain unreadable → keep genesis

	roots := []store.LogTrustRoot{
		{LogDID: "did:web:log-a", Aliases: []string{"did:key:orig-a"}, Genesis: genA},
		{LogDID: "did:web:log-b", Aliases: []string{"did:key:orig-b"}, Genesis: genB},
	}
	witnessSets := map[string]*cosign.WitnessKeySet{
		"did:key:orig-a": genA,
		"did:key:orig-b": genB,
	}
	resolver := &fakeCurrentSetResolver{
		sets: map[string]*cosign.WitnessKeySet{"did:web:log-a": curA},
		errs: map[string]error{"did:web:log-b": errors.New("journal unreadable")},
	}

	reseedWitnessSets(context.Background(), roots, resolver, witnessSets,
		map[string]string{"did:web:log-a": "did:key:orig-a", "did:web:log-b": "did:key:orig-b"},
		slog.Default())

	if witnessSets["did:key:orig-a"] != curA {
		t.Fatal("rotated log must be re-seeded with the journal-reconstructed CURRENT set")
	}
	if witnessSets["did:key:orig-b"] != genB {
		t.Fatal("unreadable chain must fail-static to the genesis seed")
	}
}

type fakeScanner struct {
	report witnessrotation.ScanReport
	err    error
}

func (f *fakeScanner) RunOnce(context.Context) (witnessrotation.ScanReport, error) {
	return f.report, f.err
}

// TestBuildRotationScanJob_AlertMapping emulates one scheduler pass over four
// logs in four states: trust-integrity failure (Critical), transient failure
// (Warning), tail-omission caught (Warning), healthy no-op (silent) — and no
// log's failure mutes the others.
func TestBuildRotationScanJob_AlertMapping(t *testing.T) {
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	job := buildRotationScanJob([]rotationScanner{
		&fakeScanner{report: witnessrotation.ScanReport{LogDID: "did:web:integrity"},
			err: fmt.Errorf("wrapped: %w", witnessrotation.ErrNoVerifiableTarget)},
		&fakeScanner{report: witnessrotation.ScanReport{LogDID: "did:web:transient"},
			err: errors.New("dial tcp: connection refused")},
		&fakeScanner{report: witnessrotation.ScanReport{
			LogDID: "did:web:omission", From: 100, Until: 250, Discovered: 1, NewlyJournaled: 1}},
		&fakeScanner{report: witnessrotation.ScanReport{LogDID: "did:web:healthy", From: 250, Until: 250}},
	}, func() time.Time { return fixed })

	alerts, err := job(context.Background())
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if len(alerts) != 3 {
		t.Fatalf("want 3 alerts (critical + transient + omission), got %d: %v", len(alerts), alerts)
	}
	bySev := map[sdkmonitoring.Severity]int{}
	for _, a := range alerts {
		if a.Monitor != "witness_rotation_scan" {
			t.Fatalf("alert monitor = %q", a.Monitor)
		}
		if !a.EmittedAt.Equal(fixed) {
			t.Fatalf("alert EmittedAt = %v, want fixed clock", a.EmittedAt)
		}
		bySev[a.Severity]++
	}
	if bySev[sdkmonitoring.Critical] != 1 || bySev[sdkmonitoring.Warning] != 2 {
		t.Fatalf("severity mix = %v, want 1 Critical + 2 Warning", bySev)
	}
}
