package runner

import (
	"context"
	"testing"

	"github.com/baseproof/tooling/e2e/fixture"
)

// TestReadStages_AgainstFixture proves the runner's READ side end to end over real
// HTTPS with real cryptography, no docker: it stands up the in-process real-crypto
// ledger fixture (a pre-committed entry, cosigned horizon, full introspection
// surface) and drives the ACTUAL unified-CLI commands — network add (author a
// bundle over HTTPS server-verify), proof (live gather → self-verify), verify
// (offline, network-pinned), info --verify (horizon K-of-N + auditor) — asserting
// every stage is green. This is the same runner `e2e run` drives against the docker
// fleet; here it closes the read/verify side anywhere.
func TestReadStages_AgainstFixture(t *testing.T) {
	fx, err := fixture.Start(3, 2)
	if err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()

	cfg := Config{
		LedgerURL: fx.Ledger.URL,
		CAFile:    fx.CAPath,
		LogDID:    fx.LogDID,
		WorkDir:   t.TempDir(),
	}
	res, err := ReadStages(context.Background(), cfg, fx.Seq, fx.SMTKeyHex)
	for _, s := range res.Stages {
		if !s.OK {
			t.Logf("stage %q err: %v", s.Name, s.Err)
		}
	}
	if err != nil {
		t.Fatalf("ReadStages: %v", err)
	}
	for _, s := range res.Stages {
		if s.OK {
			t.Logf("✔ %s — %s", s.Name, s.Detail)
		} else {
			t.Errorf("✗ %s FAILED: %v", s.Name, s.Err)
		}
	}
	if !res.OK() {
		t.Fatal("read stages were not all green")
	}
}
