// FILE PATH: services/auditor/internal/horizon/verifier_test.go
//
// The cryptographic verify path (FetchVerifiedHorizon quorum, proof-bound-to-
// witnessed-root) is owned by the SDK's hermetic log/core-smt tests and the e2e.
// These tests cover the verifier's control flow that needs no live ledger.
package horizon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func testHTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

// TestNewVerifier_NoPeers: nothing to audit ⇒ (nil, nil) (caller skips registration).
func TestNewVerifier_NoPeers(t *testing.T) {
	v, err := NewVerifier(Config{Logger: testLogger(), HTTPClient: testHTTPClient()})
	if err != nil {
		t.Fatalf("unexpected error on empty peers: %v", err)
	}
	if v != nil {
		t.Fatalf("want nil verifier when there are no peers, got %v", v)
	}
}

// TestNewVerifier_RequiresHTTPClient pins the v1.27.1 contract: peers
// configured but HTTPClient nil is a programmer error and surfaces at
// construction.
func TestNewVerifier_RequiresHTTPClient(t *testing.T) {
	_, err := NewVerifier(Config{
		Peers:  []Peer{{OriginatorDID: "did:key:zX", BaseURL: "http://127.0.0.1:0"}},
		Logger: testLogger(),
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig on nil HTTPClient; got %v", err)
	}
}

// TestAuditOnce_SkipsPeerWithoutWitnessSet: a peer with no resolved witness set
// is skipped (recorded, never silently "verified"), and no network is touched.
func TestAuditOnce_SkipsPeerWithoutWitnessSet(t *testing.T) {
	v, err := NewVerifier(Config{
		Peers:      []Peer{{OriginatorDID: "did:key:zMissing", BaseURL: "http://127.0.0.1:0"}},
		Sets:       map[string]*cosign.WitnessKeySet{}, // no set for the originator
		HTTPClient: testHTTPClient(),
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v == nil {
		t.Fatal("verifier should be non-nil with one peer")
	}
	alerts, err := v.AuditOnce(context.Background())
	if err != nil {
		t.Fatalf("AuditOnce error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("want no alerts for a skipped peer, got %d", len(alerts))
	}
	if st := v.Status()["http://127.0.0.1:0"]; st.State != "no_witness_set" {
		t.Fatalf("want state no_witness_set, got %q", st.State)
	}
}
