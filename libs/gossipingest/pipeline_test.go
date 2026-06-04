// Package gossipingest tests pin the Build contract:
//   - Every required field, when nil/missing, is rejected with ErrInvalidConfig
//     wrapping the specific field name.
//   - Build with a valid Config returns a non-nil Pipeline with every field
//     populated (puller + verifier + reconciler + heads + witness-set registry).
//
// The cryptographic verify path itself (envelope verify, finding-proof verify,
// witness-set rotation) is covered by the gossipverify package's hermetic
// tests; gossipingest only assembles the components.
package gossipingest

import (
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/gossip"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newNetworkID returns a non-zero NetworkID for tests. The actual bytes do
// not matter for Build's wiring check — only that the value is non-zero so
// downstream cosign verification doesn't reject every finding on
// "zero NetworkID" before anything else can be tested.
func newNetworkID(t *testing.T) cosign.NetworkID {
	t.Helper()
	var nid cosign.NetworkID
	if _, err := rand.Read(nid[:]); err != nil {
		t.Fatal(err)
	}
	return nid
}

// validConfig returns a Config with every required field populated — used by
// the negative-test cases below by zeroing out exactly one field at a time.
// Uses gossip.NewInMemoryStore for the evidence store: a real impl of the
// SDK contract, free of test stubs for the methods Build doesn't even call.
func validConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		HTTPClient:  &http.Client{},
		Peers:       nil,
		NetworkID:   newNetworkID(t),
		WitnessSets: map[string]*cosign.WitnessKeySet{},
		DIDRegistry: did.NewVerifierRegistry(),
		Store:       gossip.NewInMemoryStore(),
		Logger:      quietLogger(),
	}
}

// TestBuild_RequiresHTTPClient pins the v1.27.x contract: a nil HTTPClient
// is a programmer error (the binary's hoisted outbound client must be
// threaded in). Build returns ErrInvalidConfig.
func TestBuild_RequiresHTTPClient(t *testing.T) {
	cfg := validConfig(t)
	cfg.HTTPClient = nil
	_, err := Build(cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig wrapped, got %v", err)
	}
}

// TestBuild_RequiresDIDRegistry pins that a nil DID verifier registry is
// rejected (originator resolution cannot proceed without one).
func TestBuild_RequiresDIDRegistry(t *testing.T) {
	cfg := validConfig(t)
	cfg.DIDRegistry = nil
	_, err := Build(cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig wrapped, got %v", err)
	}
}

// TestBuild_RequiresStore pins that a nil evidence store is rejected (the
// reconciler has nowhere to persist verified findings).
func TestBuild_RequiresStore(t *testing.T) {
	cfg := validConfig(t)
	cfg.Store = nil
	_, err := Build(cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig wrapped, got %v", err)
	}
}

// TestBuild_RequiresWitnessSetsMap pins the subtle case: an EMPTY witness-set
// map is valid (pre-bootstrap state); a NIL map is a programmer error.
// "WitnessSets map is required" — see the field's docstring.
func TestBuild_RequiresWitnessSetsMap(t *testing.T) {
	cfg := validConfig(t)
	cfg.WitnessSets = nil
	_, err := Build(cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig on nil map, got %v", err)
	}
}

// TestBuild_EmptyWitnessSetsMapIsValid pins the inverse — an empty (non-nil)
// map is the correct pre-bootstrap shape and must succeed. Findings will
// then fail "no witness set for originator" verification, which is the
// correct zero-trust posture.
func TestBuild_EmptyWitnessSetsMapIsValid(t *testing.T) {
	cfg := validConfig(t)
	cfg.WitnessSets = map[string]*cosign.WitnessKeySet{}
	pipe, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build with empty witness map: %v", err)
	}
	if pipe == nil || pipe.Puller == nil || pipe.Reconciler == nil ||
		pipe.Verifier == nil || pipe.Heads == nil || pipe.WitnessSets == nil {
		t.Fatalf("Build returned an incomplete pipeline: %+v", pipe)
	}
}

// TestBuild_NilLoggerDefaultsToSlog pins the convenience that a nil
// cfg.Logger is replaced with slog.Default rather than rejected. Logger
// is the one field where "missing" has a sensible default.
func TestBuild_NilLoggerDefaultsToSlog(t *testing.T) {
	cfg := validConfig(t)
	cfg.Logger = nil
	if _, err := Build(cfg); err != nil {
		t.Fatalf("Build with nil Logger should succeed (defaults to slog.Default): %v", err)
	}
}

// TestBuild_Success pins that a fully-valid Config returns a Pipeline whose
// every public field is populated. Catches regressions where a future
// refactor forgets to populate one of the returned struct's fields.
func TestBuild_Success(t *testing.T) {
	pipe, err := Build(validConfig(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Puller == nil {
		t.Error("Pipeline.Puller is nil")
	}
	if pipe.Verifier == nil {
		t.Error("Pipeline.Verifier is nil")
	}
	if pipe.Reconciler == nil {
		t.Error("Pipeline.Reconciler is nil")
	}
	if pipe.Heads == nil {
		t.Error("Pipeline.Heads is nil")
	}
	if pipe.WitnessSets == nil {
		t.Error("Pipeline.WitnessSets is nil")
	}
}
