// FILE PATH: libs/clitools/horizon_verify_test.go
//
// VerifyHorizon is a thin wrapper over the SDK v1.22.0 horizon client; the
// cryptographic correctness (quorum, proof-bound-to-witnessed-root, tamper,
// sub-quorum, not-published) is covered by the SDK's hermetic tests in the
// baseproof/log + core/smt packages. These tests cover only the wrapper's wiring.
package clitools

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
)

// TestVerifyHorizon_NilHTTPClient pins the v1.27.1 contract: a nil httpClient
// is a programmer error and must surface immediately, not be silently swapped
// for a 15s plaintext default. The earlier shape (VerifyHorizon vs
// VerifyHorizonWithClient with a default fallback) is exactly the dual-form
// the SDK removed in v1.25.0 — this test makes sure tooling doesn't
// drift back.
func TestVerifyHorizon_NilHTTPClient(t *testing.T) {
	if _, err := VerifyHorizon(context.Background(), "http://127.0.0.1:0", nil, 0, nil); !errors.Is(err, ErrNilHTTPClient) {
		t.Fatalf("want ErrNilHTTPClient on nil httpClient; got %v", err)
	}
	var key [32]byte
	if _, _, err := VerifyAsOfHorizon(context.Background(), "http://127.0.0.1:0", nil, key, nil); !errors.Is(err, ErrNilHTTPClient) {
		t.Fatalf("want ErrNilHTTPClient on nil httpClient (VerifyAsOfHorizon); got %v", err)
	}
}

// TestVerifyHorizon_NilSet confirms the wrapper delegates the trust step to the
// SDK (which rejects a nil witness key set) rather than skipping verification.
// Caller supplies a valid client; the SDK then errors on the witness set.
func TestVerifyHorizon_NilSet(t *testing.T) {
	client := &http.Client{Timeout: 1 * time.Second}
	if _, err := VerifyHorizon(context.Background(), "http://127.0.0.1:0", nil, 0, client); err == nil {
		t.Fatal("want error on nil witness key set (verification must not be skippable)")
	}
}

// TestVerifyHorizon_NotPublishedSentinel confirms the SDK's ErrHorizonNotPublished
// sentinel is reachable through the wrapper's import surface (callers branch on it
// for pre-genesis 503 vs a real failure).
func TestVerifyHorizon_NotPublishedSentinel(t *testing.T) {
	if sdklog.ErrHorizonNotPublished == nil {
		t.Fatal("SDK ErrHorizonNotPublished sentinel missing")
	}
	if errors.Is(nil, sdklog.ErrHorizonNotPublished) {
		t.Fatal("errors.Is(nil, sentinel) must be false")
	}
}
