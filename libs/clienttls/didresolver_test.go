/*
FILE PATH: libs/clienttls/didresolver_test.go

T10 unit tests — BuildDIDResolverWithMTLS.

Covers the three failure / success paths of the wrapper:

  - nil client          → error (fail-loud, names the v1.32.0 posture)
  - TTL <= 0            → DefaultDIDResolverCacheTTL applied
  - explicit positive TTL → resolver returned
*/
package clienttls

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestBuildDIDResolverWithMTLS_NilClient pins the fail-loud
// rejection. The error message MUST surface the v1.32.0 advisory
// posture so an operator reading a CI failure understands WHY
// plaintext fallback isn't an option.
func TestBuildDIDResolverWithMTLS_NilClient(t *testing.T) {
	resolver, err := BuildDIDResolverWithMTLS(nil, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for nil client; got nil")
	}
	if resolver != nil {
		t.Errorf("expected nil resolver on error; got %v", resolver)
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error must mention nil client; got %v", err)
	}
	// The advisory cross-check warning is part of the contract:
	// the error message tells the operator why plaintext isn't OK.
	if !strings.Contains(err.Error(), "cross-check") &&
		!strings.Contains(err.Error(), "plaintext") {
		t.Errorf("error must reference the v1.32.0 posture (cross-check or plaintext); got: %v", err)
	}
}

// TestBuildDIDResolverWithMTLS_ValidClient_DefaultTTL covers the
// TTL<=0 path — the helper substitutes DefaultDIDResolverCacheTTL.
// We can't directly observe the TTL on the returned resolver (the
// SDK's CachingResolver doesn't expose it), so the test asserts
// that the resolver builds without error and that the
// DefaultDIDResolverCacheTTL constant is the documented value.
func TestBuildDIDResolverWithMTLS_ValidClient_DefaultTTL(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}
	resolver, err := BuildDIDResolverWithMTLS(client, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
	// The documented default is 5 minutes — pin it so a future
	// change surfaces here.
	if DefaultDIDResolverCacheTTL != 5*time.Minute {
		t.Errorf("DefaultDIDResolverCacheTTL: got %v, want 5m", DefaultDIDResolverCacheTTL)
	}
}

// TestBuildDIDResolverWithMTLS_ValidClient_NegativeTTL exercises
// the "ttl <= 0" branch with a negative value. Same outcome as
// zero: default is applied.
func TestBuildDIDResolverWithMTLS_ValidClient_NegativeTTL(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}
	resolver, err := BuildDIDResolverWithMTLS(client, -1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
}

// TestBuildDIDResolverWithMTLS_ValidClient_ExplicitTTL exercises
// the happy path with an operator-set TTL.
func TestBuildDIDResolverWithMTLS_ValidClient_ExplicitTTL(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}
	resolver, err := BuildDIDResolverWithMTLS(client, 15*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
}

// TestDefaultDIDResolverCacheTTL_DocumentedValue pins the public
// constant so any future change surfaces here.
func TestDefaultDIDResolverCacheTTL_DocumentedValue(t *testing.T) {
	if DefaultDIDResolverCacheTTL != 5*time.Minute {
		t.Errorf("DefaultDIDResolverCacheTTL changed: got %v, want 5m "+
			"(documented in didresolver.go; update the README if intentional)",
			DefaultDIDResolverCacheTTL)
	}
}
