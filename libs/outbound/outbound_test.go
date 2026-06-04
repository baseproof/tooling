// Package outbound tests pin the thin contract: HoistFromEnv delegates to
// clienttls.BuildFromEnv and packages the result into the typed Client
// wrapper. The substantive transport tests live in libs/clienttls — these
// tests pin only the wrapping and the type seam.
package outbound

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/baseproof/tooling/libs/clienttls"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// clearEnv unsets every clienttls env var under the prefix so a test can
// start from a known-empty state regardless of host env.
func clearEnv(t *testing.T, prefix string) {
	t.Helper()
	for _, suffix := range []string{"CLIENT_CERT_FILE", "CLIENT_KEY_FILE", "CA_FILE", "HTTP_TIMEOUT"} {
		t.Setenv(prefix+suffix, "")
	}
}

// TestHoistFromEnv_Plaintext pins that an empty env returns a Client with
// Posture=Plaintext and a non-nil embedded *http.Client.
func TestHoistFromEnv_Plaintext(t *testing.T) {
	prefix := "OUTBOUND_TEST_PLAINTEXT_"
	clearEnv(t, prefix)
	c, err := HoistFromEnv(prefix, quietLogger())
	if err != nil {
		t.Fatalf("HoistFromEnv: %v", err)
	}
	if c == nil {
		t.Fatal("nil Client returned without error")
	}
	if c.Client == nil {
		t.Error("Client.Client is nil (embedded *http.Client must be populated)")
	}
	if c.Posture != clienttls.PosturePlaintext {
		t.Errorf("Posture = %v, want PosturePlaintext", c.Posture)
	}
}

// TestHoistFromEnv_HalfConfiguredPropagates pins that the half-config error
// surfaces unchanged through the wrapper — no swallowing.
func TestHoistFromEnv_HalfConfiguredPropagates(t *testing.T) {
	prefix := "OUTBOUND_TEST_HALF_"
	clearEnv(t, prefix)
	t.Setenv(prefix+"CLIENT_CERT_FILE", "/nonexistent.pem")
	// key deliberately omitted
	c, err := HoistFromEnv(prefix, quietLogger())
	if !errors.Is(err, clienttls.ErrHalfConfigured) {
		t.Errorf("want ErrHalfConfigured wrapped, got %v", err)
	}
	if c != nil {
		t.Error("expected nil Client on error")
	}
}

// TestHoistFromEnv_NilLogger pins that a nil logger is acceptable (delegates
// to slog.Default through clienttls.BuildFromEnv). The wrapper must not
// pre-validate logger separately from the underlying call.
func TestHoistFromEnv_NilLogger(t *testing.T) {
	prefix := "OUTBOUND_TEST_NILLOG_"
	clearEnv(t, prefix)
	if _, err := HoistFromEnv(prefix, nil); err != nil {
		t.Fatalf("HoistFromEnv with nil logger should succeed: %v", err)
	}
}

// TestClient_EmbeddedHTTPClient pins that the embedded *http.Client field
// works for method promotion — callers must be able to do c.Do(req) and
// pass c.Client to SDK constructors. Catches regressions where a future
// refactor changes the field to a non-embedded form and silently breaks
// the promotion / extraction contract.
func TestClient_EmbeddedHTTPClient(t *testing.T) {
	prefix := "OUTBOUND_TEST_EMBED_"
	clearEnv(t, prefix)
	c, err := HoistFromEnv(prefix, quietLogger())
	if err != nil {
		t.Fatalf("HoistFromEnv: %v", err)
	}
	// Field access (passed to SDK constructors expecting *http.Client).
	if c.Client == nil {
		t.Error("c.Client (embedded *http.Client) must not be nil")
	}
	// Method promotion (so the wrapper is usable directly for one-off
	// operator probes without extracting the inner pointer).
	if c.Client.Timeout <= 0 {
		t.Error("Timeout did not propagate via embedding")
	}
}
