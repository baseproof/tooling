package outbound

import "testing"

// HoistFromEnvRequire is the secure-by-default edge hoist: fail closed without a
// client cert, unless <prefix>ALLOW_PLAINTEXT opts out.

func TestHoistFromEnvRequire_FailsClosed(t *testing.T) {
	if _, err := HoistFromEnvRequire("OBREQ_", nil); err == nil {
		t.Fatal("expected fail-closed without a client cert")
	}
}

func TestHoistFromEnvRequire_AllowPlaintextOptOut(t *testing.T) {
	t.Setenv("OBREQ2_ALLOW_PLAINTEXT", "1")
	c, err := HoistFromEnvRequire("OBREQ2_", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c == nil || c.Posture.String() != "PLAINTEXT" {
		t.Errorf("want plaintext posture (opt-out), got %v", c)
	}
}
