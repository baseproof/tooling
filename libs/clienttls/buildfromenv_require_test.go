package clienttls

import (
	"errors"
	"testing"
)

// BuildFromEnvRequire tests pin the secure-by-default EDGE entry point: require
// mTLS by default; <prefix>ALLOW_PLAINTEXT is the only opt-out. The final case
// guards that the non-edge BuildFromEnv is unchanged (still plaintext-default).

func TestBuildFromEnvRequire_DefaultFailsClosed(t *testing.T) {
	_, posture, err := BuildFromEnvRequire("EDGEREQ_", nil) // no cert, no opt-out
	if !errors.Is(err, ErrPlaintextRefused) {
		t.Fatalf("err = %v, want ErrPlaintextRefused", err)
	}
	if posture != PostureUnset {
		t.Errorf("posture = %v, want Unset", posture)
	}
}

func TestBuildFromEnvRequire_AllowPlaintextOptOut(t *testing.T) {
	const prefix = "EDGEREQ2_"
	t.Setenv(prefix+"ALLOW_PLAINTEXT", "1")
	_, posture, err := BuildFromEnvRequire(prefix, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if posture != PosturePlaintext {
		t.Errorf("posture = %v, want Plaintext (opt-out)", posture)
	}
}

func TestBuildFromEnvRequire_WithCertIsMTLS(t *testing.T) {
	const prefix = "EDGEREQ3_"
	cert, key := writeSelfSignedCert(t, t.TempDir())
	t.Setenv(prefix+"CLIENT_CERT_FILE", cert)
	t.Setenv(prefix+"CLIENT_KEY_FILE", key)
	_, posture, err := BuildFromEnvRequire(prefix, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if posture != PostureMTLS {
		t.Errorf("posture = %v, want MTLS", posture)
	}
}

func TestBuildFromEnv_StaysPlaintextDefault(t *testing.T) {
	_, posture, err := BuildFromEnv("NONEDGE_", nil) // opt-in entry — unchanged
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if posture != PosturePlaintext {
		t.Errorf("posture = %v, want Plaintext (BuildFromEnv must stay non-breaking)", posture)
	}
}
