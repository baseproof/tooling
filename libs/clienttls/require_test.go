// RequireMTLS tests pin the secure-by-default mechanism: when set, a would-be
// plaintext posture is startup-fatal (ErrPlaintextRefused); when unset, the
// library's plaintext behavior is unchanged (non-breaking). The policy of WHEN
// to require lives in the consumer; here we pin the mechanism + the env wiring.
package clienttls

import (
	"errors"
	"flag"
	"testing"
)

func TestFlags_Client_RequireMTLS_NoCertFailsClosed(t *testing.T) {
	f := Flags{RequireMTLS: true} // no cert/key
	c, posture, err := f.Client(0)
	if !errors.Is(err, ErrPlaintextRefused) {
		t.Fatalf("err = %v, want ErrPlaintextRefused", err)
	}
	if c != nil {
		t.Error("client must be nil when plaintext is refused")
	}
	if posture != PostureUnset {
		t.Errorf("posture = %v, want Unset", posture)
	}
}

func TestFlags_Client_RequireMTLS_WithCertIsMTLS(t *testing.T) {
	cert, key := writeSelfSignedCert(t, t.TempDir())
	f := Flags{CertFile: cert, KeyFile: key, RequireMTLS: true}
	_, posture, err := f.Client(0)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if posture != PostureMTLS {
		t.Errorf("posture = %v, want MTLS", posture)
	}
}

// Regression: RequireMTLS=false keeps the prior plaintext behavior intact.
func TestFlags_Client_NoRequire_PlaintextUnchanged(t *testing.T) {
	f := Flags{}
	c, posture, err := f.Client(0)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if posture != PosturePlaintext || c == nil {
		t.Errorf("posture = %v (client nil=%v), want Plaintext + non-nil", posture, c == nil)
	}
}

func TestBuildFromEnv_RequireMTLS_RefusesPlaintext(t *testing.T) {
	const prefix = "TESTEDGE_"
	t.Setenv(prefix+"REQUIRE_MTLS", "1") // no cert/key set → would be plaintext
	_, posture, err := BuildFromEnv(prefix, nil)
	if !errors.Is(err, ErrPlaintextRefused) {
		t.Fatalf("err = %v, want ErrPlaintextRefused", err)
	}
	if posture != PostureUnset {
		t.Errorf("posture = %v, want Unset", posture)
	}
}

func TestBuildFromEnv_RequireMTLS_WithCertIsMTLS(t *testing.T) {
	const prefix = "TESTEDGE2_"
	cert, key := writeSelfSignedCert(t, t.TempDir())
	t.Setenv(prefix+"REQUIRE_MTLS", "true")
	t.Setenv(prefix+"CLIENT_CERT_FILE", cert)
	t.Setenv(prefix+"CLIENT_KEY_FILE", key)
	_, posture, err := BuildFromEnv(prefix, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if posture != PostureMTLS {
		t.Errorf("posture = %v, want MTLS", posture)
	}
}

// Regression: with nothing set, BuildFromEnv stays Plaintext (non-breaking).
func TestBuildFromEnv_NoRequire_PlaintextUnchanged(t *testing.T) {
	_, posture, err := BuildFromEnv("TESTEDGE3_", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if posture != PosturePlaintext {
		t.Errorf("posture = %v, want Plaintext", posture)
	}
}

func TestBind_RegistersRequireMTLSFlag(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f.Bind(fs)
	if err := fs.Parse([]string{"-require-mtls"}); err != nil {
		t.Fatal(err)
	}
	if !f.RequireMTLS {
		t.Error("-require-mtls did not set RequireMTLS")
	}
}
