package clienttls

import (
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pinServerCert writes the httptest server's self-signed leaf cert to a PEM file
// usable as a CA-pin bundle. httptest's default cert is self-signed for
// 127.0.0.1/::1, so pinning the leaf as a trusted root verifies it by IP — no
// ServerName override needed for https://127.0.0.1:port.
func pinServerCert(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath
}

func okTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func getBody(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// FUNCTIONAL: AllowSelfSigned + a pinned CA, NO client cert → PostureServerVerify,
// and the client actually completes the TLS handshake against the privately-
// signed server. This is the open-HTTPS read path the ledger now serves.
func TestClient_AllowSelfSigned_ReachesPrivateServer(t *testing.T) {
	srv := okTLSServer(t)
	ca := pinServerCert(t, srv)

	f := Flags{CAFile: ca, AllowSelfSigned: true} // no client cert
	c, posture, err := f.Client(5 * time.Second)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if posture != PostureServerVerify {
		t.Fatalf("posture = %v, want SERVER-VERIFY", posture)
	}
	if code, body := getBody(t, c, srv.URL); code != 200 || body != "ok" {
		t.Fatalf("GET = (%d, %q), want (200, \"ok\") — CA-pinned server-verify must connect", code, body)
	}
}

// FUNCTIONAL negative: with NO CA (PosturePlaintext → system roots) the SAME
// privately-signed server is REJECTED at the handshake. Proves the CA pin is
// what makes it work, not a skipped verification.
func TestClient_NoCA_RejectsPrivateServer(t *testing.T) {
	srv := okTLSServer(t)

	f := Flags{} // no cert, no CA → system roots
	c, posture, err := f.Client(5 * time.Second)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if posture != PosturePlaintext {
		t.Fatalf("posture = %v, want PLAINTEXT (system roots)", posture)
	}
	if _, errStr := getBody(t, c, srv.URL); errStr == "ok" {
		t.Fatal("system-roots client accepted a privately-signed cert — verification was NOT enforced")
	}
}

// A CA with no client cert and no AllowSelfSigned still honors the CA (pinning
// only adds trust, never weakens it) → PostureServerVerify, connects.
func TestClient_CAOnly_HonorsPinWithoutClientCert(t *testing.T) {
	srv := okTLSServer(t)
	ca := pinServerCert(t, srv)

	f := Flags{CAFile: ca} // CA only
	c, posture, err := f.Client(5 * time.Second)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if posture != PostureServerVerify {
		t.Fatalf("posture = %v, want SERVER-VERIFY", posture)
	}
	if code, _ := getBody(t, c, srv.URL); code != 200 {
		t.Fatalf("GET code = %d, want 200", code)
	}
}

// AllowSelfSigned without a CA is startup-fatal — a self-signed cert with
// nothing to pin it to is exactly the silent-skip-verify trap we refuse.
func TestClient_AllowSelfSigned_NoCA_FailsClosed(t *testing.T) {
	f := Flags{AllowSelfSigned: true} // no CA
	c, posture, err := f.Client(0)
	if !errors.Is(err, ErrSelfSignedNoCA) {
		t.Fatalf("err = %v, want ErrSelfSignedNoCA", err)
	}
	if c != nil || posture != PostureUnset {
		t.Errorf("client/posture = (%v, %v), want (nil, Unset)", c != nil, posture)
	}
}

// The secure-by-default EDGE (BuildFromEnvRequire — auditor/JN posture) OPENS to
// server-verify when ALLOW_SELF_SIGNED + CA_FILE are set: it does NOT fail closed,
// and it reaches the private server. This is exactly the harness's open-HTTPS path
// against a privately-signed ledger.
func TestBuildFromEnvRequire_AllowSelfSigned_OpensServerVerify(t *testing.T) {
	srv := okTLSServer(t)
	ca := pinServerCert(t, srv)

	const prefix = "SSEDGE_"
	t.Setenv(prefix+"CA_FILE", ca)
	t.Setenv(prefix+"ALLOW_SELF_SIGNED", "1") // no client cert configured

	c, posture, err := BuildFromEnvRequire(prefix, nil)
	if err != nil {
		t.Fatalf("BuildFromEnvRequire: %v (must not fail closed when ALLOW_SELF_SIGNED is set)", err)
	}
	if posture != PostureServerVerify {
		t.Fatalf("posture = %v, want SERVER-VERIFY", posture)
	}
	if code, _ := getBody(t, c, srv.URL); code != 200 {
		t.Fatalf("edge GET code = %d, want 200", code)
	}
}

// ALLOW_SELF_SIGNED=1 with no CA_FILE is startup-fatal via the env entry too.
func TestBuildFromEnv_AllowSelfSigned_NoCA_FailsClosed(t *testing.T) {
	const prefix = "SSEDGE2_"
	t.Setenv(prefix+"ALLOW_SELF_SIGNED", "1")
	_, posture, err := BuildFromEnv(prefix, nil)
	if !errors.Is(err, ErrSelfSignedNoCA) {
		t.Fatalf("err = %v, want ErrSelfSignedNoCA", err)
	}
	if posture != PostureUnset {
		t.Errorf("posture = %v, want Unset", posture)
	}
}

func TestPostureServerVerify_String(t *testing.T) {
	if got := PostureServerVerify.String(); got != "SERVER-VERIFY" {
		t.Errorf("String() = %q, want SERVER-VERIFY", got)
	}
}
