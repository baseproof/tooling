/*
FILE PATH: internal/clienttls/clienttls.go

Shared mTLS-flag wiring for the ledger's outbound HTTP callers (CLI
tools + in-binary outbound clients). The helper produces *tls.Config
material; the caller composes it with whichever client constructor it
needs (retryhttp.Client for CLI tools that need startup-race retry
resilience, sdklog.DefaultClient for binary callers that own their own
retry loops).

DESIGN:
  - `Flags` carries the three file paths (cert, key, CA).
  - `Bind(fs)` registers `-client-cert / -client-key / -ca-cert` on the
    supplied flag.FlagSet.
  - `Configured()` reports whether cert+key are both set.
  - `TLSConfig()` returns:
  - (*tls.Config, nil) — when Configured(); composes the SDK
    ClientTLSConfig (TLS 1.3 floor, verified server cert, presented
    client cert).
  - (nil, nil)         — when NOT Configured(); the caller's client
    constructor falls back to stdlib defaults (server-verify only).
    This preserves legacy behaviour for plaintext deployments.
  - (nil, err)         — when Configured() but cert/key/CA cannot be
    loaded. The caller MUST fail closed — silently falling back to
    plaintext after the operator asked for mTLS would be a confused-
    deputy bug.

WHY ONE HELPER (not a per-tool ad-hoc wiring):
  - Single import, single contract — every CLI tool and every in-binary
    outbound client builds its TLS material identically.
  - Returning *tls.Config (not *http.Client) lets each caller compose
    the right transport: retryhttp.Client(t, tlsCfg) for CLI tools
    (DNS / connection-refused retries during pod startup),
    sdklog.DefaultClient(t, tlsCfg) for the binary's outbound loops
    (retry handled at the loop level). One TLS material, multiple
    clients — symmetric with v1.25.0's "no DefaultClient/WithTLS split"
    stance.
  - Server-side counterpart (api/server.go's buildServerTLSConfig)
    enforces TLS 1.3 + RequireAndVerifyClientCert. The SDK's
    LoadClientTLSConfig produces the matching client-side posture
    (TLS 1.3 floor, verified server cert, presented client cert).
*/
package clienttls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"

	sdklog "github.com/baseproof/baseproof/log"
)

// ErrSelfSignedNoCA mirrors libs/clienttls: -allow-self-signed asserts the
// server cert is self-signed/private, which is meaningless without a CA to pin
// it to. Missing -ca-cert is startup-fatal rather than a silent skip-verify.
var ErrSelfSignedNoCA = errors.New("clienttls: -allow-self-signed set but no -ca-cert configured (a self-signed server cert must be pinned to a CA; verification is never skipped)")

// Flags is the operator-facing mTLS surface. Zero value = no mTLS
// (the helper returns nil, nil from TLSConfig()). Populate from any
// flag.FlagSet via Bind, or set the fields directly when wiring from
// env-backed config.
type Flags struct {
	// CertFile is the PEM client certificate the caller presents to
	// the server. Required to enable mTLS.
	CertFile string

	// KeyFile is the PEM private key matching CertFile. Required.
	KeyFile string

	// CAFile is the PEM CA bundle used to verify the server's cert.
	// Optional — empty falls back to the system roots (per the SDK's
	// LoadClientTLSConfig contract). Pin a CA in production to defend
	// against MITM via a publicly-trusted but unauthorized cert.
	CAFile string

	// AllowSelfSigned builds a server-verify-only config that pins CAFile
	// (REQUIRED) with NO client cert — the open-HTTPS posture for reaching a
	// privately-signed ledger without mTLS. Verification stays on (never
	// InsecureSkipVerify); a missing CAFile is the startup-fatal
	// ErrSelfSignedNoCA. Mirrors libs/clienttls so the CLI tools and the
	// long-running binaries share one vocabulary.
	AllowSelfSigned bool
}

// Bind registers the three flags onto fs. Flag names match the
// JN's exchange→ledger client (api/exchange/server.go in
// judicial-network) so operators see one consistent vocabulary
// across the network.
func (f *Flags) Bind(fs *flag.FlagSet) {
	fs.StringVar(&f.CertFile, "client-cert", "",
		"PEM client certificate for mTLS (requires -client-key)")
	fs.StringVar(&f.KeyFile, "client-key", "",
		"PEM client private key for mTLS (requires -client-cert)")
	fs.StringVar(&f.CAFile, "ca-cert", "",
		"PEM CA bundle for verifying the server cert (optional; defaults to system roots)")
	fs.BoolVar(&f.AllowSelfSigned, "allow-self-signed", false,
		"verify the server against -ca-cert with no client cert (open HTTPS to a privately-signed ledger); requires -ca-cert")
}

// Configured reports whether both cert and key are set — the minimum
// for an mTLS handshake. A non-empty CAFile alone does NOT enable
// mTLS (the client can't authenticate without a key).
func (f *Flags) Configured() bool {
	return f.CertFile != "" && f.KeyFile != ""
}

// TLSConfig returns the *tls.Config built from the configured files.
//
//   - Configured() returns true  → (*tls.Config, nil) on success;
//     (nil, error) on load failure (missing file, malformed PEM,
//     mismatched keypair). The caller MUST surface the error —
//     a silent fallback to plaintext is a confused-deputy bug.
//   - Configured() returns false → (nil, nil); the caller's client
//     constructor falls back to stdlib defaults.
//
// The returned *tls.Config has the SDK's TLS 1.3 floor + presented
// client cert + (optional) pinned CA — matches the ledger's server
// posture (RequireAndVerifyClientCert + TLS 1.3) exactly.
func (f *Flags) TLSConfig() (*tls.Config, error) {
	// A self-signed assertion with nothing to pin it to can never verify safely.
	if f.AllowSelfSigned && f.CAFile == "" {
		return nil, ErrSelfSignedNoCA
	}
	if !f.Configured() {
		// No client cert. Honor a pinned CA (AllowSelfSigned guarantees one) so an
		// open-HTTPS tool verifies a privately-signed ledger without mTLS. Absent a
		// CA, return (nil, nil): the caller's constructor uses stdlib server-verify
		// (system roots), preserving legacy plaintext behaviour.
		if f.CAFile != "" {
			return serverVerifyTLSConfig(f.CAFile)
		}
		return nil, nil
	}
	tlsCfg, err := sdklog.LoadClientTLSConfig(sdklog.ClientTLSConfig{
		ClientCertFile: f.CertFile,
		ClientKeyFile:  f.KeyFile,
		RootCAFile:     f.CAFile,
	})
	if err != nil {
		return nil, fmt.Errorf("clienttls: load client TLS config: %w", err)
	}
	return tlsCfg, nil
}

// serverVerifyTLSConfig builds a server-verify-only *tls.Config that pins caFile
// and presents NO client cert (open HTTPS). The SDK's LoadClientTLSConfig
// requires a client cert, so this tooling-owned builder covers the
// no-client-cert case; InsecureSkipVerify is never set.
func serverVerifyTLSConfig(caFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("clienttls: read CA %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("clienttls: CA %q contains no parseable certificates", caFile)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}
